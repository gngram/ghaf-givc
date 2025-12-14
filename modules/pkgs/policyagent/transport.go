// SPDX-FileCopyrightText: 2024-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

package policyagent

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	pb "givc/modules/api/policyagent"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

type ActionMap map[string]string

type PolicyAgentServer struct {
	pb.UnimplementedPolicyAgentServer
}

func (s *PolicyAgentServer) Name() string {
	return "Policy Agent Server"
}

func (s *PolicyAgentServer) RegisterGrpcService(srv *grpc.Server) {
	pb.RegisterPolicyAgentServer(srv, s)
}

func NewPolicyAgentServer() (*PolicyAgentServer, error) {
	return &PolicyAgentServer{}, nil
}

func (s *PolicyAgentServer) StreamPolicy(stream pb.PolicyAgent_StreamPolicyServer) error {
	log.Info("Policy stream initiated by givc-admin.")
	tempFile, err := os.CreateTemp("", "policy-*.tar.gz")
	if err != nil {
		log.Errorf("Failed to create temporary file: %v", err)
		return err
	}
	defer os.Remove(tempFile.Name())

	changeSet := ""
	oldRev := ""
	newRev := ""

	for {
		in, err := stream.Recv()
		if err == io.EOF {

			log.Infof("PolicyAgent received message from givc-admin.")
			break
		}
		if err != nil {
			log.Errorf("Error receiving from policy stream: %v", err)
			return stream.SendAndClose(&pb.Status{Status: "FAILED"})
		}
		archive_chunk := in.GetArchiveChunk()
		if archive_chunk != nil {
			log.Infof("Writing chunk of %d bytes to temporary file....", len(archive_chunk))
			if _, err := tempFile.Write(archive_chunk); err != nil {
				log.Errorf("Failed to write to temporary file: %v", err)
				return stream.SendAndClose(&pb.Status{Status: "FAILED"})
			}
		}

		if val := in.GetChangeSet(); val != "" {
			changeSet = val
		}
		if val := in.GetOldRev(); val != "" {
			oldRev = val
		}
		if val := in.GetNewRev(); val != "" {
			newRev = val
		}
	}
	if newRev == "" {
		log.Errorf("Spurious policy received")
		return stream.SendAndClose(&pb.Status{Status: "FAILED"})
	}
	log.Infof("Policy update info: ChangeSet=%s OldRev=%s NewRev=%s", changeSet, oldRev, newRev)

	tempFile.Close()

	policyBaseDir := "/etc/policies"
	actionFile := filepath.Join(policyBaseDir, "installers.json")

	vmPolicyDir := filepath.Join(policyBaseDir, "vm-policies")
	revFile := filepath.Join(policyBaseDir, ".rev")

	extractPolicy := false
	if GetFileSize(tempFile.Name()) > 0 {
		if FileExists(revFile) {
			sha, _ := os.ReadFile(revFile)
			if string(sha) != newRev {
				extractPolicy = true
			}
		} else {
			extractPolicy = true
		}
	}

	log.Infof("ExtractPolicy=%v", extractPolicy)
	if extractPolicy {

		log.Infof("Extracting policy archive %s to %s", tempFile.Name(), vmPolicyDir)
		if err := extractTarGz(tempFile.Name(), vmPolicyDir); err != nil {
			log.Errorf("Failed to extract policy archive: %v", err)
			return stream.SendAndClose(&pb.Status{Status: "FAILED"})
		}
		err := os.WriteFile(revFile, []byte(newRev), 0644)
		if err != nil {
			log.Errorf("Failed to write to sha file: %v", err)
			return stream.SendAndClose(&pb.Status{Status: "FAILED"})
		}

		if !FileExists(actionFile) {
			log.Infof("Policy update ignored, policy install rules not found.")
			return stream.SendAndClose(&pb.Status{Status: "OK"})
		}

		installRules, err := LoadActionMap(actionFile)
		if err != nil {
			log.Errorf("Error loading install rules: %v", err)
		}
		if err := ProcessChangeset(changeSet, vmPolicyDir, installRules); err != nil {
			log.Errorf("error processing changeset: %v", err)
		}

	}

	log.Infof("Successfully extracted policies.")
	return stream.SendAndClose(&pb.Status{Status: "OK"})
}

// extractTarGz extracts a .tar.gz file to a destination directory.
func extractTarGz(tarGzPath string, destDir string) error {
	file, err := os.Open(tarGzPath)
	if err != nil {
		return err
	}
	defer file.Close()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return err
		}

		target := filepath.Join(destDir, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			// Ensure parent directory exists
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			outFile, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			// Using defer to ensure file is closed even on copy error
			defer outFile.Close()
			if _, err := io.Copy(outFile, tr); err != nil {
				return err
			}
		}
	}
	return nil
}

func LoadActionMap(jsonPath string) (ActionMap, error) {
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("reading action json: %w", err)
	}
	var m ActionMap
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("unmarshal action json: %w", err)
	}
	return m, nil
}

func ProcessChangeset(changeset, policyDir string, actions ActionMap) error {
	trimmed := strings.TrimSpace(changeset)

	/* No changeset defined */
	if trimmed == "" {
		return installAllPolicies(policyDir, actions)
	}

	names := getModifiedPolicies(changeset, "vm-policies")
	if len(names) == 0 {
		return nil
	}

	for name := range names {
		action, ok := actions[name]
		if !ok {
			fmt.Fprintf(os.Stderr, "no action found for %q, skipping\n", name)
			continue
		}
		targetPath := filepath.Join(policyDir, name)
		if err := installPolicy(action, targetPath); err != nil {
			return fmt.Errorf("running action for %q: %w", name, err)
		}
	}

	return nil
}

func getModifiedPolicies(changeset, root string) map[string]struct{} {
	result := make(map[string]struct{})
	lines := strings.Split(changeset, "\n")

	prefix := root + "/"

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Expect format: "<status> <path>" e.g. "M vm-policies/hello.txt"
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		path := parts[1]

		if !strings.HasPrefix(path, prefix) {
			continue
		}

		// Strip "vm-policies/"
		rel := strings.TrimPrefix(path, prefix)
		if rel == "" {
			continue
		}

		// Take only the first path component: no recursion
		top := strings.SplitN(rel, "/", 2)[0]
		if top != "" {
			result[top] = struct{}{}
		}
	}

	return result
}

func installAllPolicies(policyDir string, actions ActionMap) error {
	for name, action := range actions {
		targetPath := filepath.Join(policyDir, name)
		if _, err := os.Stat(targetPath); err != nil {
			// doesn't exist, skip
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("stat %q: %w", targetPath, err)
		}

		if err := installPolicy(action, targetPath); err != nil {
			return fmt.Errorf("running action for %q: %w", name, err)
		}
	}
	return nil
}

func installPolicy(action, targetPath string) error {
	action = strings.TrimSpace(action)

	if action == "" {
		return fmt.Errorf("empty action command")
	}

	action = strings.ReplaceAll(action, "{target}", targetPath)
	parts := strings.Fields(action)
	cmdName := parts[0]
	if cmdName == "" {
		return fmt.Errorf("empty command name")
	}

	args := parts[1:]

	cmd := exec.Command(cmdName, args...)
	log.Infof("Executing policy install command: %s %s", cmdName, strings.Join(args, " "))
	cmd.Run()
	cmd.Wait()
	log.Infof("Policy install command completed with exit code %d", cmd.ProcessState.ExitCode())
	if cmd.ProcessState.ExitCode() != 0 {
		return fmt.Errorf("command exited with code %d", cmd.ProcessState.ExitCode())
	}

	return nil
}

func FileExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	return !os.IsNotExist(err)
}

func GetFileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}
