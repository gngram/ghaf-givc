// SPDX-FileCopyrightText: 2024-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

package policyagent

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"

	pb "givc/modules/api/policyagent"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

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

// StreamPolicy is the implementation of the gRPC bidirectional streaming method.
func (s *PolicyAgentServer) StreamPolicy(stream pb.PolicyAgent_StreamPolicyServer) error {
	log.Info("Policy stream initiated by givc-admin.")
	tempFile, err := os.CreateTemp("", "policy-*.tar.gz")
	if err != nil {
		log.Errorf("Failed to create temporary file: %v", err)
		return err
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	for {
		// Receive a chunk from the client (givc-admin)
		in, err := stream.Recv()
		if err == io.EOF {
			// The client has closed the stream.
			log.Info("Policy stream finished. Received complete archive.")
			break
		}
		if err != nil {
			log.Errorf("Error receiving from policy stream: %v", err)
			return err
		}

		if _, err := tempFile.Write(in.GetArchiveChunk()); err != nil {
			log.Errorf("Failed to write to temporary file: %v", err)
			return err
		}
	}

	if err := tempFile.Close(); err != nil {
		log.Errorf("Failed to close temporary file: %v", err)
		return err
	}

	// Now, extract the tar.gz file
	destDir := "/etc/policies"
	log.Infof("Extracting policy archive %s to %s", tempFile.Name(), destDir)

	if err := extractTarGz(tempFile.Name(), destDir); err != nil {
		log.Errorf("Failed to extract policy archive: %v", err)
		return err
	}

	log.Info("Successfully extracted policies.")
	return nil
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
			outFile, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
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
