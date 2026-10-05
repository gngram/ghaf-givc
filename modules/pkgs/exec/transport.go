// SPDX-FileCopyrightText: 2024-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0
package exec

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	pb "givc/modules/api/exec"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ExecServer struct {
	pb.UnimplementedExecServer
}

func (s *ExecServer) Name() string {
	return "Exec Server"
}

func (s *ExecServer) RegisterGrpcService(srv *grpc.Server) {
	pb.RegisterExecServer(srv, s)
}

func NewExecServer() (*ExecServer, error) {
	return &ExecServer{}, nil
}

// GetUptime retrieves system uptime natively without shelling out to external binaries.
func (s *ExecServer) GetUptime(ctx context.Context, req *pb.UptimeRequest) (*pb.UptimeResponse, error) {
	if ctx == nil {
		return nil, status.Errorf(codes.InvalidArgument, "context cannot be nil")
	}

	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to read /proc/uptime: %v", err)
	}

	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return nil, status.Errorf(codes.Internal, "malformed /proc/uptime data")
	}

	uptimeSec, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to parse uptime: %v", err)
	}

	idleSec, err := strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to parse idle time: %v", err)
	}

	d := time.Duration(uptimeSec) * time.Second
	formatted := fmt.Sprintf("up %s", d.String())

	return &pb.UptimeResponse{
		UptimeSeconds: uptimeSec,
		IdleSeconds:   idleSec,
		Formatted:     formatted,
	}, nil
}

var validCachixIdentRegex = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

// RunOtaUpdate executes a dedicated, validated OTA update operation.
func (s *ExecServer) RunOtaUpdate(ctx context.Context, req *pb.OtaUpdateRequest) (*pb.OtaUpdateResponse, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "request cannot be nil")
	}

	var args []string

	switch req.Action {
	case pb.OtaAction_OTA_ACTION_GET:
		args = []string{"get"}
	case pb.OtaAction_OTA_ACTION_CACHIX:
		pin := req.GetPin()
		cache := req.GetCache()
		if pin == "" || cache == "" {
			return nil, status.Errorf(codes.InvalidArgument, "pin and cache must be non-empty for cachix action")
		}
		if !validCachixIdentRegex.MatchString(pin) || !validCachixIdentRegex.MatchString(cache) {
			return nil, status.Errorf(codes.InvalidArgument, "pin or cache identifier contains invalid characters")
		}
		args = []string{"cachix", pin, "--cache", cache}
		if req.Token != nil {
			if strings.ContainsRune(*req.Token, 0) {
				return nil, status.Errorf(codes.InvalidArgument, "token contains null byte")
			}
			args = append(args, "--token", *req.Token)
		}
		if req.CachixHost != nil {
			if strings.ContainsRune(*req.CachixHost, 0) {
				return nil, status.Errorf(codes.InvalidArgument, "cachix host contains null byte")
			}
			args = append(args, "--cachix-host", *req.CachixHost)
		}
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported or unspecified OTA action: %v", req.Action)
	}

	log.WithFields(log.Fields{
		"action": req.Action.String(),
		"args":   args,
	}).Info("[Exec] Executing dedicated OTA update operation")

	cmd := exec.CommandContext(ctx, "ota-update", args...)
	cmd.Env = []string{"PATH=/run/current-system/sw/bin:/bin:/usr/bin"}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	rc := int32(0)
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			rc = int32(exitErr.ExitCode())
		} else {
			return nil, status.Errorf(codes.Internal, "failed to execute ota-update: %v", err)
		}
	}

	return &pb.OtaUpdateResponse{
		ReturnCode: rc,
		Output:     stdout.String(),
		Error:      stderr.String(),
	}, nil
}
