// SPDX-FileCopyrightText: 2024-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0
package exec

import (
	"context"
	"testing"

	pb "givc/modules/api/exec"
)

func TestGetUptime(t *testing.T) {
	srv, err := NewExecServer()
	if err != nil {
		t.Fatalf("failed to create ExecServer: %v", err)
	}

	ctx := context.Background()
	resp, err := srv.GetUptime(ctx, &pb.UptimeRequest{})
	if err != nil {
		t.Fatalf("GetUptime failed: %v", err)
	}

	if resp.UptimeSeconds <= 0 {
		t.Errorf("expected positive uptime seconds, got: %v", resp.UptimeSeconds)
	}
	if resp.Formatted == "" {
		t.Errorf("expected non-empty formatted uptime string")
	}
}

func TestRunOtaUpdateValidation(t *testing.T) {
	srv, err := NewExecServer()
	if err != nil {
		t.Fatalf("failed to create ExecServer: %v", err)
	}

	ctx := context.Background()

	// Nil request
	if _, err := srv.RunOtaUpdate(ctx, nil); err == nil {
		t.Errorf("expected error on nil request, got nil")
	}

	// Unspecified action
	if _, err := srv.RunOtaUpdate(ctx, &pb.OtaUpdateRequest{Action: pb.OtaAction_OTA_ACTION_UNSPECIFIED}); err == nil {
		t.Errorf("expected error on unspecified action, got nil")
	}

	// Cachix action with empty pin/cache
	if _, err := srv.RunOtaUpdate(ctx, &pb.OtaUpdateRequest{Action: pb.OtaAction_OTA_ACTION_CACHIX}); err == nil {
		t.Errorf("expected error on empty Cachix parameters, got nil")
	}

	// Cachix action with malicious characters
	maliciousPin := "pin; rm -rf /"
	cache := "my-cache"
	if _, err := srv.RunOtaUpdate(ctx, &pb.OtaUpdateRequest{
		Action: pb.OtaAction_OTA_ACTION_CACHIX,
		Pin:    &maliciousPin,
		Cache:  &cache,
	}); err == nil {
		t.Errorf("expected error on malicious pin, got nil")
	}
}
