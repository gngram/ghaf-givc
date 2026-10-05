// SPDX-FileCopyrightText: 2024-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0
package update

import (
	"context"
	"testing"

	pbupdate "givc/modules/api/update"
)

func TestUpdateValidation(t *testing.T) {
	srv, err := NewUpdateServer()
	if err != nil {
		t.Fatalf("failed to create UpdateServer: %v", err)
	}

	ctx := context.Background()

	// Discover with empty reference
	if _, err := srv.Discover(ctx, &pbupdate.RegistryDiscoverRequest{Reference: ""}); err == nil {
		t.Errorf("expected error on empty discover reference, got nil")
	}

	// Discover with null byte
	if _, err := srv.Discover(ctx, &pbupdate.RegistryDiscoverRequest{Reference: "repo:tag\x00evil"}); err == nil {
		t.Errorf("expected error on discover reference with null byte, got nil")
	}

	// Changelog with empty reference
	if _, err := srv.Changelog(ctx, &pbupdate.RegistryChangelogRequest{Reference: ""}); err == nil {
		t.Errorf("expected error on empty changelog reference, got nil")
	}

	// Pull with empty reference or destination
	if err := srv.Pull(&pbupdate.RegistryPullRequest{Reference: "", Destination: "/tmp"}, nil); err == nil {
		t.Errorf("expected error on empty pull reference, got nil")
	}
	if err := srv.Pull(&pbupdate.RegistryPullRequest{Reference: "repo:tag", Destination: ""}, nil); err == nil {
		t.Errorf("expected error on empty pull destination, got nil")
	}

	// ImageInstall with empty manifest
	if err := srv.ImageInstall(&pbupdate.ImageInstallRequest{Manifest: ""}, nil); err == nil {
		t.Errorf("expected error on empty install manifest, got nil")
	}

	// InstallCachix invalid characters
	invalidCachix := []*pbupdate.Cachix{
		{Pin: "pin; evil", Cache: "cache"},
		{Pin: "pin", Cache: "cache/../evil"},
		{Pin: "pin\x00", Cache: "cache"},
		{Pin: "", Cache: "cache"},
		{Pin: "pin", Cache: ""},
	}

	for _, c := range invalidCachix {
		if err := srv.InstallCachix(c, nil); err == nil {
			t.Errorf("expected error on invalid Cachix request %+v, got nil", c)
		}
	}
}
