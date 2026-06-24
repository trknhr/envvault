package config_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/trknhr/credlease/internal/clerr"
	"github.com/trknhr/credlease/internal/config"
	"github.com/trknhr/credlease/internal/profile"
)

func TestProfileStoreLoadsProfileFromConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := config.Save(path, config.File{
		Version: 1,
		Installation: config.Installation{
			ID: "01JTESTINSTALL",
		},
		Runtime: config.Runtime{
			Talos: config.TalosRuntime{
				Mode:      "managed",
				Version:   "test-talos",
				Lifecycle: "on-demand",
			},
		},
		Defaults: config.Defaults{
			TokenTTL:    config.Duration(10 * time.Minute),
			MaxTokenTTL: config.Duration(time.Hour),
		},
		Profiles: map[string]config.Profile{
			"backend-a/dev": {
				Kind:     profile.KindProcess,
				Issuer:   "talos",
				Resource: "https://api.dev.example.com",
				Scopes:   []string{"repository:read"},
				ProjectBinding: config.ProjectBinding{
					Mode:     profile.ProjectBindingPathHash,
					PathHash: "sha256:abc123",
				},
			},
		},
	}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	store := config.ProfileStore{Path: path}
	got, err := store.Profile("backend-a/dev")

	if err != nil {
		t.Fatalf("Profile() error = %v", err)
	}
	if got.Name != "backend-a/dev" {
		t.Fatalf("Name = %q, want backend-a/dev", got.Name)
	}
	if got.TokenTTL != 10*time.Minute || got.MaxTokenTTL != time.Hour {
		t.Fatalf("TTLs = %s/%s, want defaults 10m/1h", got.TokenTTL, got.MaxTokenTTL)
	}
	if got.ProjectBinding.Mode != profile.ProjectBindingPathHash || got.ProjectBinding.PathHash != "sha256:abc123" {
		t.Fatalf("ProjectBinding = %#v, want stored binding", got.ProjectBinding)
	}
}

func TestProfileStoreReturnsProfileNotFound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := config.Save(path, config.File{
		Version: 1,
		Installation: config.Installation{
			ID: "01JTESTINSTALL",
		},
		Runtime: config.Runtime{
			Talos: config.TalosRuntime{
				Mode:      "managed",
				Version:   "test-talos",
				Lifecycle: "on-demand",
			},
		},
		Defaults: config.Defaults{
			TokenTTL:    config.Duration(10 * time.Minute),
			MaxTokenTTL: config.Duration(time.Hour),
		},
		Profiles: map[string]config.Profile{},
	}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	_, err := (config.ProfileStore{Path: path}).Profile("missing/dev")

	code, ok := clerr.CodeOf(err)
	if !ok || code != clerr.ProfileNotFound {
		t.Fatalf("Profile() error = %v, want %s", err, clerr.ProfileNotFound)
	}
}

func TestProfileStoreReloadsConfigForEachLookup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	base := config.File{
		Version: 1,
		Installation: config.Installation{
			ID: "01JTESTINSTALL",
		},
		Runtime: config.Runtime{
			Talos: config.TalosRuntime{
				Mode:      "managed",
				Version:   "test-talos",
				Lifecycle: "on-demand",
			},
		},
		Defaults: config.Defaults{
			TokenTTL:    config.Duration(10 * time.Minute),
			MaxTokenTTL: config.Duration(time.Hour),
		},
		Profiles: map[string]config.Profile{
			"backend-a/dev": {
				Kind:     profile.KindProcess,
				Issuer:   "talos",
				Resource: "https://api.dev.example.com",
				Scopes:   []string{"repository:read"},
				TokenTTL: config.Duration(5 * time.Minute),
			},
		},
	}
	if err := config.Save(path, base); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	store := config.ProfileStore{Path: path}
	first, err := store.Profile("backend-a/dev")
	if err != nil {
		t.Fatalf("Profile() first error = %v", err)
	}

	base.Profiles["backend-a/dev"] = config.Profile{
		Kind:     profile.KindProcess,
		Issuer:   "talos",
		Resource: "https://api.dev.example.com",
		Scopes:   []string{"repository:read"},
		TokenTTL: config.Duration(7 * time.Minute),
	}
	if err := config.Save(path, base); err != nil {
		t.Fatalf("Save() second error = %v", err)
	}
	second, err := store.Profile("backend-a/dev")

	if err != nil {
		t.Fatalf("Profile() second error = %v", err)
	}
	if first.TokenTTL != 5*time.Minute || second.TokenTTL != 7*time.Minute {
		t.Fatalf("TokenTTLs = %s then %s, want reload from disk", first.TokenTTL, second.TokenTTL)
	}
}
