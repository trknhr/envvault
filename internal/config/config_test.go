package config_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/trknhr/credlease/internal/clerr"
	"github.com/trknhr/credlease/internal/config"
	"github.com/trknhr/credlease/internal/profile"
)

func TestLoadProfileAppliesDefaultsAndValidates(t *testing.T) {
	path := writeConfig(t, `
version: 1
installation:
  id: 01JTESTINSTALL
runtime:
  talos:
    mode: managed
    version: test-talos
    lifecycle: on-demand
defaults:
  token_ttl: 10m
  max_token_ttl: 60m
profiles:
  backend-a/dev:
    kind: process
    issuer: talos
    resource: https://api.dev.example.com
    scopes:
      - repository:read
      - issue:read
    claims:
      environment: dev
    project_binding:
      mode: git-remote-and-root
      git_root: /work/backend-a
      git_remote: git@example.com:team/backend-a.git
      path_hash: sha256:test
`)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	got, err := cfg.Profile("backend-a/dev")
	if err != nil {
		t.Fatalf("Profile() error = %v", err)
	}

	if got.Kind != profile.KindProcess {
		t.Fatalf("Kind = %q", got.Kind)
	}
	if got.TokenTTL != 10*time.Minute {
		t.Fatalf("TokenTTL = %s, want 10m", got.TokenTTL)
	}
	if got.MaxTokenTTL != time.Hour {
		t.Fatalf("MaxTokenTTL = %s, want 1h", got.MaxTokenTTL)
	}
	if !got.AllowsScopes([]string{"repository:read"}) {
		t.Fatal("profile should allow repository:read")
	}
	if got.ProjectBinding.Mode != profile.ProjectBindingGitRemoteAndRoot {
		t.Fatalf("ProjectBinding.Mode = %q", got.ProjectBinding.Mode)
	}
	if got.ProjectBinding.GitRoot != "/work/backend-a" {
		t.Fatalf("ProjectBinding.GitRoot = %q", got.ProjectBinding.GitRoot)
	}
	if got.ProjectBinding.GitRemote != "git@example.com:team/backend-a.git" {
		t.Fatalf("ProjectBinding.GitRemote = %q", got.ProjectBinding.GitRemote)
	}
	if got.ProjectBinding.PathHash != "sha256:test" {
		t.Fatalf("ProjectBinding.PathHash = %q", got.ProjectBinding.PathHash)
	}
	if got.Claims["environment"] != "dev" {
		t.Fatalf("Claims[environment] = %q", got.Claims["environment"])
	}
}

func TestLoadProfileRejectsUnknownProfileFailClosed(t *testing.T) {
	path := writeConfig(t, `
version: 1
installation:
  id: 01JTESTINSTALL
runtime:
  talos:
    mode: managed
    version: test-talos
    lifecycle: on-demand
defaults:
  token_ttl: 10m
  max_token_ttl: 60m
profiles: {}
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	_, err = cfg.Profile("backend-a/dev")
	if err == nil {
		t.Fatal("Profile() error = nil, want error")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.ProfileNotFound {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.ProfileNotFound)
	}
}

func TestLoadRejectsInvalidProfile(t *testing.T) {
	path := writeConfig(t, `
version: 1
installation:
  id: 01JTESTINSTALL
runtime:
  talos:
    mode: managed
    version: test-talos
    lifecycle: on-demand
defaults:
  token_ttl: 10m
  max_token_ttl: 60m
profiles:
  backend-a/dev:
    kind: process
    issuer: talos
    resource: https://api.dev.example.com
    token_ttl: 2h
    max_token_ttl: 30m
    scopes:
      - repository:read
`)

	_, err := config.Load(path)
	if err == nil {
		t.Fatal("Load() error = nil, want error")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.ConfigInvalid {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.ConfigInvalid)
	}
}

func TestLoadRejectsUnsupportedProfileIssuer(t *testing.T) {
	path := writeConfig(t, `
version: 1
installation:
  id: 01JTESTINSTALL
runtime:
  talos:
    mode: managed
    version: test-talos
    lifecycle: on-demand
defaults:
  token_ttl: 10m
  max_token_ttl: 60m
profiles:
  backend-a/dev:
    kind: process
    issuer: remote
    resource: https://api.dev.example.com
    token_ttl: 10m
    max_token_ttl: 30m
    scopes:
      - repository:read
`)

	_, err := config.Load(path)

	if err == nil {
		t.Fatal("Load() error = nil, want error")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.ConfigInvalid {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.ConfigInvalid)
	}
}

func TestSaveCreatesUserPrivateConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.yaml")
	cfg := config.File{
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
				Kind:        profile.KindProcess,
				Issuer:      "talos",
				Resource:    "https://api.dev.example.com",
				TokenTTL:    config.Duration(10 * time.Minute),
				MaxTokenTTL: config.Duration(30 * time.Minute),
				Scopes:      []string{"repository:read"},
				ProjectBinding: config.ProjectBinding{
					Mode: profile.ProjectBindingNone,
				},
			},
		},
	}

	if err := config.Save(path, cfg); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	text := string(raw)
	if !strings.Contains(text, "token_ttl: 10m0s") {
		t.Fatalf("saved config did not contain duration string: %s", text)
	}
	if strings.Contains(strings.ToLower(text), "parent") || strings.Contains(strings.ToLower(text), "secret") {
		t.Fatalf("saved config contains forbidden secret authority words: %s", text)
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(body)+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}
