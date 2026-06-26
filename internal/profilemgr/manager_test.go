package profilemgr_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/config"
	"github.com/trknhr/envvault/internal/issuer/talos"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/profile"
	"github.com/trknhr/envvault/internal/profilemgr"
)

func TestAddProcessProfileIssuesParentKeyStoresSecretInKeyringOnly(t *testing.T) {
	ctx := context.Background()
	configPath := writeBaseConfig(t)
	secrets := keyring.NewMemoryStore()
	parentIssuer := &fakeParentIssuer{secret: "parent-secret"}
	manager := profilemgr.New(configPath, secrets, parentIssuer)

	got, err := manager.AddProcess(ctx, profilemgr.ProcessRequest{
		Name:        "backend-a/dev",
		Resource:    "https://api.dev.example.com",
		Scopes:      []string{"repository:read", "issue:read"},
		TokenTTL:    10 * time.Minute,
		MaxTokenTTL: 30 * time.Minute,
		Claims:      map[string]string{"environment": "dev"},
		ProjectBinding: profile.ProjectBinding{
			Mode:      profile.ProjectBindingGitRemoteAndRoot,
			GitRoot:   "/work/backend-a",
			GitRemote: "git@example.com:team/backend-a.git",
		},
	})
	if err != nil {
		t.Fatalf("AddProcess() error = %v", err)
	}

	if got.Name != "backend-a/dev" {
		t.Fatalf("Name = %q", got.Name)
	}
	parentKey, err := secrets.Get(ctx, keyring.ProfileParentKey("backend-a/dev"))
	if err != nil {
		t.Fatalf("keyring Get() error = %v", err)
	}
	if string(parentKey) != "parent-secret" {
		t.Fatalf("parent key = %q, want parent-secret", parentKey)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	stored, err := cfg.Profile("backend-a/dev")
	if err != nil {
		t.Fatalf("Profile() error = %v", err)
	}
	if stored.Resource != "https://api.dev.example.com" {
		t.Fatalf("stored resource = %q", stored.Resource)
	}
	if stored.ProjectBinding.Mode != profile.ProjectBindingGitRemoteAndRoot {
		t.Fatalf("binding mode = %q", stored.ProjectBinding.Mode)
	}
	if stored.ProjectBinding.GitRoot != "/work/backend-a" {
		t.Fatalf("binding git root = %q", stored.ProjectBinding.GitRoot)
	}
	if stored.ProjectBinding.GitRemote != "git@example.com:team/backend-a.git" {
		t.Fatalf("binding git remote = %q", stored.ProjectBinding.GitRemote)
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if strings.Contains(string(raw), "parent-secret") {
		t.Fatalf("config leaked parent key: %s", raw)
	}

	if parentIssuer.request.Profile != "backend-a/dev" {
		t.Fatalf("parent request profile = %q", parentIssuer.request.Profile)
	}
	if parentIssuer.request.InstallationID != "01JTESTINSTALL" {
		t.Fatalf("installation id = %q", parentIssuer.request.InstallationID)
	}
	if parentIssuer.request.TTL != 2160*time.Hour {
		t.Fatalf("parent ttl = %s, want 2160h", parentIssuer.request.TTL)
	}
	if len(parentIssuer.request.Scopes) != 2 || parentIssuer.request.Scopes[0] != "repository:read" || parentIssuer.request.Scopes[1] != "issue:read" {
		t.Fatalf("parent scopes = %#v", parentIssuer.request.Scopes)
	}
}

func TestAddProcessProfileRejectsDuplicateBeforeIssuingParentKey(t *testing.T) {
	ctx := context.Background()
	configPath := writeBaseConfig(t)
	secrets := keyring.NewMemoryStore()
	parentIssuer := &fakeParentIssuer{secret: "parent-secret"}
	manager := profilemgr.New(configPath, secrets, parentIssuer)

	request := profilemgr.ProcessRequest{
		Name:        "backend-a/dev",
		Resource:    "https://api.dev.example.com",
		Scopes:      []string{"repository:read"},
		TokenTTL:    10 * time.Minute,
		MaxTokenTTL: 30 * time.Minute,
	}
	if _, err := manager.AddProcess(ctx, request); err != nil {
		t.Fatalf("first AddProcess() error = %v", err)
	}
	parentIssuer.calls = 0

	_, err := manager.AddProcess(ctx, request)
	if err == nil {
		t.Fatal("second AddProcess() error = nil, want error")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.ConfigInvalid {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.ConfigInvalid)
	}
	if parentIssuer.calls != 0 {
		t.Fatalf("parent issuer calls = %d, want 0", parentIssuer.calls)
	}
}

func TestAddProcessProfileDoesNotPersistConfigWhenKeyringFails(t *testing.T) {
	ctx := context.Background()
	configPath := writeBaseConfig(t)
	parentIssuer := &fakeParentIssuer{secret: "parent-secret"}
	manager := profilemgr.New(configPath, keyring.UnavailableStore{}, parentIssuer)

	_, err := manager.AddProcess(ctx, profilemgr.ProcessRequest{
		Name:        "backend-a/dev",
		Resource:    "https://api.dev.example.com",
		Scopes:      []string{"repository:read"},
		TokenTTL:    10 * time.Minute,
		MaxTokenTTL: 30 * time.Minute,
	})
	if err == nil {
		t.Fatal("AddProcess() error = nil, want error")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.KeyringUnavailable {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.KeyringUnavailable)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if _, err := cfg.Profile("backend-a/dev"); codeOf(err) != clerr.ProfileNotFound {
		t.Fatalf("Profile() error code = %q, want %q", codeOf(err), clerr.ProfileNotFound)
	}
}

func TestAddBrowserSessionProfileIssuesParentKeyAndStoresPolicy(t *testing.T) {
	ctx := context.Background()
	configPath := writeBaseConfig(t)
	secrets := keyring.NewMemoryStore()
	parentIssuer := &fakeParentIssuer{secret: "browser-parent-secret"}
	manager := profilemgr.New(configPath, secrets, parentIssuer)

	got, err := manager.AddBrowserSession(ctx, profilemgr.BrowserSessionRequest{
		Name:              "admin-web/dev",
		Resource:          "https://admin.dev.example.com",
		Scopes:            []string{"browser:session:create"},
		BootstrapTokenTTL: 60 * time.Second,
		LoginCodeTTL:      30 * time.Second,
		WebSessionTTL:     30 * time.Minute,
		ExchangeURL:       "https://admin.dev.example.com/auth/envvault/browser-sessions",
		CompleteURL:       "https://admin.dev.example.com/auth/envvault/complete",
		PostLoginURL:      "https://admin.dev.example.com/",
		AllowedHosts:      []string{"admin.dev.example.com"},
		ProjectBinding: profile.ProjectBinding{
			Mode:     profile.ProjectBindingPathHash,
			PathHash: "sha256:browser-project",
		},
	})
	if err != nil {
		t.Fatalf("AddBrowserSession() error = %v", err)
	}

	if got.Kind != profile.KindBrowserSession {
		t.Fatalf("Kind = %q", got.Kind)
	}
	parentKey, err := secrets.Get(ctx, keyring.ProfileParentKey("admin-web/dev"))
	if err != nil {
		t.Fatalf("keyring Get() error = %v", err)
	}
	if string(parentKey) != "browser-parent-secret" {
		t.Fatalf("parent key = %q, want browser-parent-secret", parentKey)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	stored, err := cfg.Profile("admin-web/dev")
	if err != nil {
		t.Fatalf("Profile() error = %v", err)
	}
	if stored.ExchangeURL != "https://admin.dev.example.com/auth/envvault/browser-sessions" {
		t.Fatalf("ExchangeURL = %q", stored.ExchangeURL)
	}
	if stored.ProjectBinding.PathHash != "sha256:browser-project" {
		t.Fatalf("binding path hash = %q", stored.ProjectBinding.PathHash)
	}
	if len(parentIssuer.request.Scopes) != 1 || parentIssuer.request.Scopes[0] != "browser:session:create" {
		t.Fatalf("parent scopes = %#v", parentIssuer.request.Scopes)
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if strings.Contains(string(raw), "browser-parent-secret") {
		t.Fatalf("config leaked browser parent key: %s", raw)
	}
}

func TestAddBrowserSessionRejectsInvalidTTLBeforeIssuingParentKey(t *testing.T) {
	configPath := writeBaseConfig(t)
	parentIssuer := &fakeParentIssuer{secret: "browser-parent-secret"}
	manager := profilemgr.New(configPath, keyring.NewMemoryStore(), parentIssuer)

	_, err := manager.AddBrowserSession(context.Background(), profilemgr.BrowserSessionRequest{
		Name:              "admin-web/dev",
		Resource:          "https://admin.dev.example.com",
		Scopes:            []string{"browser:session:create"},
		BootstrapTokenTTL: 61 * time.Second,
		LoginCodeTTL:      30 * time.Second,
		WebSessionTTL:     30 * time.Minute,
		ExchangeURL:       "https://admin.dev.example.com/auth/envvault/browser-sessions",
		CompleteURL:       "https://admin.dev.example.com/auth/envvault/complete",
		PostLoginURL:      "https://admin.dev.example.com/",
		AllowedHosts:      []string{"admin.dev.example.com"},
	})
	if err == nil {
		t.Fatal("AddBrowserSession() error = nil, want error")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.ConfigInvalid {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.ConfigInvalid)
	}
	if parentIssuer.calls != 0 {
		t.Fatalf("parent issuer calls = %d, want 0", parentIssuer.calls)
	}
}

type fakeParentIssuer struct {
	secret  string
	request talos.ParentKeyRequest
	calls   int
}

func (f *fakeParentIssuer) IssueParentKey(_ context.Context, request talos.ParentKeyRequest) (talos.ParentKey, error) {
	f.calls++
	f.request = request
	return talos.ParentKey{ID: "parent-id", Secret: f.secret}, nil
}

func writeBaseConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
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
		Profiles: map[string]config.Profile{},
	}
	if err := config.Save(path, cfg); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	return path
}

func codeOf(err error) clerr.Code {
	code, _ := clerr.CodeOf(err)
	return code
}
