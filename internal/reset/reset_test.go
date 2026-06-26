package reset_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/config"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/profile"
	"github.com/trknhr/envvault/internal/reset"
)

func TestPlannerDryRunReportsEnvVaultOwnedFilesAndKeyringEntries(t *testing.T) {
	ctx := context.Background()
	paths := testPaths(t)
	writeResetConfig(t, paths)
	writeFile(t, filepath.Join(paths.DataDir, "envvault.sqlite"), "metadata-only-db")
	writeFile(t, filepath.Join(paths.DataDir, "talos.sqlite"), "talos-metadata-db")
	writeFile(t, filepath.Join(paths.DataDir, "envvault-jwks.json"), `{"keys":[]}`)
	writeFile(t, filepath.Join(paths.DataDir, "audit.jsonl"), `{"event":"credential_issued"}`)
	secrets := keyring.NewMemoryStore()
	putSecret(t, ctx, secrets, keyring.TalosHMACKey(), "secret-canary-hmac")
	putSecret(t, ctx, secrets, keyring.TalosSigningKey("current"), "secret-canary-signing")
	putSecret(t, ctx, secrets, keyring.ProfileParentKey("backend-a/dev"), "secret-canary-parent")
	putSecret(t, ctx, secrets, keyring.CredentialValue("openai-key/dev"), "secret-canary-provider")
	putSecret(t, ctx, secrets, keyring.CredentialValue("database-url/dev"), "secret-canary-database")
	repoFile := filepath.Join(t.TempDir(), ".env")
	writeFile(t, repoFile, "TOKEN=envvault://backend-a/dev\n")

	result, err := reset.Planner{Paths: paths, Secrets: secrets}.Reset(ctx, reset.Options{DryRun: true})
	if err != nil {
		t.Fatalf("Reset() error = %v", err)
	}

	if !contains(result.Files, paths.ConfigFile) {
		t.Fatalf("Files = %#v, want config file", result.Files)
	}
	if !contains(result.Files, filepath.Join(paths.DataDir, "envvault.sqlite")) {
		t.Fatalf("Files = %#v, want sqlite file", result.Files)
	}
	if !contains(result.Files, filepath.Join(paths.DataDir, "talos.sqlite")) {
		t.Fatalf("Files = %#v, want managed Talos sqlite file", result.Files)
	}
	if !contains(result.Files, filepath.Join(paths.DataDir, "audit.jsonl")) {
		t.Fatalf("Files = %#v, want audit file", result.Files)
	}
	if !contains(result.KeyringKeys, string(keyring.ProfileParentKey("backend-a/dev"))) {
		t.Fatalf("KeyringKeys = %#v, want profile parent key", result.KeyringKeys)
	}
	if !contains(result.KeyringKeys, string(keyring.CredentialValue("openai-key/dev"))) {
		t.Fatalf("KeyringKeys = %#v, want provider api key", result.KeyringKeys)
	}
	if !contains(result.KeyringKeys, string(keyring.CredentialValue("database-url/dev"))) {
		t.Fatalf("KeyringKeys = %#v, want inject credential value", result.KeyringKeys)
	}
	if _, err := os.Stat(paths.ConfigFile); err != nil {
		t.Fatalf("config removed during dry-run: %v", err)
	}
	if _, err := secrets.Get(ctx, keyring.TalosHMACKey()); err != nil {
		t.Fatalf("keyring changed during dry-run: %v", err)
	}
	if got := readFile(t, repoFile); got != "TOKEN=envvault://backend-a/dev\n" {
		t.Fatalf("repository file changed: %q", got)
	}
}

func TestPlannerResetDeletesEnvVaultFilesAndKnownKeyringEntries(t *testing.T) {
	ctx := context.Background()
	paths := testPaths(t)
	writeResetConfig(t, paths)
	sqlitePath := filepath.Join(paths.DataDir, "envvault.sqlite")
	talosSQLitePath := filepath.Join(paths.DataDir, "talos.sqlite")
	jwksPath := filepath.Join(paths.DataDir, "envvault-jwks.json")
	auditPath := filepath.Join(paths.DataDir, "audit.jsonl")
	writeFile(t, sqlitePath, "metadata-only-db")
	writeFile(t, talosSQLitePath, "talos-metadata-db")
	writeFile(t, jwksPath, `{"keys":[]}`)
	writeFile(t, auditPath, `{"event":"credential_issued"}`)
	writeFile(t, filepath.Join(paths.CacheDir, "talos-v0.1.0-linux-amd64"), "runtime")
	secrets := keyring.NewMemoryStore()
	putSecret(t, ctx, secrets, keyring.TalosHMACKey(), "hmac")
	putSecret(t, ctx, secrets, keyring.TalosSigningKey("current"), "signing")
	putSecret(t, ctx, secrets, keyring.ProfileParentKey("backend-a/dev"), "parent")
	putSecret(t, ctx, secrets, keyring.CredentialValue("openai-key/dev"), "provider")
	putSecret(t, ctx, secrets, keyring.CredentialValue("database-url/dev"), "database")

	result, err := reset.Planner{Paths: paths, Secrets: secrets}.Reset(ctx, reset.Options{})
	if err != nil {
		t.Fatalf("Reset() error = %v", err)
	}

	for _, path := range []string{paths.ConfigFile, sqlitePath, talosSQLitePath, jwksPath, auditPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s still exists after reset; err=%v", path, err)
		}
	}
	if _, err := os.Stat(paths.CacheDir); !os.IsNotExist(err) {
		t.Fatalf("cache dir still exists after reset; err=%v", err)
	}
	for _, key := range []keyring.Key{
		keyring.TalosHMACKey(),
		keyring.TalosSigningKey("current"),
		keyring.ProfileParentKey("backend-a/dev"),
		keyring.CredentialValue("openai-key/dev"),
		keyring.CredentialValue("database-url/dev"),
	} {
		if _, err := secrets.Get(ctx, key); err == nil {
			t.Fatalf("key %s still exists after reset", key)
		}
	}
	if !contains(result.KeyringKeys, string(keyring.ProfileParentKey("backend-a/dev"))) {
		t.Fatalf("KeyringKeys = %#v, want profile parent key", result.KeyringKeys)
	}
	if !contains(result.KeyringKeys, string(keyring.CredentialValue("openai-key/dev"))) {
		t.Fatalf("KeyringKeys = %#v, want provider api key", result.KeyringKeys)
	}
	if !contains(result.KeyringKeys, string(keyring.CredentialValue("database-url/dev"))) {
		t.Fatalf("KeyringKeys = %#v, want inject credential value", result.KeyringKeys)
	}
}

func testPaths(t *testing.T) config.Paths {
	t.Helper()
	root := t.TempDir()
	return config.Paths{
		ConfigDir:  filepath.Join(root, "config"),
		ConfigFile: filepath.Join(root, "config", "config.yaml"),
		DataDir:    filepath.Join(root, "data"),
		CacheDir:   filepath.Join(root, "cache"),
	}
}

func writeResetConfig(t *testing.T, paths config.Paths) {
	t.Helper()
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
				Scopes:      []string{"repository:read"},
				TokenTTL:    config.Duration(10 * time.Minute),
				MaxTokenTTL: config.Duration(30 * time.Minute),
			},
			"openai/dev": {
				Kind:           profile.KindProviderProxy,
				CredentialName: "openai-key/dev",
				AuthMode:       "bearer",
				Provider:       "openai-compatible",
				TargetURL:      "https://api.openai.com/v1",
				AllowedPaths:   []string{"/chat/completions"},
				AllowedMethods: []string{"POST"},
				LocalTokenTTL:  config.Duration(10 * time.Minute),
			},
			"database/dev": {
				Kind:           profile.KindInject,
				CredentialName: "database-url/dev",
				ProjectBinding: config.ProjectBinding{
					Mode: profile.ProjectBindingNone,
				},
			},
		},
	}
	if err := config.Save(paths.ConfigFile, cfg); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
}

func putSecret(t *testing.T, ctx context.Context, store keyring.Store, key keyring.Key, value string) {
	t.Helper()
	if err := store.Put(ctx, key, []byte(value)); err != nil {
		t.Fatalf("Put(%s) error = %v", key, err)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	return string(raw)
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want || strings.TrimRight(value, string(os.PathSeparator)) == want {
			return true
		}
	}
	return false
}
