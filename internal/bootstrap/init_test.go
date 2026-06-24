package bootstrap_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/trknhr/credlease/internal/bootstrap"
	"github.com/trknhr/credlease/internal/clerr"
	"github.com/trknhr/credlease/internal/config"
	"github.com/trknhr/credlease/internal/keyring"
	runtimetalos "github.com/trknhr/credlease/internal/runtime/talos"
	"github.com/trknhr/credlease/internal/sqlite"
)

func TestInitializerCreatesConfigRuntimeSQLiteJWKSAndKeyringSecrets(t *testing.T) {
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir:  filepath.Join(root, "config"),
		ConfigFile: filepath.Join(root, "config", "config.yaml"),
		DataDir:    filepath.Join(root, "data"),
		CacheDir:   filepath.Join(root, "cache"),
	}
	secrets := keyring.NewMemoryStore()
	installer := &fakeInstaller{}
	jwks := []byte(`{"keys":[{"kid":"test-kid","kty":"RSA"}]}`)

	result, err := bootstrap.Initializer{
		Paths:         paths,
		Secrets:       secrets,
		Installer:     installer,
		SQLiteMigrate: sqlite.Migrate,
		Manifest: runtimetalos.Manifest{
			Version: "talos-test-v1",
			Artifacts: []runtimetalos.Artifact{{
				OS:     "linux",
				Arch:   "amd64",
				URL:    "https://example.invalid/talos",
				SHA256: "sha256",
			}},
		},
		Platform: runtimetalos.Platform{OS: "linux", Arch: "amd64"},
		JWKS:     func(context.Context) ([]byte, error) { return jwks, nil },
		NewInstallationID: func() (string, error) {
			return "01JTESTINSTALL", nil
		},
		RandomBytes: deterministicGenerator(
			[]byte("secret-canary-hmac"),
			[]byte("secret-canary-signing"),
		),
		Now: func() time.Time {
			return time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
		},
	}.Init(context.Background())
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	if result.ConfigPath != paths.ConfigFile {
		t.Fatalf("ConfigPath = %q, want %q", result.ConfigPath, paths.ConfigFile)
	}
	if result.SQLitePath != filepath.Join(paths.DataDir, "credlease.sqlite") {
		t.Fatalf("SQLitePath = %q", result.SQLitePath)
	}
	if result.JWKSPath != filepath.Join(paths.DataDir, "credlease-jwks.json") {
		t.Fatalf("JWKSPath = %q", result.JWKSPath)
	}
	if !installer.called {
		t.Fatal("installer was not called")
	}
	if installer.platform != (runtimetalos.Platform{OS: "linux", Arch: "amd64"}) {
		t.Fatalf("installer platform = %#v", installer.platform)
	}

	cfg, err := config.Load(paths.ConfigFile)
	if err != nil {
		t.Fatalf("Load(config) error = %v", err)
	}
	if cfg.Installation.ID != "01JTESTINSTALL" {
		t.Fatalf("installation id = %q", cfg.Installation.ID)
	}
	if cfg.Runtime.Talos.Mode != "managed" || cfg.Runtime.Talos.Lifecycle != "on-demand" {
		t.Fatalf("talos runtime config = %#v", cfg.Runtime.Talos)
	}
	if cfg.Runtime.Talos.Version != "talos-test-v1" {
		t.Fatalf("talos version = %q", cfg.Runtime.Talos.Version)
	}
	if cfg.Defaults.TokenTTL.Duration() != 10*time.Minute {
		t.Fatalf("default token ttl = %s", cfg.Defaults.TokenTTL.Duration())
	}
	if cfg.Defaults.MaxTokenTTL.Duration() != time.Hour {
		t.Fatalf("default max token ttl = %s", cfg.Defaults.MaxTokenTTL.Duration())
	}

	assertFileMode(t, paths.ConfigFile, 0o600)
	assertFileMode(t, paths.DataDir, 0o700)
	assertFileMode(t, result.SQLitePath, 0o600)
	assertFileMode(t, result.JWKSPath, 0o644)
	rawJWKS, err := os.ReadFile(result.JWKSPath)
	if err != nil {
		t.Fatalf("ReadFile(jwks) error = %v", err)
	}
	if string(rawJWKS) != string(jwks) {
		t.Fatalf("jwks = %s, want %s", rawJWKS, jwks)
	}

	hmac, err := secrets.Get(context.Background(), keyring.TalosHMACKey())
	if err != nil {
		t.Fatalf("Get(hmac) error = %v", err)
	}
	if !bytes.Equal(hmac, []byte("secret-canary-hmac")) {
		t.Fatalf("hmac secret = %q", hmac)
	}
	signing, err := secrets.Get(context.Background(), keyring.TalosSigningKey("current"))
	if err != nil {
		t.Fatalf("Get(signing) error = %v", err)
	}
	if !bytes.Equal(signing, []byte("secret-canary-signing")) {
		t.Fatalf("signing secret = %q", signing)
	}

	for _, path := range []string{paths.ConfigFile, result.SQLitePath, result.JWKSPath} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", path, err)
		}
		if bytes.Contains(raw, []byte("secret-canary")) {
			t.Fatalf("%s persisted generated secret canary", path)
		}
	}
}

func TestInitializerIsIdempotentAndDoesNotRotateExistingSecrets(t *testing.T) {
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir:  filepath.Join(root, "config"),
		ConfigFile: filepath.Join(root, "config", "config.yaml"),
		DataDir:    filepath.Join(root, "data"),
		CacheDir:   filepath.Join(root, "cache"),
	}
	secrets := keyring.NewMemoryStore()
	initializer := bootstrap.Initializer{
		Paths:         paths,
		Secrets:       secrets,
		Installer:     &fakeInstaller{},
		SQLiteMigrate: sqlite.Migrate,
		Manifest: runtimetalos.Manifest{
			Version: "talos-test-v1",
			Artifacts: []runtimetalos.Artifact{{
				OS:     "linux",
				Arch:   "amd64",
				URL:    "https://example.invalid/talos",
				SHA256: "sha256",
			}},
		},
		Platform: runtimetalos.Platform{OS: "linux", Arch: "amd64"},
		JWKS:     func(context.Context) ([]byte, error) { return []byte(`{"keys":[]}`), nil },
		NewInstallationID: func() (string, error) {
			return "01JTESTINSTALL", nil
		},
		RandomBytes: deterministicGenerator(
			[]byte("first-hmac"),
			[]byte("first-signing"),
		),
	}

	if _, err := initializer.Init(context.Background()); err != nil {
		t.Fatalf("first Init() error = %v", err)
	}
	firstHMAC, err := secrets.Get(context.Background(), keyring.TalosHMACKey())
	if err != nil {
		t.Fatalf("Get(first hmac) error = %v", err)
	}
	firstSigning, err := secrets.Get(context.Background(), keyring.TalosSigningKey("current"))
	if err != nil {
		t.Fatalf("Get(first signing) error = %v", err)
	}

	initializer.RandomBytes = func(int) ([]byte, error) {
		t.Fatal("RandomBytes called during idempotent init")
		return nil, nil
	}
	if _, err := initializer.Init(context.Background()); err != nil {
		t.Fatalf("second Init() error = %v", err)
	}
	secondHMAC, err := secrets.Get(context.Background(), keyring.TalosHMACKey())
	if err != nil {
		t.Fatalf("Get(second hmac) error = %v", err)
	}
	secondSigning, err := secrets.Get(context.Background(), keyring.TalosSigningKey("current"))
	if err != nil {
		t.Fatalf("Get(second signing) error = %v", err)
	}
	if !bytes.Equal(secondHMAC, firstHMAC) {
		t.Fatalf("hmac rotated on idempotent init")
	}
	if !bytes.Equal(secondSigning, firstSigning) {
		t.Fatalf("signing key rotated on idempotent init")
	}
}

func TestInitializerFailsClosedWhenKeyringUnavailable(t *testing.T) {
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir:  filepath.Join(root, "config"),
		ConfigFile: filepath.Join(root, "config", "config.yaml"),
		DataDir:    filepath.Join(root, "data"),
		CacheDir:   filepath.Join(root, "cache"),
	}

	_, err := bootstrap.Initializer{
		Paths:         paths,
		Secrets:       keyring.UnavailableStore{},
		Installer:     &fakeInstaller{},
		SQLiteMigrate: sqlite.Migrate,
		Manifest: runtimetalos.Manifest{
			Version: "talos-test-v1",
			Artifacts: []runtimetalos.Artifact{{
				OS:     "linux",
				Arch:   "amd64",
				URL:    "https://example.invalid/talos",
				SHA256: "sha256",
			}},
		},
		Platform:          runtimetalos.Platform{OS: "linux", Arch: "amd64"},
		JWKS:              func(context.Context) ([]byte, error) { return []byte(`{"keys":[]}`), nil },
		NewInstallationID: func() (string, error) { return "01JTESTINSTALL", nil },
		RandomBytes:       deterministicGenerator([]byte("hmac"), []byte("signing")),
	}.Init(context.Background())
	if err == nil {
		t.Fatal("Init() error = nil, want fail closed")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.KeyringUnavailable {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.KeyringUnavailable)
	}
	if _, statErr := os.Stat(paths.ConfigFile); !os.IsNotExist(statErr) {
		t.Fatalf("config file exists after keyring failure: %v", statErr)
	}
}

func TestInitializerPreparesRuntimeWithStoredSecretsBeforeJWKS(t *testing.T) {
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir:  filepath.Join(root, "config"),
		ConfigFile: filepath.Join(root, "config", "config.yaml"),
		DataDir:    filepath.Join(root, "data"),
		CacheDir:   filepath.Join(root, "cache"),
	}
	secrets := keyring.NewMemoryStore()
	hmacSecret := []byte("0123456789abcdef0123456789abcdef")
	signingSeed := []byte("abcdef0123456789abcdef0123456789")
	prepared := false
	jwksFetched := false

	_, err := bootstrap.Initializer{
		Paths:         paths,
		Secrets:       secrets,
		Installer:     &fakeInstaller{},
		SQLiteMigrate: sqlite.Migrate,
		Manifest: runtimetalos.Manifest{
			Version: "talos-test-v1",
			Artifacts: []runtimetalos.Artifact{{
				OS:     "linux",
				Arch:   "amd64",
				URL:    "https://example.invalid/talos",
				SHA256: "sha256",
			}},
		},
		Platform: runtimetalos.Platform{OS: "linux", Arch: "amd64"},
		NewInstallationID: func() (string, error) {
			return "01JTESTINSTALL", nil
		},
		RandomBytes: deterministicGenerator(hmacSecret, signingSeed),
		PrepareRuntime: func(ctx context.Context, request bootstrap.RuntimePrepareRequest) (bootstrap.JWKSFetcher, error) {
			prepared = true
			if request.Paths != paths {
				t.Fatalf("PrepareRuntime paths = %#v, want %#v", request.Paths, paths)
			}
			if request.Installed.Version != "talos-test-v1" || request.Installed.Path == "" {
				t.Fatalf("PrepareRuntime installed = %#v", request.Installed)
			}
			if request.InstallationID != "01JTESTINSTALL" {
				t.Fatalf("PrepareRuntime installation id = %q", request.InstallationID)
			}
			if !bytes.Equal(request.HMACSecret, hmacSecret) || !bytes.Equal(request.SigningSeed, signingSeed) {
				t.Fatalf("PrepareRuntime received wrong secret material")
			}
			if _, err := secrets.Get(ctx, keyring.TalosHMACKey()); err != nil {
				t.Fatalf("hmac secret was not stored before PrepareRuntime: %v", err)
			}
			if _, err := secrets.Get(ctx, keyring.TalosSigningKey("current")); err != nil {
				t.Fatalf("signing seed was not stored before PrepareRuntime: %v", err)
			}
			return func(context.Context) ([]byte, error) {
				jwksFetched = true
				return []byte(`{"keys":[]}`), nil
			}, nil
		},
	}.Init(context.Background())
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	if !prepared {
		t.Fatal("PrepareRuntime was not called")
	}
	if !jwksFetched {
		t.Fatal("prepared JWKS fetcher was not called")
	}
}

type fakeInstaller struct {
	called   bool
	manifest runtimetalos.Manifest
	platform runtimetalos.Platform
}

func (f *fakeInstaller) Install(_ context.Context, manifest runtimetalos.Manifest, platform runtimetalos.Platform) (runtimetalos.InstalledArtifact, error) {
	f.called = true
	f.manifest = manifest
	f.platform = platform
	return runtimetalos.InstalledArtifact{Version: manifest.Version, Path: "/cache/talos", SHA256: "sha256"}, nil
}

func deterministicGenerator(values ...[]byte) func(int) ([]byte, error) {
	index := 0
	return func(_ int) ([]byte, error) {
		if index >= len(values) {
			return []byte("extra-generated"), nil
		}
		value := append([]byte(nil), values[index]...)
		index++
		return value, nil
	}
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s) error = %v", path, err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != want {
		t.Fatalf("%s mode = %v, want %v", path, info.Mode().Perm(), want)
	}
}
