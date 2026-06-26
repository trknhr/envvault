package acceptance_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/audit"
	"github.com/trknhr/envvault/internal/bootstrap"
	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/cli"
	"github.com/trknhr/envvault/internal/config"
	"github.com/trknhr/envvault/internal/doctor"
	"github.com/trknhr/envvault/internal/issuer"
	"github.com/trknhr/envvault/internal/issuer/local"
	issuertalos "github.com/trknhr/envvault/internal/issuer/talos"
	"github.com/trknhr/envvault/internal/issuer/talosruntime"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/process"
	"github.com/trknhr/envvault/internal/profile"
	"github.com/trknhr/envvault/internal/profilemgr"
	resetpkg "github.com/trknhr/envvault/internal/reset"
	runtimetalos "github.com/trknhr/envvault/internal/runtime/talos"
	"github.com/trknhr/envvault/internal/sqlite"
	_ "modernc.org/sqlite"
)

func TestATKEYRING001InitFailsClosedWhenKeyringUnavailable(t *testing.T) {
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir:  filepath.Join(root, "config"),
		ConfigFile: filepath.Join(root, "config", "config.yaml"),
		DataDir:    filepath.Join(root, "data"),
		CacheDir:   filepath.Join(root, "cache"),
	}
	app := cli.New(cli.Options{
		Initializer: bootstrap.Initializer{
			Paths:         paths,
			Secrets:       keyring.UnavailableStore{},
			Installer:     &acceptanceInstaller{},
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
			RandomBytes: acceptanceDeterministicGenerator(
				[]byte("secret-canary-hmac"),
				[]byte("secret-canary-signing"),
			),
		},
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"init"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("Run(init) code = %d, want 1; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), string(clerr.KeyringUnavailable)) {
		t.Fatalf("stderr = %q, want %s", stderr.String(), clerr.KeyringUnavailable)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	for _, output := range []string{stdout.String(), stderr.String()} {
		if strings.Contains(output, "secret-canary") {
			t.Fatalf("command output leaked generated secret marker: %q", output)
		}
	}
	if _, err := os.Stat(paths.ConfigFile); !os.IsNotExist(err) {
		t.Fatalf("config file exists after keyring failure: %v", err)
	}
	assertTreeDoesNotContain(t, root, []byte("secret-canary"))
}

func TestATINIT001And002InitCreatesLocalStateAndIsIdempotent(t *testing.T) {
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir:  filepath.Join(root, "config"),
		ConfigFile: filepath.Join(root, "config", "config.yaml"),
		DataDir:    filepath.Join(root, "data"),
		CacheDir:   filepath.Join(root, "cache"),
	}
	secrets := keyring.NewMemoryStore()
	platform := runtimetalos.Platform{OS: "linux", Arch: "amd64"}
	runtimeBody := []byte("talos-runtime-binary")
	manifest := acceptanceRuntimeManifest("talos-test-v1", platform, runtimeBody)
	installer := &recordingRuntimeInstaller{
		path: filepath.Join(paths.CacheDir, "runtime", "talos-test-v1", "talos"),
		body: runtimeBody,
	}
	jwks := []byte(`{"keys":[{"kid":"init-test-kid","kty":"RSA","use":"sig"}]}`)
	randomBytes := acceptanceDeterministicGenerator(
		[]byte("secret-canary-hmac-32-byte-value"),
		[]byte("secret-canary-signing-32-byte-seed"),
	)
	randomAllowed := true
	jwksFetches := 0
	app := cli.New(cli.Options{
		Initializer: bootstrap.Initializer{
			Paths:         paths,
			Secrets:       secrets,
			Installer:     installer,
			SQLiteMigrate: sqlite.Migrate,
			Manifest:      manifest,
			Platform:      platform,
			JWKS: func(context.Context) ([]byte, error) {
				jwksFetches++
				return append([]byte(nil), jwks...), nil
			},
			NewInstallationID: func() (string, error) { return "01JTESTINSTALL", nil },
			RandomBytes: func(n int) ([]byte, error) {
				if !randomAllowed {
					t.Fatalf("RandomBytes(%d) called during idempotent init", n)
				}
				return randomBytes(n)
			},
		},
	})

	runAcceptanceCommand(t, app, []string{"init"})

	cfg, err := config.Load(paths.ConfigFile)
	if err != nil {
		t.Fatalf("Load(config) error = %v", err)
	}
	if cfg.Installation.ID != "01JTESTINSTALL" {
		t.Fatalf("installation id = %q, want 01JTESTINSTALL", cfg.Installation.ID)
	}
	if cfg.Runtime.Talos.Mode != "managed" || cfg.Runtime.Talos.Version != "talos-test-v1" || cfg.Runtime.Talos.Lifecycle != "on-demand" {
		t.Fatalf("runtime config = %#v, want managed talos-test-v1 on-demand", cfg.Runtime.Talos)
	}
	if cfg.Defaults.TokenTTL.Duration() != 10*time.Minute || cfg.Defaults.MaxTokenTTL.Duration() != time.Hour {
		t.Fatalf("default TTLs = %s/%s, want 10m/1h", cfg.Defaults.TokenTTL.Duration(), cfg.Defaults.MaxTokenTTL.Duration())
	}
	if installer.calls != 1 {
		t.Fatalf("installer calls = %d, want 1", installer.calls)
	}
	assertFileContent(t, installer.path, string(runtimeBody))
	assertFileContent(t, filepath.Join(paths.DataDir, "envvault-jwks.json"), string(jwks))
	assertSQLiteIntegrity(t, filepath.Join(paths.DataDir, "envvault.sqlite"))
	assertAcceptanceFileMode(t, paths.ConfigFile, 0o600)
	assertAcceptanceFileMode(t, filepath.Join(paths.DataDir, "envvault.sqlite"), 0o600)
	assertAcceptanceFileMode(t, filepath.Join(paths.DataDir, "envvault-jwks.json"), 0o644)

	firstHMAC, err := secrets.Get(context.Background(), keyring.TalosHMACKey())
	if err != nil {
		t.Fatalf("Get(hmac) error = %v", err)
	}
	firstSigning, err := secrets.Get(context.Background(), keyring.TalosSigningKey("current"))
	if err != nil {
		t.Fatalf("Get(signing) error = %v", err)
	}
	if string(firstHMAC) != "secret-canary-hmac-32-byte-value" || string(firstSigning) != "secret-canary-signing-32-byte-seed" {
		t.Fatalf("stored secrets = %q/%q, want generated secret material", firstHMAC, firstSigning)
	}
	for _, path := range []string{paths.ConfigFile, filepath.Join(paths.DataDir, "envvault.sqlite"), filepath.Join(paths.DataDir, "envvault-jwks.json")} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", path, err)
		}
		if bytes.Contains(raw, []byte("secret-canary")) {
			t.Fatalf("%s persisted generated secret canary", path)
		}
	}

	randomAllowed = false
	runAcceptanceCommand(t, app, []string{"init"})
	secondHMAC, err := secrets.Get(context.Background(), keyring.TalosHMACKey())
	if err != nil {
		t.Fatalf("Get(second hmac) error = %v", err)
	}
	secondSigning, err := secrets.Get(context.Background(), keyring.TalosSigningKey("current"))
	if err != nil {
		t.Fatalf("Get(second signing) error = %v", err)
	}
	if !bytes.Equal(secondHMAC, firstHMAC) || !bytes.Equal(secondSigning, firstSigning) {
		t.Fatalf("idempotent init rotated stored secrets")
	}
	if installer.calls != 1 {
		t.Fatalf("installer calls after second init = %d, want 1", installer.calls)
	}
	if jwksFetches != 1 {
		t.Fatalf("JWKS fetches after second init = %d, want 1", jwksFetches)
	}
}

func TestATCONCURRENCY001ConcurrentTokenIssuance(t *testing.T) {
	projectRoot := t.TempDir()
	tokenIssuer := &concurrentTokenIssuer{}
	app := cli.New(cli.Options{
		ProjectStartDir: projectRoot,
		Profiles: fakeProfileResolver{
			"backend-a/dev": {
				Name:        "backend-a/dev",
				Kind:        profile.KindProcess,
				Resource:    "https://api.dev.example.com",
				Scopes:      []string{"repository:read"},
				TokenTTL:    10 * time.Minute,
				MaxTokenTTL: 30 * time.Minute,
			},
		},
		Issuer: tokenIssuer,
	})

	results := make(chan tokenRunResult, 10)
	for i := 0; i < cap(results); i++ {
		go func() {
			var stdout, stderr bytes.Buffer
			code := app.Run(context.Background(), []string{"token", "backend-a/dev", "--quiet"}, &stdout, &stderr)
			results <- tokenRunResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
		}()
	}

	seenTokens := map[string]bool{}
	deadline := time.After(5 * time.Second)
	for i := 0; i < cap(results); i++ {
		select {
		case result := <-results:
			if result.code != 0 {
				t.Fatalf("Run(token) code = %d, want 0; stderr=%q", result.code, result.stderr)
			}
			if result.stderr != "" {
				t.Fatalf("stderr = %q, want empty", result.stderr)
			}
			token := strings.TrimSpace(result.stdout)
			if !strings.HasPrefix(token, "leased-hex:") {
				t.Fatalf("stdout token = %q, want leased token derived from session id", result.stdout)
			}
			if seenTokens[token] {
				t.Fatalf("duplicate leased token %q", token)
			}
			seenTokens[token] = true
		case <-deadline:
			t.Fatal("concurrent token issuance did not complete before timeout")
		}
	}

	grants := tokenIssuer.Grants()
	if len(grants) != 10 {
		t.Fatalf("issuer grants = %d, want 10", len(grants))
	}
	seenSessions := map[string]bool{}
	for _, grant := range grants {
		if grant.Profile != "backend-a/dev" {
			t.Fatalf("grant profile = %q, want backend-a/dev", grant.Profile)
		}
		sessionID, ok := grant.Claims["envvault_session_id"].(string)
		if !ok || !strings.HasPrefix(sessionID, "hex:") {
			t.Fatalf("grant session id = %#v, want hex session", grant.Claims["envvault_session_id"])
		}
		if seenSessions[sessionID] {
			t.Fatalf("duplicate session id %q", sessionID)
		}
		seenSessions[sessionID] = true
	}
}

func TestATCRASH001DoctorRepairCleansStaleRuntimeArtifactsAndChecksDBs(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	fixture := prepareAcceptanceDoctorInstallation(t)
	stale := now.Add(-2 * time.Hour)

	staleLock := filepath.Join(fixture.paths.CacheDir, "runtime.lock")
	if err := os.MkdirAll(staleLock, 0o700); err != nil {
		t.Fatalf("MkdirAll(stale lock) error = %v", err)
	}
	if err := os.Chtimes(staleLock, stale, stale); err != nil {
		t.Fatalf("Chtimes(stale lock) error = %v", err)
	}

	tmpDir := filepath.Join(fixture.paths.CacheDir, "tmp")
	if err := os.MkdirAll(tmpDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(tmp) error = %v", err)
	}
	staleTemp := filepath.Join(tmpDir, "envvault-secret-canary.yaml")
	if err := os.WriteFile(staleTemp, []byte("secret-canary temporary config"), 0o600); err != nil {
		t.Fatalf("WriteFile(stale temp) error = %v", err)
	}
	if err := os.Chtimes(staleTemp, stale, stale); err != nil {
		t.Fatalf("Chtimes(stale temp) error = %v", err)
	}

	app := cli.New(cli.Options{
		Doctor: doctor.Checker{
			Paths:            fixture.paths,
			Secrets:          fixture.secrets,
			RuntimeManifest:  fixture.manifest,
			RuntimePlatform:  fixture.platform,
			Now:              func() time.Time { return now },
			RepairStaleAfter: time.Hour,
		},
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"doctor", "--repair"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run(doctor --repair) code = %d, want 0; stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	for _, want := range []string{
		"ok repair-runtime-lock: removed stale runtime lock",
		"ok repair-temp-files: removed 1 stale temporary file",
		"ok sqlite: integrity ok",
		"ok talos-sqlite: integrity ok",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("doctor output = %q, want %q", stdout.String(), want)
		}
	}
	for _, path := range []string{staleLock, staleTemp} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s still exists after doctor repair: %v", path, err)
		}
	}
	if strings.Contains(stdout.String(), "secret-canary") || strings.Contains(stderr.String(), "secret-canary") {
		t.Fatalf("doctor output leaked stale temp secret marker; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	assertTreeDoesNotContain(t, filepath.Dir(fixture.paths.ConfigDir), []byte("secret-canary"))
}

func TestATPROFILE001ProfileAddCreatesSeparateParentKeysWithBoundedTalosScopes(t *testing.T) {
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir:  filepath.Join(root, "config"),
		ConfigFile: filepath.Join(root, "config", "config.yaml"),
		DataDir:    filepath.Join(root, "data"),
		CacheDir:   filepath.Join(root, "cache"),
	}
	if err := paths.Ensure(); err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	if err := config.Save(paths.ConfigFile, acceptanceBaseConfig()); err != nil {
		t.Fatalf("Save(config) error = %v", err)
	}

	secrets := keyring.NewMemoryStore()
	runtime := &recordingParentKeyRuntime{}
	app := cli.New(cli.Options{
		ProjectStartDir: root,
		ProfileManager:  profilemgr.New(paths.ConfigFile, secrets, talosruntime.Client{Runtime: runtime}),
	})

	runAcceptanceCommand(t, app, []string{
		"profile", "add", "process", "backend-a/dev",
		"--resource", "https://api.dev.example.com",
		"--scope", "repository:read",
		"--scope", "issue:read",
		"--ttl", "10m",
		"--max-ttl", "30m",
		"--project-binding", "none",
	})
	runAcceptanceCommand(t, app, []string{
		"profile", "add", "process", "backend-b/dev",
		"--resource", "https://api-b.dev.example.com",
		"--scope", "deploy:read",
		"--ttl", "5m",
		"--max-ttl", "15m",
		"--project-binding", "none",
	})

	parentA, err := secrets.Get(context.Background(), keyring.ProfileParentKey("backend-a/dev"))
	if err != nil {
		t.Fatalf("Get(parent A) error = %v", err)
	}
	parentB, err := secrets.Get(context.Background(), keyring.ProfileParentKey("backend-b/dev"))
	if err != nil {
		t.Fatalf("Get(parent B) error = %v", err)
	}
	if bytes.Equal(parentA, parentB) {
		t.Fatalf("profile parent keys are not separated: %q", parentA)
	}

	cfg, err := config.Load(paths.ConfigFile)
	if err != nil {
		t.Fatalf("Load(config) error = %v", err)
	}
	requests := runtime.Requests()
	if len(requests) != 2 {
		t.Fatalf("Talos parent key requests = %d, want 2", len(requests))
	}
	assertParentKeyRequestMatchesProfile(t, cfg, requests[0], "backend-a/dev")
	assertParentKeyRequestMatchesProfile(t, cfg, requests[1], "backend-b/dev")

	rawConfig, err := os.ReadFile(paths.ConfigFile)
	if err != nil {
		t.Fatalf("ReadFile(config) error = %v", err)
	}
	for _, secret := range [][]byte{parentA, parentB} {
		if bytes.Contains(rawConfig, secret) {
			t.Fatalf("config leaked parent key material: %s", rawConfig)
		}
	}
}

func TestATRESET001ResetRequiresConfirmationDeletesEnvVaultStateAndPreservesRepository(t *testing.T) {
	root := t.TempDir()
	repositoryRoot := filepath.Join(root, "repo")
	if err := os.MkdirAll(repositoryRoot, 0o700); err != nil {
		t.Fatalf("MkdirAll(repo) error = %v", err)
	}
	repoEnv := filepath.Join(repositoryRoot, ".env")
	if err := os.WriteFile(repoEnv, []byte("TOKEN=envvault://backend-a/dev\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(repo .env) error = %v", err)
	}

	paths := config.Paths{
		ConfigDir:  filepath.Join(root, "config"),
		ConfigFile: filepath.Join(root, "config", "config.yaml"),
		DataDir:    filepath.Join(root, "data"),
		CacheDir:   filepath.Join(root, "cache"),
	}
	cfg := acceptanceBaseConfig()
	cfg.Profiles["backend-a/dev"] = config.Profile{
		Kind:        profile.KindProcess,
		Issuer:      "talos",
		Resource:    "https://api.dev.example.com",
		Scopes:      []string{"repository:read"},
		TokenTTL:    config.Duration(10 * time.Minute),
		MaxTokenTTL: config.Duration(30 * time.Minute),
	}
	if err := config.Save(paths.ConfigFile, cfg); err != nil {
		t.Fatalf("Save(config) error = %v", err)
	}
	envvaultSQLite := filepath.Join(paths.DataDir, "envvault.sqlite")
	talosSQLite := filepath.Join(paths.DataDir, "talos.sqlite")
	jwksPath := filepath.Join(paths.DataDir, "envvault-jwks.json")
	auditPath := filepath.Join(paths.DataDir, "audit.jsonl")
	cacheArtifact := filepath.Join(paths.CacheDir, "runtime", "talos-test-v1", "talos")
	for path, body := range map[string]string{
		envvaultSQLite: "metadata-only-db",
		talosSQLite:    "talos-metadata-db",
		jwksPath:       `{"keys":[]}`,
		auditPath:      `{"event":"credential_issued"}`,
		cacheArtifact:  "runtime-binary",
	} {
		writeAcceptanceFile(t, path, body)
	}
	secrets := keyring.NewMemoryStore()
	putAcceptanceSecret(t, secrets, keyring.TalosHMACKey(), "secret-canary-hmac")
	putAcceptanceSecret(t, secrets, keyring.TalosSigningKey("current"), "secret-canary-signing")
	putAcceptanceSecret(t, secrets, keyring.ProfileParentKey("backend-a/dev"), "secret-canary-parent")
	app := cli.New(cli.Options{
		Resetter: resetpkg.Planner{Paths: paths, Secrets: secrets},
	})

	var unconfirmedStdout, unconfirmedStderr bytes.Buffer
	unconfirmedCode := app.Run(context.Background(), []string{"reset"}, &unconfirmedStdout, &unconfirmedStderr)
	if unconfirmedCode != 2 {
		t.Fatalf("Run(reset) code = %d, want 2", unconfirmedCode)
	}
	if !strings.Contains(unconfirmedStderr.String(), "--yes") {
		t.Fatalf("unconfirmed stderr = %q, want --yes guidance", unconfirmedStderr.String())
	}
	assertFileContent(t, repoEnv, "TOKEN=envvault://backend-a/dev\n")
	for _, path := range []string{paths.ConfigFile, envvaultSQLite, talosSQLite, jwksPath, auditPath, cacheArtifact} {
		assertPathExists(t, path)
	}
	if _, err := secrets.Get(context.Background(), keyring.ProfileParentKey("backend-a/dev")); err != nil {
		t.Fatalf("profile parent key removed before confirmation: %v", err)
	}

	result := runAcceptanceCommand(t, app, []string{"reset", "--yes"})
	if result.stdout != "" {
		t.Fatalf("reset --yes stdout = %q, want empty", result.stdout)
	}
	for _, path := range []string{paths.ConfigFile, envvaultSQLite, talosSQLite, jwksPath, auditPath, paths.CacheDir} {
		assertPathMissing(t, path)
	}
	for _, key := range []keyring.Key{
		keyring.TalosHMACKey(),
		keyring.TalosSigningKey("current"),
		keyring.ProfileParentKey("backend-a/dev"),
	} {
		if _, err := secrets.Get(context.Background(), key); err == nil {
			t.Fatalf("keyring key %s still exists after reset", key)
		}
	}
	assertFileContent(t, repoEnv, "TOKEN=envvault://backend-a/dev\n")
}

func TestATSEC001LocalFlowDoesNotPersistRawLongLivedSecretMarkers(t *testing.T) {
	root := t.TempDir()
	projectRoot := filepath.Join(root, "project")
	if err := os.MkdirAll(projectRoot, 0o700); err != nil {
		t.Fatalf("MkdirAll(project) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectRoot, ".env"), []byte("TOKEN=envvault://backend-a/dev\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(.env) error = %v", err)
	}

	paths := config.Paths{
		ConfigDir:  filepath.Join(root, "config"),
		ConfigFile: filepath.Join(root, "config", "config.yaml"),
		DataDir:    filepath.Join(root, "data"),
		CacheDir:   filepath.Join(root, "cache"),
	}
	secrets := keyring.NewMemoryStore()
	profiles := config.ProfileStore{Path: paths.ConfigFile}
	parentIssuer := &acceptanceParentIssuer{secret: "parent-secret-canary"}
	deriver := &acceptanceDeriver{token: "leased-jwt"}
	auditRecorder := &audit.FileRecorder{Path: filepath.Join(paths.DataDir, "audit.jsonl")}
	app := cli.New(cli.Options{
		ProjectStartDir: projectRoot,
		Initializer: bootstrap.Initializer{
			Paths:         paths,
			Secrets:       secrets,
			Installer:     &acceptanceInstaller{},
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
			RandomBytes: acceptanceDeterministicGenerator(
				[]byte("0123456789abcdef0123456789abcdef"),
				[]byte("abcdef0123456789abcdef0123456789"),
			),
		},
		Profiles:       profiles,
		ProfileManager: profilemgr.New(paths.ConfigFile, secrets, parentIssuer),
		Issuer:         local.NewIssuerWithAudit(profiles, secrets, deriver, auditRecorder),
	})

	runAcceptanceCommand(t, app, []string{"init"})
	runAcceptanceCommand(t, app, []string{
		"profile", "add", "process", "backend-a/dev",
		"--resource", "https://api.dev.example.com",
		"--scope", "repository:read",
		"--ttl", "10m",
		"--max-ttl", "30m",
		"--project-binding", "none",
	})
	result := runAcceptanceCommand(t, app, []string{"token", "backend-a/dev", "--quiet"})
	if strings.TrimSpace(result.stdout) != "leased-jwt" {
		t.Fatalf("token stdout = %q, want leased-jwt", result.stdout)
	}
	if deriver.parentKey != "parent-secret-canary" {
		t.Fatalf("deriver parent key = %q, want keyring parent secret", deriver.parentKey)
	}

	for _, marker := range [][]byte{
		[]byte("secret-canary"),
		[]byte("parent-secret"),
		[]byte("0123456789abcdef0123456789abcdef"),
		[]byte("abcdef0123456789abcdef0123456789"),
		[]byte("Authorization: Bearer"),
	} {
		assertTreeDoesNotContain(t, root, marker)
	}
}

func TestATLOG001SecretRedactionAcrossIssueFailuresAndCrashOutput(t *testing.T) {
	root := t.TempDir()
	projectRoot := filepath.Join(root, "project")
	if err := os.MkdirAll(projectRoot, 0o700); err != nil {
		t.Fatalf("MkdirAll(project) error = %v", err)
	}
	envFile := filepath.Join(projectRoot, ".env")
	if err := os.WriteFile(envFile, []byte("TOKEN=envvault://backend-a/dev\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(.env) error = %v", err)
	}
	quietChild := buildFixture(t, findRepoRoot(t), "exit-code")
	auditPath := filepath.Join(root, "data", "audit.jsonl")
	forbidden := []string{
		"jwt-canary-success",
		"jwt-canary-failure",
		"parent-secret-canary",
		"hmac-secret-canary",
		"signing-secret-canary",
		"Authorization: Bearer",
		"crash-output-canary",
	}

	successRuntime := newAcceptanceDeriveRuntime(t, http.StatusOK, `{"token":{"token":"jwt-canary-success"}}`)
	success := runAcceptanceLogExec(t, projectRoot, envFile, quietChild, successRuntime, successRuntime.Client(), auditPath)
	if success.code != 0 {
		t.Fatalf("success exec code = %d, want 0; stdout=%q stderr=%q", success.code, success.stdout, success.stderr)
	}
	assertStringDoesNotContainAny(t, "successful exec output", success.stdout+success.stderr, forbidden)
	assertAuditFileDoesNotContainAny(t, auditPath, forbidden)

	failureRuntime := newAcceptanceDeriveRuntime(t, http.StatusInternalServerError, "jwt-canary-failure parent-secret-canary Authorization: Bearer hmac-secret-canary")
	failure := runAcceptanceLogExec(t, projectRoot, envFile, quietChild, failureRuntime, failureRuntime.Client(), auditPath)
	if failure.code != 1 {
		t.Fatalf("HTTP 500 exec code = %d, want 1; stdout=%q stderr=%q", failure.code, failure.stdout, failure.stderr)
	}
	if failure.stdout != "" {
		t.Fatalf("HTTP 500 stdout = %q, want empty", failure.stdout)
	}
	if !strings.Contains(failure.stderr, string(clerr.IssueFailed)) || !strings.Contains(failure.stderr, "HTTP 500") {
		t.Fatalf("HTTP 500 stderr = %q, want redacted issue failure", failure.stderr)
	}
	assertStringDoesNotContainAny(t, "HTTP 500 exec output", failure.stdout+failure.stderr, forbidden)
	assertAuditFileDoesNotContainAny(t, auditPath, forbidden)

	crashRuntime := runtimetalos.NewRuntime(runtimetalos.RuntimeOptions{
		BinaryPath:    os.Args[0],
		Args:          []string{"-test.run=TestAcceptanceLeakyTalosRuntimeHelperProcess", "--", "leak-and-sleep", "{address}"},
		HealthPath:    "/healthz",
		StartTimeout:  50 * time.Millisecond,
		StopTimeout:   time.Second,
		PollInterval:  5 * time.Millisecond,
		ExtraEnv:      []string{"ENVVAULT_ACCEPTANCE_TALOS_RUNTIME_HELPER=1"},
		StopSignal:    os.Interrupt,
		DialTimeout:   10 * time.Millisecond,
		PortCloseWait: time.Second,
	})
	crash := runAcceptanceLogExec(t, projectRoot, envFile, quietChild, crashRuntime, nil, auditPath)
	if crash.code != 1 {
		t.Fatalf("runtime crash exec code = %d, want 1; stdout=%q stderr=%q", crash.code, crash.stdout, crash.stderr)
	}
	if crash.stdout != "" {
		t.Fatalf("runtime crash stdout = %q, want empty", crash.stdout)
	}
	if !strings.Contains(crash.stderr, string(clerr.RuntimeUnavailable)) {
		t.Fatalf("runtime crash stderr = %q, want runtime unavailable", crash.stderr)
	}
	assertStringDoesNotContainAny(t, "runtime crash exec output", crash.stdout+crash.stderr, forbidden)
	assertAuditFileDoesNotContainAny(t, auditPath, forbidden)
}

func TestAcceptanceLeakyTalosRuntimeHelperProcess(t *testing.T) {
	if os.Getenv("ENVVAULT_ACCEPTANCE_TALOS_RUNTIME_HELPER") != "1" {
		return
	}
	args := os.Args
	separator := -1
	for index, arg := range args {
		if arg == "--" {
			separator = index
			break
		}
	}
	if separator == -1 || separator+1 >= len(args) || args[separator+1] != "leak-and-sleep" {
		_, _ = os.Stderr.WriteString("missing acceptance helper mode\n")
		os.Exit(2)
	}
	_, _ = os.Stderr.WriteString("crash-output-canary jwt-canary-failure parent-secret-canary Authorization: Bearer hmac-secret-canary\n")
	time.Sleep(5 * time.Second)
	os.Exit(0)
}

type acceptanceDeriveRuntime struct {
	server *httptest.Server
	status int
	body   string
}

func newAcceptanceDeriveRuntime(t *testing.T, status int, body string) *acceptanceDeriveRuntime {
	t.Helper()
	runtime := &acceptanceDeriveRuntime{
		status: status,
		body:   body,
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(runtime.handle))
	runtime.server = server
	t.Cleanup(server.Close)
	return runtime
}

func (r *acceptanceDeriveRuntime) Client() *http.Client {
	return r.server.Client()
}

func (r *acceptanceDeriveRuntime) Start(context.Context) (runtimetalos.Endpoint, error) {
	r.server.Start()
	return runtimetalos.Endpoint{URL: r.server.URL, Address: r.server.Listener.Addr().String()}, nil
}

func (r *acceptanceDeriveRuntime) Stop(context.Context) error {
	r.server.Close()
	return nil
}

func (r *acceptanceDeriveRuntime) handle(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost || req.URL.Path != "/v2alpha1/admin/apiKeys:derive" {
		http.NotFound(w, req)
		return
	}
	if r.status < 200 || r.status >= 300 {
		http.Error(w, r.body, r.status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(r.status)
	_, _ = w.Write([]byte(r.body))
}

func runAcceptanceLogExec(t *testing.T, projectRoot, envFile, child string, runtime talosruntime.Runtime, httpClient *http.Client, auditPath string) tokenRunResult {
	t.Helper()
	secrets := keyring.NewMemoryStore()
	putAcceptanceSecret(t, secrets, keyring.TalosHMACKey(), "hmac-secret-canary")
	putAcceptanceSecret(t, secrets, keyring.TalosSigningKey("current"), "signing-secret-canary")
	putAcceptanceSecret(t, secrets, keyring.ProfileParentKey("backend-a/dev"), "parent-secret-canary")
	profiles := fakeProfiles()
	issuer := local.NewIssuerWithAudit(profiles, secrets, talosruntime.Client{
		Runtime: runtime,
		HTTP:    httpClient,
	}, &audit.FileRecorder{Path: auditPath})
	parent := append([]string{}, os.Environ()...)
	parent = append(parent,
		"ENVVAULT_TALOS_HMAC_SECRET=hmac-secret-canary",
		"ENVVAULT_TALOS_SIGNING_KEY=signing-secret-canary",
		"ENVVAULT_PROFILE_PARENT_KEY=parent-secret-canary",
	)
	app := cli.New(cli.Options{
		ParentEnv:       parent,
		ProjectStartDir: projectRoot,
		Profiles:        profiles,
		Issuer:          issuer,
		Runner:          process.Runner{},
	})

	var stdout, stderr bytes.Buffer
	code := app.Run(context.Background(), []string{
		"exec",
		"--env-file", envFile,
		"--", child, "--code", "0",
	}, &stdout, &stderr)
	return tokenRunResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

func assertAuditFileDoesNotContainAny(t *testing.T, path string, forbidden []string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(audit) error = %v", err)
	}
	assertStringDoesNotContainAny(t, "audit file", string(body), forbidden)
}

func assertStringDoesNotContainAny(t *testing.T, label string, body string, forbidden []string) {
	t.Helper()
	for _, marker := range forbidden {
		if strings.Contains(body, marker) {
			t.Fatalf("%s leaked forbidden marker %q: %q", label, marker, body)
		}
	}
}

type acceptanceInstaller struct{}

func (a *acceptanceInstaller) Install(_ context.Context, manifest runtimetalos.Manifest, _ runtimetalos.Platform) (runtimetalos.InstalledArtifact, error) {
	return runtimetalos.InstalledArtifact{Version: manifest.Version, Path: "/cache/talos", SHA256: "sha256"}, nil
}

func acceptanceDeterministicGenerator(values ...[]byte) func(int) ([]byte, error) {
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

func assertTreeDoesNotContain(t *testing.T, root string, needle []byte) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(body, needle) {
			t.Fatalf("%s persisted secret marker", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
}

type tokenRunResult struct {
	code   int
	stdout string
	stderr string
}

type concurrentTokenIssuer struct {
	mu     sync.Mutex
	grants []issuer.Grant
}

func (i *concurrentTokenIssuer) Issue(_ context.Context, grant issuer.Grant) (issuer.Credential, error) {
	sessionID, _ := grant.Claims["envvault_session_id"].(string)
	i.mu.Lock()
	i.grants = append(i.grants, cloneGrant(grant))
	i.mu.Unlock()
	return issuer.Credential{
		AccessToken: "leased-" + sessionID,
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(grant.TTL),
		Scopes:      append([]string(nil), grant.Scopes...),
	}, nil
}

func (i *concurrentTokenIssuer) Grants() []issuer.Grant {
	i.mu.Lock()
	defer i.mu.Unlock()
	grants := make([]issuer.Grant, len(i.grants))
	for index, grant := range i.grants {
		grants[index] = cloneGrant(grant)
	}
	return grants
}

func cloneGrant(grant issuer.Grant) issuer.Grant {
	claims := make(map[string]any, len(grant.Claims))
	for key, value := range grant.Claims {
		claims[key] = value
	}
	return issuer.Grant{
		Profile:  grant.Profile,
		Resource: grant.Resource,
		Scopes:   append([]string(nil), grant.Scopes...),
		TTL:      grant.TTL,
		Claims:   claims,
	}
}

type acceptanceDoctorFixture struct {
	paths    config.Paths
	secrets  keyring.Store
	manifest runtimetalos.Manifest
	platform runtimetalos.Platform
}

func prepareAcceptanceDoctorInstallation(t *testing.T) acceptanceDoctorFixture {
	t.Helper()
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir:  filepath.Join(root, "config"),
		ConfigFile: filepath.Join(root, "config", "config.yaml"),
		DataDir:    filepath.Join(root, "data"),
		CacheDir:   filepath.Join(root, "cache"),
	}
	if err := paths.Ensure(); err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
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
		},
	}
	if err := config.Save(paths.ConfigFile, cfg); err != nil {
		t.Fatalf("Save(config) error = %v", err)
	}
	if err := sqlite.Migrate(context.Background(), sqlite.Options{Path: filepath.Join(paths.DataDir, "envvault.sqlite")}); err != nil {
		t.Fatalf("Migrate(envvault sqlite) error = %v", err)
	}
	createAcceptanceSQLite(t, filepath.Join(paths.DataDir, "talos.sqlite"))
	if err := os.WriteFile(filepath.Join(paths.DataDir, "envvault-jwks.json"), []byte(`{"keys":[{"kid":"test","kty":"OKP"}]}`), 0o644); err != nil {
		t.Fatalf("WriteFile(jwks) error = %v", err)
	}
	secrets := keyring.NewMemoryStore()
	putAcceptanceSecret(t, secrets, keyring.TalosHMACKey(), "secret-canary-hmac")
	putAcceptanceSecret(t, secrets, keyring.TalosSigningKey("current"), "secret-canary-signing")
	putAcceptanceSecret(t, secrets, keyring.ProfileParentKey("backend-a/dev"), "secret-canary-parent")
	platform := runtimetalos.Platform{OS: "linux", Arch: "amd64"}
	runtimeBody := []byte("talos-runtime")
	manifest := acceptanceRuntimeManifest("test-talos", platform, runtimeBody)
	writeAcceptanceRuntimeArtifact(t, paths, manifest, platform, runtimeBody)
	return acceptanceDoctorFixture{
		paths:    paths,
		secrets:  secrets,
		manifest: manifest,
		platform: platform,
	}
}

func createAcceptanceSQLite(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll(sqlite) error = %v", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("Open(sqlite) error = %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE talos_healthcheck (id TEXT PRIMARY KEY)`); err != nil {
		t.Fatalf("create sqlite healthcheck table error = %v", err)
	}
}

func putAcceptanceSecret(t *testing.T, store keyring.Store, key keyring.Key, value string) {
	t.Helper()
	if err := store.Put(context.Background(), key, []byte(value)); err != nil {
		t.Fatalf("Put(%s) error = %v", key, err)
	}
}

func writeAcceptanceFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}

func assertPathExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("Stat(%s) error = %v, want path to exist", path, err)
	}
}

func assertPathMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("Stat(%s) error = %v, want missing path", path, err)
	}
}

func acceptanceRuntimeManifest(version string, platform runtimetalos.Platform, body []byte) runtimetalos.Manifest {
	sum := sha256.Sum256(body)
	return runtimetalos.Manifest{
		Version: version,
		Artifacts: []runtimetalos.Artifact{{
			OS:     platform.OS,
			Arch:   platform.Arch,
			URL:    "https://example.invalid/talos",
			SHA256: hex.EncodeToString(sum[:]),
		}},
	}
}

func writeAcceptanceRuntimeArtifact(t *testing.T, paths config.Paths, manifest runtimetalos.Manifest, platform runtimetalos.Platform, body []byte) {
	t.Helper()
	cached, err := manifest.CachedArtifactPaths(paths.CacheDir, platform)
	if err != nil {
		t.Fatalf("CachedArtifactPaths() error = %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(cached.Binary), 0o700); err != nil {
		t.Fatalf("MkdirAll(runtime cache) error = %v", err)
	}
	if err := os.WriteFile(cached.Binary, body, 0o755); err != nil {
		t.Fatalf("WriteFile(runtime artifact) error = %v", err)
	}
}

func runAcceptanceCommand(t *testing.T, app cli.App, args []string) tokenRunResult {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := app.Run(context.Background(), args, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run(%v) code = %d, want 0; stdout=%q stderr=%q", args, code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("Run(%v) stderr = %q, want empty", args, stderr.String())
	}
	return tokenRunResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

type recordingRuntimeInstaller struct {
	path  string
	body  []byte
	calls int
}

func (i *recordingRuntimeInstaller) Install(_ context.Context, manifest runtimetalos.Manifest, _ runtimetalos.Platform) (runtimetalos.InstalledArtifact, error) {
	i.calls++
	if len(manifest.Artifacts) == 0 {
		return runtimetalos.InstalledArtifact{}, clerr.New(clerr.RuntimeIncompatible, "missing test manifest artifact")
	}
	if err := os.MkdirAll(filepath.Dir(i.path), 0o700); err != nil {
		return runtimetalos.InstalledArtifact{}, err
	}
	if err := os.WriteFile(i.path, i.body, 0o755); err != nil {
		return runtimetalos.InstalledArtifact{}, err
	}
	return runtimetalos.InstalledArtifact{
		Version: manifest.Version,
		Path:    i.path,
		SHA256:  manifest.Artifacts[0].SHA256,
	}, nil
}

func assertSQLiteIntegrity(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("Open(sqlite %s) error = %v", path, err)
	}
	defer db.Close()

	var integrity string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil {
		t.Fatalf("integrity_check(%s) error = %v", path, err)
	}
	if integrity != "ok" {
		t.Fatalf("integrity_check(%s) = %q, want ok", path, integrity)
	}
	var version int
	if err := db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatalf("schema_migrations(%s) error = %v", path, err)
	}
	if version != 1 {
		t.Fatalf("schema version = %d, want 1", version)
	}
}

func assertAcceptanceFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s) error = %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %v, want %v", path, got, want)
	}
}

func acceptanceBaseConfig() config.File {
	return config.File{
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
}

type parentKeyRequestRecord struct {
	Name     string            `json:"name"`
	ActorID  string            `json:"actor_id"`
	Scopes   []string          `json:"scopes"`
	TTL      string            `json:"ttl"`
	Metadata map[string]string `json:"metadata"`
}

type recordingParentKeyRuntime struct {
	mu       sync.Mutex
	server   *httptest.Server
	requests []parentKeyRequestRecord
}

func (r *recordingParentKeyRuntime) Start(context.Context) (runtimetalos.Endpoint, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.server != nil {
		return runtimetalos.Endpoint{URL: r.server.URL, Address: r.server.Listener.Addr().String()}, nil
	}
	server := httptest.NewServer(http.HandlerFunc(r.handle))
	r.server = server
	return runtimetalos.Endpoint{URL: server.URL, Address: server.Listener.Addr().String()}, nil
}

func (r *recordingParentKeyRuntime) Stop(context.Context) error {
	r.mu.Lock()
	server := r.server
	r.server = nil
	r.mu.Unlock()
	if server != nil {
		server.Close()
	}
	return nil
}

func (r *recordingParentKeyRuntime) Requests() []parentKeyRequestRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]parentKeyRequestRecord(nil), r.requests...)
}

func (r *recordingParentKeyRuntime) handle(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost || req.URL.Path != "/v2alpha1/admin/issuedApiKeys" {
		http.NotFound(w, req)
		return
	}
	var record parentKeyRequestRecord
	if err := json.NewDecoder(req.Body).Decode(&record); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	r.mu.Lock()
	r.requests = append(r.requests, record)
	index := len(r.requests)
	r.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"id":"parent-id-` + hex.EncodeToString([]byte{byte(index)}) + `","secret":"parent-secret-` + hex.EncodeToString([]byte{byte(index)}) + `"}`))
}

func assertParentKeyRequestMatchesProfile(t *testing.T, cfg config.File, request parentKeyRequestRecord, name string) {
	t.Helper()
	p, err := cfg.Profile(name)
	if err != nil {
		t.Fatalf("Profile(%s) error = %v", name, err)
	}
	if request.Name != "envvault:"+name {
		t.Fatalf("%s Talos name = %q", name, request.Name)
	}
	if request.ActorID != "envvault-local:"+cfg.Installation.ID {
		t.Fatalf("%s actor_id = %q", name, request.ActorID)
	}
	if request.Metadata["envvault_profile"] != name {
		t.Fatalf("%s metadata = %#v, want envvault_profile", name, request.Metadata)
	}
	if request.TTL != "2160h0m0s" {
		t.Fatalf("%s parent key ttl = %q, want 2160h0m0s", name, request.TTL)
	}
	if strings.Join(request.Scopes, ",") != strings.Join(p.Scopes, ",") {
		t.Fatalf("%s Talos scopes = %#v, want profile scopes %#v", name, request.Scopes, p.Scopes)
	}
	if !p.AllowsScopes(request.Scopes) {
		t.Fatalf("%s Talos scopes exceed profile maximum: %#v", name, request.Scopes)
	}
}

type acceptanceParentIssuer struct {
	secret string
}

func (i *acceptanceParentIssuer) IssueParentKey(_ context.Context, _ issuertalos.ParentKeyRequest) (issuertalos.ParentKey, error) {
	return issuertalos.ParentKey{ID: "parent-id", Secret: i.secret}, nil
}

type acceptanceDeriver struct {
	token     string
	parentKey string
}

func (d *acceptanceDeriver) DeriveJWT(_ context.Context, parentKey string, grant issuer.Grant) (issuer.Credential, error) {
	d.parentKey = parentKey
	return issuer.Credential{
		AccessToken: d.token,
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(grant.TTL),
		Scopes:      append([]string(nil), grant.Scopes...),
	}, nil
}
