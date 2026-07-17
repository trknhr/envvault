package doctor_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/config"
	"github.com/trknhr/envvault/internal/doctor"
	"github.com/trknhr/envvault/internal/homefile"
	"github.com/trknhr/envvault/internal/keyring"
	runtimetalos "github.com/trknhr/envvault/internal/runtime/talos"
	"github.com/trknhr/envvault/internal/sqlite"
)

func TestCheckerReportsHealthyInstallationWithoutSecrets(t *testing.T) {
	ctx := context.Background()
	paths := testPaths(t)
	if err := paths.Ensure(); err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	saveDoctorConfig(t, paths, map[string]config.Profile{
		"backend-a/dev": {
			Kind:        "process",
			Issuer:      "talos",
			Resource:    "https://api.dev.example.com",
			Scopes:      []string{"repository:read"},
			TokenTTL:    config.Duration(10 * time.Minute),
			MaxTokenTTL: config.Duration(30 * time.Minute),
		},
	})
	if err := sqlite.Migrate(ctx, sqlite.Options{Path: filepath.Join(paths.DataDir, "envvault.sqlite")}); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	createTalosSQLite(t, filepath.Join(paths.DataDir, "talos.sqlite"))
	if err := os.WriteFile(filepath.Join(paths.DataDir, "envvault-jwks.json"), []byte(`{"keys":[{"kid":"test","kty":"OKP"}]}`), 0o644); err != nil {
		t.Fatalf("WriteFile(jwks) error = %v", err)
	}
	secrets := keyring.NewMemoryStore()
	putSecret(t, ctx, secrets, keyring.TalosHMACKey(), "secret-canary-hmac")
	putSecret(t, ctx, secrets, keyring.TalosSigningKey("current"), "secret-canary-signing")
	putSecret(t, ctx, secrets, keyring.ProfileParentKey("backend-a/dev"), "secret-canary-parent")
	platform := runtimetalos.Platform{OS: "linux", Arch: "amd64"}
	runtimeBody := []byte("talos-runtime")
	manifest := testRuntimeManifest("test-talos", platform, runtimeBody)
	writeCachedRuntimeArtifact(t, paths, manifest, platform, runtimeBody)

	result, err := doctor.Checker{
		Paths:           paths,
		Secrets:         secrets,
		RuntimeManifest: manifest,
		RuntimePlatform: platform,
	}.Check(ctx)

	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.HasErrors() {
		t.Fatalf("HasErrors() = true; checks=%#v", result.Checks)
	}
	got := renderChecks(result)
	for _, want := range []string{"config", "runtime", "sqlite", "talos-sqlite", "jwks", "keyring", "cache"} {
		if !strings.Contains(got, want) {
			t.Fatalf("checks = %q, want %q", got, want)
		}
	}
	if strings.Contains(got, "secret-canary") {
		t.Fatalf("checks leaked secret material: %q", got)
	}
}

func TestCheckerReportsRuntimeArtifactChecksumMismatch(t *testing.T) {
	ctx := context.Background()
	fixture := prepareHealthyDoctorInstallation(t, ctx)
	paths, err := fixture.manifest.CachedArtifactPaths(fixture.paths.CacheDir, fixture.platform)
	if err != nil {
		t.Fatalf("CachedArtifactPaths() error = %v", err)
	}
	if err := os.WriteFile(paths.Binary, []byte("tampered"), 0o755); err != nil {
		t.Fatalf("WriteFile(runtime artifact) error = %v", err)
	}

	result, err := doctor.Checker{
		Paths:           fixture.paths,
		Secrets:         fixture.secrets,
		RuntimeManifest: fixture.manifest,
		RuntimePlatform: fixture.platform,
	}.Check(ctx)

	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	check := findCheck(t, result, "runtime")
	if check.Status != doctor.StatusError {
		t.Fatalf("runtime status = %q, want error", check.Status)
	}
	if check.Code != clerr.RuntimeIncompatible {
		t.Fatalf("runtime code = %q, want %q", check.Code, clerr.RuntimeIncompatible)
	}
	if strings.Contains(renderChecks(result), "tampered") {
		t.Fatalf("runtime output leaked artifact body: %q", renderChecks(result))
	}
}

func TestCheckerReportsStaleRuntimeLockAndTempFilesWithoutRepair(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	fixture := prepareHealthyDoctorInstallation(t, ctx)
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
	staleTemp := filepath.Join(tmpDir, "envvault-secret-canary.tmp")
	if err := os.WriteFile(staleTemp, []byte("secret-canary"), 0o600); err != nil {
		t.Fatalf("WriteFile(stale temp) error = %v", err)
	}
	if err := os.Chtimes(staleTemp, stale, stale); err != nil {
		t.Fatalf("Chtimes(stale temp) error = %v", err)
	}
	staleHome := filepath.Join(tmpDir, "envvault-home-secret-canary")
	if err := os.MkdirAll(filepath.Join(staleHome, "home"), 0o700); err != nil {
		t.Fatalf("MkdirAll(stale home) error = %v", err)
	}
	writeHomeWorkspaceLock(t, staleHome)
	if err := os.Chtimes(staleHome, stale, stale); err != nil {
		t.Fatalf("Chtimes(stale home) error = %v", err)
	}

	result, err := doctor.Checker{
		Paths:            fixture.paths,
		Secrets:          fixture.secrets,
		Now:              func() time.Time { return now },
		RepairStaleAfter: time.Hour,
		RuntimeManifest:  fixture.manifest,
		RuntimePlatform:  fixture.platform,
	}.Check(ctx)

	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	lockCheck := findCheck(t, result, "runtime-lock")
	if lockCheck.Status != doctor.StatusWarn {
		t.Fatalf("runtime-lock status = %q, want warn", lockCheck.Status)
	}
	tempCheck := findCheck(t, result, "temp-files")
	if tempCheck.Status != doctor.StatusWarn {
		t.Fatalf("temp-files status = %q, want warn", tempCheck.Status)
	}
	for _, path := range []string{staleLock, staleTemp, staleHome} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s to remain after non-repair check: %v", path, err)
		}
	}
	if strings.Contains(renderChecks(result), "secret-canary") {
		t.Fatalf("doctor output leaked temp file marker: %q", renderChecks(result))
	}
}

func TestCheckerReportsKeyringUnavailableFailClosed(t *testing.T) {
	ctx := context.Background()
	paths := testPaths(t)
	if err := paths.Ensure(); err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	saveDoctorConfig(t, paths, map[string]config.Profile{})
	if err := sqlite.Migrate(ctx, sqlite.Options{Path: filepath.Join(paths.DataDir, "envvault.sqlite")}); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(paths.DataDir, "envvault-jwks.json"), []byte(`{"keys":[]}`), 0o644); err != nil {
		t.Fatalf("WriteFile(jwks) error = %v", err)
	}

	result, err := doctor.Checker{Paths: paths, Secrets: keyring.UnavailableStore{}}.Check(ctx)

	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.HasErrors() {
		t.Fatalf("HasErrors() = false; checks=%#v", result.Checks)
	}
	check := findCheck(t, result, "keyring")
	if check.Status != doctor.StatusError {
		t.Fatalf("keyring status = %q, want error", check.Status)
	}
	if check.Code != clerr.KeyringUnavailable {
		t.Fatalf("keyring code = %q, want %q", check.Code, clerr.KeyringUnavailable)
	}
	if strings.Contains(check.Message, "secret-canary") {
		t.Fatalf("keyring message leaked secret: %q", check.Message)
	}
}

func TestCheckerReportsInvalidJWKS(t *testing.T) {
	ctx := context.Background()
	paths := testPaths(t)
	if err := paths.Ensure(); err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	saveDoctorConfig(t, paths, map[string]config.Profile{})
	if err := sqlite.Migrate(ctx, sqlite.Options{Path: filepath.Join(paths.DataDir, "envvault.sqlite")}); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(paths.DataDir, "envvault-jwks.json"), []byte(`{"not_keys":[]}`), 0o644); err != nil {
		t.Fatalf("WriteFile(jwks) error = %v", err)
	}
	secrets := keyring.NewMemoryStore()
	putSecret(t, ctx, secrets, keyring.TalosHMACKey(), "hmac")
	putSecret(t, ctx, secrets, keyring.TalosSigningKey("current"), "signing")

	result, err := doctor.Checker{Paths: paths, Secrets: secrets}.Check(ctx)

	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	check := findCheck(t, result, "jwks")
	if check.Status != doctor.StatusError {
		t.Fatalf("jwks status = %q, want error", check.Status)
	}
	if check.Code != clerr.ConfigInvalid {
		t.Fatalf("jwks code = %q, want %q", check.Code, clerr.ConfigInvalid)
	}
}

func TestCheckerReportsPrivateJWKS(t *testing.T) {
	ctx := context.Background()
	paths := testPaths(t)
	if err := paths.Ensure(); err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	saveDoctorConfig(t, paths, map[string]config.Profile{})
	if err := sqlite.Migrate(ctx, sqlite.Options{Path: filepath.Join(paths.DataDir, "envvault.sqlite")}); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	createTalosSQLite(t, filepath.Join(paths.DataDir, "talos.sqlite"))
	if err := os.WriteFile(filepath.Join(paths.DataDir, "envvault-jwks.json"), []byte(`{"keys":[{"kid":"test","kty":"OKP","d":"private-seed"}]}`), 0o644); err != nil {
		t.Fatalf("WriteFile(jwks) error = %v", err)
	}
	secrets := keyring.NewMemoryStore()
	putSecret(t, ctx, secrets, keyring.TalosHMACKey(), "hmac")
	putSecret(t, ctx, secrets, keyring.TalosSigningKey("current"), "signing")

	result, err := doctor.Checker{Paths: paths, Secrets: secrets}.Check(ctx)

	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	check := findCheck(t, result, "jwks")
	if check.Status != doctor.StatusError {
		t.Fatalf("jwks status = %q, want error", check.Status)
	}
	if check.Code != clerr.ConfigInvalid {
		t.Fatalf("jwks code = %q, want %q", check.Code, clerr.ConfigInvalid)
	}
}

func TestCheckerRepairRemovesOnlyStaleRuntimeLockAndEnvVaultTempFiles(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	paths := testPaths(t)
	if err := paths.Ensure(); err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	stale := now.Add(-2 * time.Hour)
	fresh := now.Add(-time.Minute)

	staleLock := filepath.Join(paths.CacheDir, "runtime.lock")
	if err := os.MkdirAll(staleLock, 0o700); err != nil {
		t.Fatalf("MkdirAll(stale lock) error = %v", err)
	}
	if err := os.Chtimes(staleLock, stale, stale); err != nil {
		t.Fatalf("Chtimes(stale lock) error = %v", err)
	}

	tmpDir := filepath.Join(paths.CacheDir, "tmp")
	if err := os.MkdirAll(tmpDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(tmp) error = %v", err)
	}
	staleTemp := filepath.Join(tmpDir, "envvault-secret-canary.tmp")
	freshTemp := filepath.Join(tmpDir, "envvault-fresh.tmp")
	unrelated := filepath.Join(tmpDir, "other.tmp")
	for _, item := range []struct {
		path string
		when time.Time
	}{
		{path: staleTemp, when: stale},
		{path: freshTemp, when: fresh},
		{path: unrelated, when: stale},
	} {
		if err := os.WriteFile(item.path, []byte("secret-canary"), 0o600); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", item.path, err)
		}
		if err := os.Chtimes(item.path, item.when, item.when); err != nil {
			t.Fatalf("Chtimes(%s) error = %v", item.path, err)
		}
	}
	staleHome := filepath.Join(tmpDir, "envvault-home-stale")
	freshHome := filepath.Join(tmpDir, "envvault-home-fresh")
	unrelatedDir := filepath.Join(tmpDir, "envvault-unrelated-dir")
	for _, item := range []struct {
		path string
		when time.Time
	}{
		{path: staleHome, when: stale},
		{path: freshHome, when: fresh},
		{path: unrelatedDir, when: stale},
	} {
		if err := os.MkdirAll(filepath.Join(item.path, "home"), 0o700); err != nil {
			t.Fatalf("MkdirAll(%s) error = %v", item.path, err)
		}
		if strings.HasPrefix(filepath.Base(item.path), homefile.WorkspacePrefix) {
			writeHomeWorkspaceLock(t, item.path)
		}
		if err := os.Chtimes(item.path, item.when, item.when); err != nil {
			t.Fatalf("Chtimes(%s) error = %v", item.path, err)
		}
	}

	result, err := (doctor.Checker{
		Paths:            paths,
		Now:              func() time.Time { return now },
		RepairStaleAfter: time.Hour,
	}).Repair(context.Background())

	if err != nil {
		t.Fatalf("Repair() error = %v", err)
	}
	if _, err := os.Stat(staleLock); !os.IsNotExist(err) {
		t.Fatalf("stale runtime lock still exists or stat failed: %v", err)
	}
	if _, err := os.Stat(staleTemp); !os.IsNotExist(err) {
		t.Fatalf("stale temp file still exists or stat failed: %v", err)
	}
	if _, err := os.Stat(staleHome); !os.IsNotExist(err) {
		t.Fatalf("stale isolated home still exists or stat failed: %v", err)
	}
	for _, path := range []string{freshTemp, unrelated, freshHome, unrelatedDir} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s to remain: %v", path, err)
		}
	}
	rendered := renderChecks(result)
	for _, want := range []string{"repair-runtime-lock", "repair-temp-files"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("checks = %q, want %q", rendered, want)
		}
	}
	if strings.Contains(rendered, "secret-canary") {
		t.Fatalf("repair output leaked secret marker: %q", rendered)
	}
}

func TestCheckerRepairDoesNotRemoveStaleButActiveHomeWorkspace(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	fixture := prepareHealthyDoctorInstallation(t, ctx)
	secrets := keyring.NewMemoryStore()
	putSecret(t, ctx, secrets, keyring.CredentialValue("app/config"), "secret-canary")
	specs, err := homefile.ParseAll([]string{".hogehoge=envvault://app/config"})
	if err != nil {
		t.Fatalf("ParseAll() error = %v", err)
	}
	workspace, err := homefile.Prepare(ctx, homefile.Options{
		CacheDir: fixture.paths.CacheDir,
		Specs:    specs,
		Secrets:  secrets,
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	defer workspace.Close()
	workspaceRoot := filepath.Dir(workspace.HomeDir())
	stale := now.Add(-2 * time.Hour)
	if err := os.Chtimes(workspaceRoot, stale, stale); err != nil {
		t.Fatalf("Chtimes(workspace) error = %v", err)
	}

	result, err := (doctor.Checker{
		Paths:            fixture.paths,
		Secrets:          fixture.secrets,
		Now:              func() time.Time { return now },
		RepairStaleAfter: time.Hour,
		RuntimeManifest:  fixture.manifest,
		RuntimePlatform:  fixture.platform,
	}).Repair(ctx)
	if err != nil {
		t.Fatalf("Repair() error = %v", err)
	}
	if _, err := os.Stat(workspace.HomeDir()); err != nil {
		t.Fatalf("active isolated home was removed: %v", err)
	}
	if check := findCheck(t, result, "repair-temp-files"); check.Status != doctor.StatusOK {
		t.Fatalf("repair-temp-files status = %q, want ok; message=%q", check.Status, check.Message)
	}
}

func TestCheckerRepairFailsClosedWhenStaleHomeLockIsMissing(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	paths := testPaths(t)
	workspaceRoot := filepath.Join(paths.CacheDir, "tmp", homefile.WorkspacePrefix+"missing-lock")
	if err := os.MkdirAll(filepath.Join(workspaceRoot, "home"), 0o700); err != nil {
		t.Fatalf("MkdirAll(workspace) error = %v", err)
	}
	stale := now.Add(-2 * time.Hour)
	if err := os.Chtimes(workspaceRoot, stale, stale); err != nil {
		t.Fatalf("Chtimes(workspace) error = %v", err)
	}

	result, err := (doctor.Checker{
		Paths:            paths,
		Now:              func() time.Time { return now },
		RepairStaleAfter: time.Hour,
	}).Repair(context.Background())
	if err != nil {
		t.Fatalf("Repair() error = %v", err)
	}
	if _, err := os.Stat(workspaceRoot); err != nil {
		t.Fatalf("workspace with unknown active state was removed: %v", err)
	}
	if check := findCheck(t, result, "repair-temp-files"); check.Status != doctor.StatusError {
		t.Fatalf("repair-temp-files status = %q, want error; message=%q", check.Status, check.Message)
	}
}

func TestCheckerRepairStopsStaleManagedTalosProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("doctor process verification uses ps on Unix-like systems")
	}
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	paths := testPaths(t)
	if err := paths.Ensure(); err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	stale := now.Add(-2 * time.Hour)
	lockDir := filepath.Join(paths.CacheDir, "runtime.lock")
	if err := os.MkdirAll(lockDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(lock) error = %v", err)
	}
	if err := os.Chtimes(lockDir, stale, stale); err != nil {
		t.Fatalf("Chtimes(lock) error = %v", err)
	}
	configPath := filepath.Join(paths.CacheDir, "tmp", "envvault-stale.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatalf("MkdirAll(tmp) error = %v", err)
	}
	if err := os.WriteFile(configPath, []byte("runtime config"), 0o600); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestDoctorManagedTalosProcessHelper", "--", configPath)
	cmd.Env = append(os.Environ(), "ENVVAULT_DOCTOR_PROCESS_HELPER=1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start(helper) error = %v", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	reaped := false
	t.Cleanup(func() {
		if reaped {
			return
		}
		select {
		case <-done:
		default:
			_ = cmd.Process.Kill()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
			}
		}
	})

	markerPath := filepath.Join(lockDir, "talos-process.json")
	writeDoctorProcessMarker(t, markerPath, cmd.Process.Pid, os.Args[0], configPath, stale)

	result, err := (doctor.Checker{
		Paths:            paths,
		Now:              func() time.Time { return now },
		RepairStaleAfter: time.Hour,
	}).Repair(context.Background())

	if err != nil {
		t.Fatalf("Repair() error = %v", err)
	}
	select {
	case <-done:
		reaped = true
	case <-time.After(2 * time.Second):
		t.Fatal("stale helper process still running after repair")
	}
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatalf("process marker still exists after repair: %v", err)
	}
	rendered := renderChecks(result)
	if !strings.Contains(rendered, "repair-runtime-process") {
		t.Fatalf("checks = %q, want runtime process repair check", rendered)
	}
	if strings.Contains(rendered, configPath) {
		t.Fatalf("repair output leaked temp config path: %q", rendered)
	}
}

func TestDoctorManagedTalosProcessHelper(t *testing.T) {
	if os.Getenv("ENVVAULT_DOCTOR_PROCESS_HELPER") != "1" {
		return
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	select {
	case <-signals:
		os.Exit(0)
	case <-time.After(30 * time.Second):
		os.Exit(0)
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

func writeHomeWorkspaceLock(t *testing.T, workspaceRoot string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(workspaceRoot, homefile.LockFilename), nil, 0o600); err != nil {
		t.Fatalf("WriteFile(active lock) error = %v", err)
	}
}

type doctorFixture struct {
	paths    config.Paths
	secrets  keyring.Store
	manifest runtimetalos.Manifest
	platform runtimetalos.Platform
}

func prepareHealthyDoctorInstallation(t *testing.T, ctx context.Context) doctorFixture {
	t.Helper()
	paths := testPaths(t)
	if err := paths.Ensure(); err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	saveDoctorConfig(t, paths, map[string]config.Profile{
		"backend-a/dev": {
			Kind:        "process",
			Issuer:      "talos",
			Resource:    "https://api.dev.example.com",
			Scopes:      []string{"repository:read"},
			TokenTTL:    config.Duration(10 * time.Minute),
			MaxTokenTTL: config.Duration(30 * time.Minute),
		},
	})
	if err := sqlite.Migrate(ctx, sqlite.Options{Path: filepath.Join(paths.DataDir, "envvault.sqlite")}); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	createTalosSQLite(t, filepath.Join(paths.DataDir, "talos.sqlite"))
	if err := os.WriteFile(filepath.Join(paths.DataDir, "envvault-jwks.json"), []byte(`{"keys":[{"kid":"test","kty":"OKP"}]}`), 0o644); err != nil {
		t.Fatalf("WriteFile(jwks) error = %v", err)
	}
	secrets := keyring.NewMemoryStore()
	putSecret(t, ctx, secrets, keyring.TalosHMACKey(), "hmac")
	putSecret(t, ctx, secrets, keyring.TalosSigningKey("current"), "signing")
	putSecret(t, ctx, secrets, keyring.ProfileParentKey("backend-a/dev"), "parent")
	platform := runtimetalos.Platform{OS: "linux", Arch: "amd64"}
	runtimeBody := []byte("talos-runtime")
	manifest := testRuntimeManifest("test-talos", platform, runtimeBody)
	writeCachedRuntimeArtifact(t, paths, manifest, platform, runtimeBody)
	return doctorFixture{
		paths:    paths,
		secrets:  secrets,
		manifest: manifest,
		platform: platform,
	}
}

func testRuntimeManifest(version string, platform runtimetalos.Platform, body []byte) runtimetalos.Manifest {
	return runtimetalos.Manifest{
		Version:   version,
		SourceURL: "https://example.invalid/talos/releases/" + version,
		Checksums: runtimetalos.ChecksumSource{
			URL:    "https://example.invalid/talos/checksums.txt",
			SHA256: doctorDigest([]byte("checksums")),
		},
		Artifacts: []runtimetalos.Artifact{{
			OS:     platform.OS,
			Arch:   platform.Arch,
			URL:    "https://example.invalid/talos",
			SHA256: doctorDigest(body),
		}},
	}
}

func writeCachedRuntimeArtifact(t *testing.T, paths config.Paths, manifest runtimetalos.Manifest, platform runtimetalos.Platform, body []byte) {
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

func doctorDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func saveDoctorConfig(t *testing.T, paths config.Paths, profiles map[string]config.Profile) {
	t.Helper()
	if err := config.Save(paths.ConfigFile, config.File{
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
		Profiles: profiles,
	}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(paths.ConfigFile)
		if err != nil {
			t.Fatalf("Stat(config) error = %v", err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("config mode = %v, want 0600", info.Mode().Perm())
		}
	}
}

func putSecret(t *testing.T, ctx context.Context, store keyring.Store, key keyring.Key, value string) {
	t.Helper()
	if err := store.Put(ctx, key, []byte(value)); err != nil {
		t.Fatalf("Put(%s) error = %v", key, err)
	}
}

func createTalosSQLite(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll(talos sqlite) error = %v", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("Open(talos sqlite) error = %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE talos_healthcheck (id TEXT PRIMARY KEY)`); err != nil {
		t.Fatalf("create talos healthcheck table error = %v", err)
	}
}

func renderChecks(result doctor.Result) string {
	var out strings.Builder
	for _, check := range result.Checks {
		out.WriteString(string(check.Status))
		out.WriteString(" ")
		out.WriteString(check.Name)
		out.WriteString(": ")
		out.WriteString(check.Message)
		if check.Code != "" {
			out.WriteString(" ")
			out.WriteString(string(check.Code))
		}
		out.WriteString("\n")
	}
	return out.String()
}

func findCheck(t *testing.T, result doctor.Result, name string) doctor.Check {
	t.Helper()
	for _, check := range result.Checks {
		if check.Name == name {
			return check
		}
	}
	t.Fatalf("check %q not found in %#v", name, result.Checks)
	return doctor.Check{}
}

func writeDoctorProcessMarker(t *testing.T, path string, pid int, binaryPath, configPath string, startedAt time.Time) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"pid":         pid,
		"binary_path": binaryPath,
		"config_path": configPath,
		"started_at":  startedAt.UTC(),
	})
	if err != nil {
		t.Fatalf("Marshal(marker) error = %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("WriteFile(marker) error = %v", err)
	}
	if err := os.Chtimes(path, startedAt, startedAt); err != nil {
		t.Fatalf("Chtimes(marker) error = %v", err)
	}
}
