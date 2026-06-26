package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/admin"
	"github.com/trknhr/envvault/internal/audit"
	"github.com/trknhr/envvault/internal/bootstrap"
	"github.com/trknhr/envvault/internal/browser"
	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/config"
	doctorpkg "github.com/trknhr/envvault/internal/doctor"
	"github.com/trknhr/envvault/internal/issuer/local"
	"github.com/trknhr/envvault/internal/lock"
	"github.com/trknhr/envvault/internal/process"
	"github.com/trknhr/envvault/internal/profile"
	"github.com/trknhr/envvault/internal/profilemgr"
	"github.com/trknhr/envvault/internal/projectbinding"
	resetpkg "github.com/trknhr/envvault/internal/reset"
	runtimetalos "github.com/trknhr/envvault/internal/runtime/talos"
)

func TestDefaultOptionsWireResetAndDoctorServices(t *testing.T) {
	paths := config.Paths{
		ConfigDir:  filepath.Join(t.TempDir(), "config"),
		ConfigFile: filepath.Join(t.TempDir(), "config", "config.yaml"),
		DataDir:    filepath.Join(t.TempDir(), "data"),
		CacheDir:   filepath.Join(t.TempDir(), "cache"),
	}

	options := defaultOptions(paths)

	if options.Paths != paths {
		t.Fatalf("Paths = %#v, want %#v", options.Paths, paths)
	}
	profiles, ok := options.Profiles.(config.ProfileStore)
	if !ok {
		t.Fatalf("Profiles = %T, want config.ProfileStore", options.Profiles)
	}
	if profiles.Path != paths.ConfigFile {
		t.Fatalf("profile store path = %q, want %q", profiles.Path, paths.ConfigFile)
	}
	if _, ok := options.Runner.(process.Runner); !ok {
		t.Fatalf("Runner = %T, want process.Runner", options.Runner)
	}
	if options.Initializer == nil {
		t.Fatal("Initializer = nil, want managed Talos initializer")
	}
	if _, ok := options.ProfileManager.(*profilemgr.Manager); !ok {
		t.Fatalf("ProfileManager = %T, want profile manager backed by managed Talos", options.ProfileManager)
	}
	if _, ok := options.Issuer.(*local.Issuer); !ok {
		t.Fatalf("Issuer = %T, want local issuer backed by managed Talos", options.Issuer)
	}
	browserClient, ok := options.Browser.(browser.Client)
	if !ok {
		t.Fatalf("Browser = %T, want browser.Client", options.Browser)
	}
	if browserClient.Issuer == nil {
		t.Fatal("Browser.Issuer = nil, want managed Talos issuer")
	}
	if browserClient.Opener == nil {
		t.Fatal("Browser.Opener = nil, want command opener")
	}
	auditRecorder, ok := browserClient.Audit.(*audit.FileRecorder)
	if !ok {
		t.Fatalf("Browser.Audit = %T, want audit.FileRecorder", browserClient.Audit)
	}
	if auditRecorder.Path != filepath.Join(paths.DataDir, "audit.jsonl") {
		t.Fatalf("audit path = %q, want data audit log", auditRecorder.Path)
	}
	resetter, ok := options.Resetter.(resetpkg.Planner)
	if !ok {
		t.Fatalf("Resetter = %T, want reset.Planner", options.Resetter)
	}
	if resetter.Paths != paths {
		t.Fatalf("resetter paths = %#v, want %#v", resetter.Paths, paths)
	}
	if resetter.Secrets == nil {
		t.Fatal("resetter Secrets = nil, want OS keyring store")
	}
	doctor, ok := options.Doctor.(doctorpkg.Checker)
	if !ok {
		t.Fatalf("Doctor = %T, want doctor.Checker", options.Doctor)
	}
	if doctor.Paths != paths {
		t.Fatalf("doctor paths = %#v, want %#v", doctor.Paths, paths)
	}
	if doctor.Secrets == nil {
		t.Fatal("doctor Secrets = nil, want OS keyring store")
	}
	if options.ProjectBindingConfirmer == nil {
		t.Fatal("ProjectBindingConfirmer = nil, want TTY confirmer")
	}
	if _, ok := options.AdminController.(admin.Control); !ok {
		t.Fatalf("AdminController = %T, want admin.Control", options.AdminController)
	}
	if options.AdminServer == nil {
		t.Fatal("AdminServer = nil, want local admin server")
	}
}

func TestManagedTalosLocalConfigUsesDedicatedRuntimeDBAndIssuer(t *testing.T) {
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir:  filepath.Join(root, "config"),
		ConfigFile: filepath.Join(root, "config", "config.yaml"),
		DataDir:    filepath.Join(root, "data"),
		CacheDir:   filepath.Join(root, "cache"),
	}
	hmacSecret := []byte("0123456789abcdef0123456789abcdef")
	signingSeed := []byte("abcdef0123456789abcdef0123456789")

	localConfig, err := managedTalosLocalConfig(bootstrap.RuntimePrepareRequest{
		Paths:          paths,
		InstallationID: "01JTESTINSTALL",
		HMACSecret:     hmacSecret,
		SigningSeed:    signingSeed,
		SigningKeyID:   "current",
	}, "127.0.0.1:12345", "127.0.0.1:12346")
	if err != nil {
		t.Fatalf("managedTalosLocalConfig() error = %v", err)
	}

	if localConfig.HTTPAddress != "127.0.0.1:12345" {
		t.Fatalf("HTTPAddress = %q", localConfig.HTTPAddress)
	}
	if localConfig.MetricsAddr != "127.0.0.1:12346" {
		t.Fatalf("MetricsAddr = %q", localConfig.MetricsAddr)
	}
	wantDSN := "sqlite3://" + filepath.ToSlash(filepath.Join(root, "data", "talos.sqlite")) + "?_journal_mode=WAL"
	if localConfig.DatabaseDSN != wantDSN {
		t.Fatalf("DatabaseDSN = %q, want %q", localConfig.DatabaseDSN, wantDSN)
	}
	if localConfig.Issuer != "envvault-local:01JTESTINSTALL" {
		t.Fatalf("Issuer = %q", localConfig.Issuer)
	}
	if !bytes.Equal(localConfig.HMACSecret, hmacSecret) {
		t.Fatalf("HMACSecret = %q", localConfig.HMACSecret)
	}
	if !bytes.Equal(localConfig.SigningSeed, signingSeed) {
		t.Fatalf("SigningSeed = %q", localConfig.SigningSeed)
	}
	if localConfig.SigningKeyID != "current" {
		t.Fatalf("SigningKeyID = %q", localConfig.SigningKeyID)
	}
}

func TestManagedTalosLocalConfigUsesWhitespaceSafeSQLiteAlias(t *testing.T) {
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir:  filepath.Join(root, "Application Support", "envvault"),
		ConfigFile: filepath.Join(root, "Application Support", "envvault", "config.yaml"),
		DataDir:    filepath.Join(root, "Application Support", "envvault"),
		CacheDir:   filepath.Join(root, "cache"),
	}

	localConfig, err := managedTalosLocalConfig(bootstrap.RuntimePrepareRequest{
		Paths:          paths,
		InstallationID: "01JTESTINSTALL",
		HMACSecret:     []byte("0123456789abcdef0123456789abcdef"),
		SigningSeed:    []byte("abcdef0123456789abcdef0123456789"),
		SigningKeyID:   "current",
	}, "127.0.0.1:12345", "127.0.0.1:12346")
	if err != nil {
		t.Fatalf("managedTalosLocalConfig() error = %v", err)
	}

	if strings.Contains(localConfig.DatabaseDSN, "Application Support") {
		t.Fatalf("DatabaseDSN = %q, want whitespace-safe alias path", localConfig.DatabaseDSN)
	}
	if !strings.HasPrefix(localConfig.DatabaseDSN, "sqlite3://") {
		t.Fatalf("DatabaseDSN = %q, want sqlite3 DSN", localConfig.DatabaseDSN)
	}

	aliasRoot := filepath.Join(paths.CacheDir, "talos-db-aliases")
	entries, err := os.ReadDir(aliasRoot)
	if err != nil {
		t.Fatalf("ReadDir(%q) error = %v", aliasRoot, err)
	}
	if len(entries) != 1 {
		t.Fatalf("alias entries = %d, want 1", len(entries))
	}
	aliasDir := filepath.Join(aliasRoot, entries[0].Name())
	target, err := os.Readlink(aliasDir)
	if err != nil {
		t.Fatalf("Readlink(%q) error = %v", aliasDir, err)
	}
	if target != paths.DataDir {
		t.Fatalf("alias target = %q, want %q", target, paths.DataDir)
	}
	if !strings.Contains(localConfig.DatabaseDSN, filepath.ToSlash(filepath.Join(aliasDir, talosSQLiteFilename))) {
		t.Fatalf("DatabaseDSN = %q, want alias sqlite path %q", localConfig.DatabaseDSN, filepath.Join(aliasDir, talosSQLiteFilename))
	}
}

func TestPrepareManagedTalosRuntimeRequiresRuntimeLock(t *testing.T) {
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir:  filepath.Join(root, "config"),
		ConfigFile: filepath.Join(root, "config", "config.yaml"),
		DataDir:    filepath.Join(root, "data"),
		CacheDir:   filepath.Join(root, "cache"),
	}
	held, err := lock.Acquire(context.Background(), lock.Options{
		Path:    managedTalosLockPath(paths),
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	defer held.Release()
	oldTimeout := managedTalosLockTimeout
	oldPoll := managedTalosLockPollInterval
	managedTalosLockTimeout = 25 * time.Millisecond
	managedTalosLockPollInterval = 5 * time.Millisecond
	defer func() {
		managedTalosLockTimeout = oldTimeout
		managedTalosLockPollInterval = oldPoll
	}()

	_, err = prepareManagedTalosRuntime(context.Background(), bootstrap.RuntimePrepareRequest{
		Paths:          paths,
		InstallationID: "01JTESTINSTALL",
		Installed:      runtimetalos.InstalledArtifact{Path: filepath.Join(root, "missing-talos"), Version: "test"},
		HMACSecret:     []byte("0123456789abcdef0123456789abcdef"),
		SigningSeed:    []byte("abcdef0123456789abcdef0123456789"),
		SigningKeyID:   "current",
	}, nil)
	if err == nil {
		t.Fatal("prepareManagedTalosRuntime() error = nil, want lock timeout")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.LockTimeout {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.LockTimeout)
	}
}

func TestTemporaryTalosConfigPathUsesDoctorRepairableTempDirectory(t *testing.T) {
	cacheDir := filepath.Join(t.TempDir(), "cache")

	path, err := temporaryTalosConfigPath(cacheDir)
	if err != nil {
		t.Fatalf("temporaryTalosConfigPath() error = %v", err)
	}

	if got, want := filepath.Dir(path), filepath.Join(cacheDir, "tmp"); got != want {
		t.Fatalf("temporary config dir = %q, want %q", got, want)
	}
	if !strings.HasPrefix(filepath.Base(path), "envvault-") {
		t.Fatalf("temporary config basename = %q, want envvault-*", filepath.Base(path))
	}
	if filepath.Ext(path) != ".yaml" {
		t.Fatalf("temporary config extension = %q, want .yaml", filepath.Ext(path))
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("temporary placeholder exists or stat failed: %v", err)
	}
	info, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("Stat(temp dir) error = %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("temp path parent is not a directory")
	}
}

func TestManagedTalosProcessMarkerLifecycle(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "cache", "runtime.lock", "talos-process.json")

	if err := writeManagedTalosProcessMarker(path, 12345, "/usr/local/bin/talos", "/tmp/envvault-runtime.yaml", now); err != nil {
		t.Fatalf("writeManagedTalosProcessMarker() error = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(marker) error = %v", err)
	}
	var marker managedTalosProcessMarker
	if err := json.Unmarshal(raw, &marker); err != nil {
		t.Fatalf("Unmarshal(marker) error = %v; body=%s", err, raw)
	}
	if marker.PID != 12345 {
		t.Fatalf("PID = %d, want 12345", marker.PID)
	}
	if marker.BinaryPath != "/usr/local/bin/talos" {
		t.Fatalf("BinaryPath = %q", marker.BinaryPath)
	}
	if marker.ConfigPath != "/tmp/envvault-runtime.yaml" {
		t.Fatalf("ConfigPath = %q", marker.ConfigPath)
	}
	if !marker.StartedAt.Equal(now.UTC()) {
		t.Fatalf("StartedAt = %s, want %s", marker.StartedAt, now.UTC())
	}

	if err := removeManagedTalosProcessMarker(path); err != nil {
		t.Fatalf("removeManagedTalosProcessMarker() error = %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("marker still exists after remove: %v", err)
	}
}

func TestTTYProjectBindingConfirmerRejectsNonInteractiveInput(t *testing.T) {
	var stderr strings.Builder
	confirmer := ttyProjectBindingConfirmer{
		input:      strings.NewReader("yes\n"),
		isTerminal: func() bool { return false },
		output:     &stderr,
	}

	err := confirmer.ConfirmProjectBinding(context.Background(), ProjectBindingConfirmation{
		Mode: profile.ProjectBindingPathHash,
		Identity: projectbinding.Identity{
			Root: "/work/backend-a",
		},
	})

	if code, _ := clerr.CodeOf(err); code != clerr.ProjectNotTrusted {
		t.Fatalf("ConfirmProjectBinding() error = %v, want %s", err, clerr.ProjectNotTrusted)
	}
	if strings.Contains(stderr.String(), "yes") {
		t.Fatalf("stderr = %q, want no input echo", stderr.String())
	}
}

func TestTTYProjectBindingConfirmerAcceptsExplicitYes(t *testing.T) {
	var stderr strings.Builder
	confirmer := ttyProjectBindingConfirmer{
		input:      strings.NewReader("yes\n"),
		isTerminal: func() bool { return true },
		output:     &stderr,
	}

	err := confirmer.ConfirmProjectBinding(context.Background(), ProjectBindingConfirmation{
		Mode: profile.ProjectBindingGitRemoteAndRoot,
		Identity: projectbinding.Identity{
			Root:      "/work/backend-a",
			GitRemote: "git@example.com:team/backend-a.git",
		},
	})

	if err != nil {
		t.Fatalf("ConfirmProjectBinding() error = %v", err)
	}
	for _, want := range []string{"/work/backend-a", "git@example.com:team/backend-a.git"} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr = %q, want %q", stderr.String(), want)
		}
	}
}

func TestDefaultResetDryRunUsesPlanner(t *testing.T) {
	paths := config.Paths{
		ConfigDir:  filepath.Join(t.TempDir(), "config"),
		ConfigFile: filepath.Join(t.TempDir(), "config", "config.yaml"),
		DataDir:    filepath.Join(t.TempDir(), "data"),
		CacheDir:   filepath.Join(t.TempDir(), "cache"),
	}
	app := New(defaultOptions(paths))
	var stdout, stderr strings.Builder

	code := app.Run(context.Background(), []string{"reset", "--dry-run"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), paths.ConfigFile) {
		t.Fatalf("stdout = %q, want config file in dry-run plan", stdout.String())
	}
	if strings.Contains(stdout.String(), "secret-canary") || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q, want no secret and empty stderr", stdout.String(), stderr.String())
	}
}
