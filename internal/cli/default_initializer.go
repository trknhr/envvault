package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"time"

	"github.com/trknhr/envvault/internal/bootstrap"
	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/config"
	"github.com/trknhr/envvault/internal/issuer"
	"github.com/trknhr/envvault/internal/issuer/talos"
	"github.com/trknhr/envvault/internal/issuer/talosruntime"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/lock"
	runtimetalos "github.com/trknhr/envvault/internal/runtime/talos"
	"github.com/trknhr/envvault/internal/sqlite"
)

const talosSQLiteFilename = "talos.sqlite"
const managedTalosLockDir = "runtime.lock"

var (
	managedTalosLockTimeout      = 30 * time.Second
	managedTalosLockPollInterval = 50 * time.Millisecond
	managedTalosLockStaleAfter   = 15 * time.Minute
)

type managedTalos struct {
	paths   config.Paths
	secrets keyring.Store
	http    *http.Client
}

func newManagedTalos(paths config.Paths, secrets keyring.Store) *managedTalos {
	return &managedTalos{paths: paths, secrets: secrets, http: http.DefaultClient}
}

func (m *managedTalos) Init(ctx context.Context) (bootstrap.Result, error) {
	manifest, err := runtimetalos.DefaultReleaseManifest()
	if err != nil {
		return bootstrap.Result{}, err
	}
	httpClient := m.http
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return bootstrap.Initializer{
		Paths:         m.paths,
		Secrets:       m.secrets,
		Installer:     runtimetalos.NewInstaller(httpClient, m.paths.CacheDir),
		SQLiteMigrate: sqlite.Migrate,
		Manifest:      manifest,
		Platform:      runtimetalos.Platform{OS: goruntime.GOOS, Arch: goruntime.GOARCH},
		PrepareRuntime: func(ctx context.Context, request bootstrap.RuntimePrepareRequest) (bootstrap.JWKSFetcher, error) {
			return prepareManagedTalosRuntime(ctx, request, httpClient)
		},
	}.Init(ctx)
}

func (m *managedTalos) IssueParentKey(ctx context.Context, request talos.ParentKeyRequest) (talos.ParentKey, error) {
	client, cleanup, err := m.runtimeClient(ctx)
	if err != nil {
		return talos.ParentKey{}, err
	}
	defer cleanup()
	return client.IssueParentKey(ctx, request)
}

func (m *managedTalos) DeriveJWT(ctx context.Context, parentKey string, grant issuer.Grant) (issuer.Credential, error) {
	client, cleanup, err := m.runtimeClient(ctx)
	if err != nil {
		return issuer.Credential{}, err
	}
	defer cleanup()
	return client.DeriveJWT(ctx, parentKey, grant)
}

func (m *managedTalos) runtimeClient(ctx context.Context) (talosruntime.Client, func(), error) {
	httpClient := m.http
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	guard, err := acquireManagedTalosRuntimeLock(ctx, m.paths)
	if err != nil {
		return talosruntime.Client{}, nil, err
	}
	releaseLock := func() {
		_ = guard.Release()
	}

	manifest, err := runtimetalos.DefaultReleaseManifest()
	if err != nil {
		releaseLock()
		return talosruntime.Client{}, nil, err
	}
	installed, err := runtimetalos.NewInstaller(httpClient, m.paths.CacheDir).Install(ctx, manifest, runtimetalos.Platform{OS: goruntime.GOOS, Arch: goruntime.GOARCH})
	if err != nil {
		releaseLock()
		return talosruntime.Client{}, nil, err
	}
	runtime, cleanup, err := m.runtimeForInstalledArtifact(ctx, installed, httpClient)
	if err != nil {
		releaseLock()
		return talosruntime.Client{}, nil, err
	}
	return talosruntime.Client{Runtime: runtime, HTTP: httpClient}, func() {
		cleanup()
		releaseLock()
	}, nil
}

func (m *managedTalos) runtimeForInstalledArtifact(ctx context.Context, installed runtimetalos.InstalledArtifact, httpClient *http.Client) (*runtimetalos.Runtime, func(), error) {
	cfg, err := config.Load(m.paths.ConfigFile)
	if err != nil {
		return nil, nil, err
	}
	hmacSecret, err := m.secrets.Get(ctx, keyring.TalosHMACKey())
	if err != nil {
		return nil, nil, err
	}
	defer zero(hmacSecret)
	signingSeed, err := m.secrets.Get(ctx, keyring.TalosSigningKey("current"))
	if err != nil {
		return nil, nil, err
	}
	defer zero(signingSeed)

	httpAddress, err := reserveManagedLoopbackAddress()
	if err != nil {
		return nil, nil, err
	}
	metricsAddress, err := reserveManagedLoopbackAddress()
	if err != nil {
		return nil, nil, err
	}
	localConfig, err := managedTalosLocalConfig(bootstrap.RuntimePrepareRequest{
		Paths:          m.paths,
		Installed:      installed,
		InstallationID: cfg.Installation.ID,
		HMACSecret:     hmacSecret,
		SigningSeed:    signingSeed,
		SigningKeyID:   "current",
	}, httpAddress, metricsAddress)
	if err != nil {
		return nil, nil, err
	}
	configPath, err := temporaryTalosConfigPath(m.paths.CacheDir)
	if err != nil {
		return nil, nil, err
	}
	if err := runtimetalos.WriteLocalConfig(configPath, localConfig); err != nil {
		_ = os.Remove(configPath)
		return nil, nil, err
	}

	runtime := newManagedTalosRuntime(installed.Path, httpAddress, configPath, localConfig.DatabaseDSN, managedTalosProcessMarkerPath(m.paths), httpClient)
	if err := runtime.Migrate(ctx); err != nil {
		_ = os.Remove(configPath)
		return nil, nil, err
	}
	return runtime, func() { _ = os.Remove(configPath) }, nil
}

func prepareManagedTalosRuntime(ctx context.Context, request bootstrap.RuntimePrepareRequest, httpClient *http.Client) (bootstrap.JWKSFetcher, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	guard, err := acquireManagedTalosRuntimeLock(ctx, request.Paths)
	if err != nil {
		return nil, err
	}
	releaseLock := func() {
		_ = guard.Release()
	}

	httpAddress, err := reserveManagedLoopbackAddress()
	if err != nil {
		releaseLock()
		return nil, err
	}
	metricsAddress, err := reserveManagedLoopbackAddress()
	if err != nil {
		releaseLock()
		return nil, err
	}
	localConfig, err := managedTalosLocalConfig(request, httpAddress, metricsAddress)
	if err != nil {
		releaseLock()
		return nil, err
	}
	configPath, err := temporaryTalosConfigPath(request.Paths.CacheDir)
	if err != nil {
		releaseLock()
		return nil, err
	}
	if err := runtimetalos.WriteLocalConfig(configPath, localConfig); err != nil {
		_ = os.Remove(configPath)
		releaseLock()
		return nil, err
	}

	runtime := newManagedTalosRuntime(request.Installed.Path, httpAddress, configPath, localConfig.DatabaseDSN, managedTalosProcessMarkerPath(request.Paths), httpClient)
	if err := runtime.Migrate(ctx); err != nil {
		_ = os.Remove(configPath)
		releaseLock()
		return nil, err
	}

	client := talosruntime.Client{Runtime: runtime, HTTP: httpClient}
	return func(ctx context.Context) ([]byte, error) {
		defer releaseLock()
		defer os.Remove(configPath)
		return client.JWKS(ctx)
	}, nil
}

func newManagedTalosRuntime(binaryPath, httpAddress, configPath, databaseDSN, processMarkerPath string, httpClient *http.Client) *runtimetalos.Runtime {
	return runtimetalos.NewRuntime(runtimetalos.RuntimeOptions{
		BinaryPath:    binaryPath,
		Address:       httpAddress,
		Args:          []string{"serve", "--config", configPath},
		MigrateArgs:   []string{"migrate", "up", "--config", configPath, "--database", databaseDSN},
		HealthPath:    "/health/alive",
		StartTimeout:  10 * time.Second,
		StopTimeout:   5 * time.Second,
		PollInterval:  50 * time.Millisecond,
		StopSignal:    os.Interrupt,
		DialTimeout:   500 * time.Millisecond,
		PortCloseWait: time.Second,
		HTTPClient:    httpClient,
		ProcessStarted: func(pid int) error {
			return writeManagedTalosProcessMarker(processMarkerPath, pid, binaryPath, configPath, time.Now())
		},
		ProcessStopped: func(int) error {
			return removeManagedTalosProcessMarker(processMarkerPath)
		},
	})
}

func managedTalosLocalConfig(request bootstrap.RuntimePrepareRequest, httpAddress, metricsAddress string) (runtimetalos.LocalConfig, error) {
	if request.InstallationID == "" {
		return runtimetalos.LocalConfig{}, clerr.New(clerr.ConfigInvalid, "installation id is required")
	}
	databaseDSN, err := talosSQLiteDSN(request.Paths)
	if err != nil {
		return runtimetalos.LocalConfig{}, err
	}
	return runtimetalos.LocalConfig{
		HTTPAddress:  httpAddress,
		MetricsAddr:  metricsAddress,
		DatabaseDSN:  databaseDSN,
		Issuer:       "envvault-local:" + request.InstallationID,
		HMACSecret:   request.HMACSecret,
		SigningSeed:  request.SigningSeed,
		SigningKeyID: request.SigningKeyID,
	}, nil
}

func acquireManagedTalosRuntimeLock(ctx context.Context, paths config.Paths) (*lock.Guard, error) {
	return lock.Acquire(ctx, lock.Options{
		Path:         managedTalosLockPath(paths),
		Timeout:      managedTalosLockTimeout,
		PollInterval: managedTalosLockPollInterval,
		StaleAfter:   managedTalosLockStaleAfter,
	})
}

func managedTalosLockPath(paths config.Paths) string {
	return filepath.Join(paths.CacheDir, managedTalosLockDir)
}

func managedTalosProcessMarkerPath(paths config.Paths) string {
	return filepath.Join(managedTalosLockPath(paths), "talos-process.json")
}

type managedTalosProcessMarker struct {
	PID        int       `json:"pid"`
	BinaryPath string    `json:"binary_path"`
	ConfigPath string    `json:"config_path"`
	StartedAt  time.Time `json:"started_at"`
}

func writeManagedTalosProcessMarker(path string, pid int, binaryPath, configPath string, startedAt time.Time) error {
	if path == "" {
		return clerr.New(clerr.ConfigInvalid, "managed talos process marker path is required")
	}
	marker := managedTalosProcessMarker{
		PID:        pid,
		BinaryPath: binaryPath,
		ConfigPath: configPath,
		StartedAt:  startedAt.UTC(),
	}
	body, err := json.Marshal(marker)
	if err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "marshal managed talos process marker", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "create managed talos process marker directory", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".talos-process-*")
	if err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "create managed talos process marker", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return clerr.Wrap(clerr.ConfigInvalid, "write managed talos process marker", err)
	}
	if err := tmp.Close(); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "close managed talos process marker", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "secure managed talos process marker", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "install managed talos process marker", err)
	}
	return nil
}

func removeManagedTalosProcessMarker(path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return clerr.Wrap(clerr.CleanupFailed, "remove managed talos process marker", err)
	}
	return nil
}

func talosSQLiteDSN(paths config.Paths) (string, error) {
	path := filepath.Join(paths.DataDir, talosSQLiteFilename)
	if dsnPathNeedsAlias(path) {
		aliasPath, err := ensureTalosSQLiteAlias(paths)
		if err != nil {
			return "", err
		}
		path = aliasPath
	}
	clean := filepath.ToSlash(path)
	if strings.HasPrefix(clean, "/") {
		return "sqlite3://" + clean + "?_journal_mode=WAL", nil
	}
	return "sqlite3:///" + clean + "?_journal_mode=WAL", nil
}

func dsnPathNeedsAlias(path string) bool {
	return strings.ContainsAny(filepath.ToSlash(path), " \t\r\n")
}

func ensureTalosSQLiteAlias(paths config.Paths) (string, error) {
	if err := os.MkdirAll(paths.DataDir, 0o700); err != nil {
		return "", clerr.Wrap(clerr.RuntimeUnavailable, "create talos sqlite data directory", err)
	}
	if err := os.Chmod(paths.DataDir, 0o700); err != nil {
		return "", clerr.Wrap(clerr.RuntimeUnavailable, "secure talos sqlite data directory", err)
	}

	parent := filepath.Join(paths.CacheDir, "talos-db-aliases")
	if dsnPathNeedsAlias(parent) {
		parent = filepath.Join(os.TempDir(), "envvault-talos-db-aliases")
	}
	if dsnPathNeedsAlias(parent) {
		return "", clerr.New(clerr.RuntimeUnavailable, "talos sqlite alias path contains unsupported whitespace")
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", clerr.Wrap(clerr.RuntimeUnavailable, "create talos sqlite alias directory", err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		return "", clerr.Wrap(clerr.RuntimeUnavailable, "secure talos sqlite alias directory", err)
	}

	hash := sha256.Sum256([]byte(paths.DataDir))
	aliasDir := filepath.Join(parent, hex.EncodeToString(hash[:8]))
	if info, err := os.Lstat(aliasDir); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return "", clerr.New(clerr.RuntimeUnavailable, "talos sqlite alias path is not a symlink")
		}
		target, err := os.Readlink(aliasDir)
		if err != nil {
			return "", clerr.Wrap(clerr.RuntimeUnavailable, "inspect talos sqlite alias", err)
		}
		if target == paths.DataDir {
			return filepath.Join(aliasDir, talosSQLiteFilename), nil
		}
		return "", clerr.New(clerr.RuntimeUnavailable, "talos sqlite alias points outside envvault data directory")
	} else if !os.IsNotExist(err) {
		return "", clerr.Wrap(clerr.RuntimeUnavailable, "inspect talos sqlite alias path", err)
	}
	if err := os.Symlink(paths.DataDir, aliasDir); err != nil {
		return "", clerr.Wrap(clerr.RuntimeUnavailable, "create talos sqlite alias", err)
	}
	return filepath.Join(aliasDir, talosSQLiteFilename), nil
}

func reserveManagedLoopbackAddress() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", clerr.Wrap(clerr.RuntimeUnavailable, "reserve talos loopback address", err)
	}
	defer listener.Close()
	return listener.Addr().String(), nil
}

func temporaryTalosConfigPath(cacheDir string) (string, error) {
	tempDir := filepath.Join(cacheDir, "tmp")
	if err := os.MkdirAll(tempDir, 0o700); err != nil {
		return "", clerr.Wrap(clerr.RuntimeUnavailable, "create talos config cache directory", err)
	}
	if err := os.Chmod(tempDir, 0o700); err != nil {
		return "", clerr.Wrap(clerr.RuntimeUnavailable, "set talos config cache directory permissions", err)
	}
	tmp, err := os.CreateTemp(tempDir, "envvault-*.yaml")
	if err != nil {
		return "", clerr.Wrap(clerr.RuntimeUnavailable, "create temporary talos config path", err)
	}
	name := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return "", clerr.Wrap(clerr.RuntimeUnavailable, "close temporary talos config path", err)
	}
	if err := os.Remove(name); err != nil {
		return "", clerr.Wrap(clerr.RuntimeUnavailable, "release temporary talos config path", err)
	}
	return name, nil
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
