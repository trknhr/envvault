package doctor

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/trknhr/credlease/internal/clerr"
	"github.com/trknhr/credlease/internal/config"
	"github.com/trknhr/credlease/internal/keyring"
	runtimetalos "github.com/trknhr/credlease/internal/runtime/talos"
	_ "modernc.org/sqlite"
)

const (
	sqliteFilename      = "credlease.sqlite"
	talosSQLiteFilename = "talos.sqlite"
	jwksFilename        = "credlease-jwks.json"
	signingKeyID        = "current"
	runtimeLockDir      = "runtime.lock"
	runtimeProcessFile  = "talos-process.json"
	tempDirName         = "tmp"
)

type Status string

const (
	StatusOK    Status = "ok"
	StatusWarn  Status = "warn"
	StatusError Status = "error"
)

type Check struct {
	Name    string
	Status  Status
	Code    clerr.Code
	Message string
}

type Result struct {
	Checks []Check
}

func (r Result) HasErrors() bool {
	for _, check := range r.Checks {
		if check.Status == StatusError {
			return true
		}
	}
	return false
}

type Checker struct {
	Paths            config.Paths
	Secrets          keyring.Store
	RuntimeManifest  runtimetalos.Manifest
	RuntimePlatform  runtimetalos.Platform
	Now              func() time.Time
	RepairStaleAfter time.Duration
}

func (c Checker) Check(ctx context.Context) (Result, error) {
	var result Result

	cfg, configOK := c.checkConfig(&result)
	c.checkRuntime(&result, cfg, configOK)
	c.checkSQLite(ctx, &result)
	c.checkTalosSQLite(ctx, &result)
	c.checkJWKS(&result)
	c.checkKeyring(ctx, &result, cfg, configOK)
	c.checkCache(&result)
	c.checkRuntimeLock(&result)
	c.checkRuntimeProcess(&result)
	c.checkTempFiles(&result)

	return result, nil
}

func (c Checker) Repair(ctx context.Context) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	var result Result
	c.repairRuntimeProcess(&result)
	c.repairRuntimeLock(&result)
	c.repairTempFiles(&result)

	checks, err := c.Check(ctx)
	if err != nil {
		return result, err
	}
	result.Checks = append(result.Checks, checks.Checks...)
	return result, nil
}

func (c Checker) checkConfig(result *Result) (config.File, bool) {
	cfg, err := config.Load(c.Paths.ConfigFile)
	if err != nil {
		addError(result, "config", err, "config is invalid or missing")
		return config.File{}, false
	}
	addOK(result, "config", fmt.Sprintf("loaded installation %s with %d profile(s)", cfg.Installation.ID, len(cfg.Profiles)))
	return cfg, true
}

func (c Checker) checkRuntime(result *Result, cfg config.File, configOK bool) {
	manifest, err := c.runtimeManifest()
	if err != nil {
		addError(result, "runtime", err, "runtime manifest is invalid")
		return
	}
	if configOK && cfg.Runtime.Talos.Version != manifest.Version {
		addError(result, "runtime", clerr.New(clerr.RuntimeIncompatible, "configured talos version does not match release manifest"), "runtime version does not match release manifest")
		return
	}

	cached, err := manifest.CachedArtifactPaths(c.Paths.CacheDir, c.runtimePlatform())
	if err != nil {
		addError(result, "runtime", err, "runtime artifact is unavailable")
		return
	}

	digestPath := cached.Binary
	if cached.Archive != "" {
		if err := requireRegularFile(cached.Binary, "inspect talos runtime binary"); err != nil {
			addError(result, "runtime", err, "runtime artifact is unavailable")
			return
		}
		digestPath = cached.Archive
	}
	ok, err := fileMatchesSHA256(digestPath, cached.SHA256)
	if err != nil {
		addError(result, "runtime", err, "runtime artifact is unavailable")
		return
	}
	if !ok {
		addError(result, "runtime", clerr.New(clerr.RuntimeIncompatible, "talos artifact checksum mismatch"), "runtime artifact checksum mismatch")
		return
	}
	addOK(result, "runtime", fmt.Sprintf("talos %s artifact checksum ok", manifest.Version))
}

func (c Checker) checkSQLite(ctx context.Context, result *Result) {
	path := filepath.Join(c.Paths.DataDir, sqliteFilename)
	info, err := os.Stat(path)
	if err != nil {
		addError(result, "sqlite", clerr.Wrap(clerr.ConfigInvalid, "inspect sqlite database", err), "sqlite database is unavailable")
		return
	}
	if info.IsDir() {
		addError(result, "sqlite", clerr.New(clerr.ConfigInvalid, "sqlite path is a directory"), "sqlite database is unavailable")
		return
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		addError(result, "sqlite", clerr.Wrap(clerr.ConfigInvalid, "open sqlite database", err), "sqlite database is unavailable")
		return
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		addError(result, "sqlite", clerr.Wrap(clerr.ConfigInvalid, "ping sqlite database", err), "sqlite database is unavailable")
		return
	}

	var integrity string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil {
		addError(result, "sqlite", clerr.Wrap(clerr.ConfigInvalid, "run sqlite integrity check", err), "sqlite integrity check failed")
		return
	}
	if integrity != "ok" {
		addError(result, "sqlite", clerr.New(clerr.ConfigInvalid, "sqlite integrity check failed"), "sqlite integrity check failed")
		return
	}

	var version int
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&version); err != nil {
		addError(result, "sqlite", clerr.Wrap(clerr.ConfigInvalid, "read sqlite migration version", err), "sqlite schema is invalid")
		return
	}
	if version < 1 {
		addError(result, "sqlite", clerr.New(clerr.ConfigInvalid, "sqlite schema is not migrated"), "sqlite schema is invalid")
		return
	}
	addOK(result, "sqlite", fmt.Sprintf("integrity ok; schema version %d", version))
}

func (c Checker) checkTalosSQLite(ctx context.Context, result *Result) {
	path := filepath.Join(c.Paths.DataDir, talosSQLiteFilename)
	info, err := os.Stat(path)
	if err != nil {
		addError(result, "talos-sqlite", clerr.Wrap(clerr.ConfigInvalid, "inspect talos sqlite database", err), "talos sqlite database is unavailable")
		return
	}
	if info.IsDir() {
		addError(result, "talos-sqlite", clerr.New(clerr.ConfigInvalid, "talos sqlite path is a directory"), "talos sqlite database is unavailable")
		return
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		addError(result, "talos-sqlite", clerr.Wrap(clerr.ConfigInvalid, "open talos sqlite database", err), "talos sqlite database is unavailable")
		return
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		addError(result, "talos-sqlite", clerr.Wrap(clerr.ConfigInvalid, "ping talos sqlite database", err), "talos sqlite database is unavailable")
		return
	}

	var integrity string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil {
		addError(result, "talos-sqlite", clerr.Wrap(clerr.ConfigInvalid, "run talos sqlite integrity check", err), "talos sqlite integrity check failed")
		return
	}
	if integrity != "ok" {
		addError(result, "talos-sqlite", clerr.New(clerr.ConfigInvalid, "talos sqlite integrity check failed"), "talos sqlite integrity check failed")
		return
	}
	addOK(result, "talos-sqlite", "integrity ok")
}

func (c Checker) checkJWKS(result *Result) {
	path := filepath.Join(c.Paths.DataDir, jwksFilename)
	body, err := os.ReadFile(path)
	if err != nil {
		addError(result, "jwks", clerr.Wrap(clerr.ConfigInvalid, "read jwks file", err), "jwks file is unavailable")
		return
	}
	keyCount, err := validateJWKS(body)
	if err != nil {
		addError(result, "jwks", err, "jwks file is invalid")
		return
	}
	addOK(result, "jwks", fmt.Sprintf("keys array present with %d key(s)", keyCount))
}

func (c Checker) checkKeyring(ctx context.Context, result *Result, cfg config.File, configOK bool) {
	if c.Secrets == nil {
		addError(result, "keyring", clerr.New(clerr.KeyringUnavailable, "OS credential store unavailable"), "required keyring entries unavailable")
		return
	}

	keys := []keyring.Key{
		keyring.TalosHMACKey(),
		keyring.TalosSigningKey(signingKeyID),
	}
	if configOK {
		names := make([]string, 0, len(cfg.Profiles))
		for name := range cfg.Profiles {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			keys = append(keys, keyring.ProfileParentKey(name))
		}
	}

	for _, key := range keys {
		value, err := c.Secrets.Get(ctx, key)
		if err != nil {
			addError(result, "keyring", err, "required keyring entry unavailable: "+string(key))
			return
		}
		zero(value)
	}
	addOK(result, "keyring", fmt.Sprintf("%d required entr%s present", len(keys), pluralY(len(keys))))
}

func (c Checker) checkCache(result *Result) {
	info, err := os.Stat(c.Paths.CacheDir)
	if err != nil {
		if os.IsNotExist(err) {
			result.Checks = append(result.Checks, Check{
				Name:    "cache",
				Status:  StatusWarn,
				Message: "cache directory is missing",
			})
			return
		}
		addError(result, "cache", clerr.Wrap(clerr.ConfigInvalid, "inspect cache directory", err), "cache directory is unavailable")
		return
	}
	if !info.IsDir() {
		addError(result, "cache", clerr.New(clerr.ConfigInvalid, "cache path is not a directory"), "cache directory is unavailable")
		return
	}
	addOK(result, "cache", "cache directory present")
}

func (c Checker) checkRuntimeLock(result *Result) {
	path := filepath.Join(c.Paths.CacheDir, runtimeLockDir)
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			addOK(result, "runtime-lock", "no stale runtime lock")
			return
		}
		addError(result, "runtime-lock", clerr.Wrap(clerr.ConfigInvalid, "inspect runtime lock", err), "runtime lock is unavailable")
		return
	}
	if !info.IsDir() {
		addError(result, "runtime-lock", clerr.New(clerr.ConfigInvalid, "runtime lock path is not a directory"), "runtime lock is unavailable")
		return
	}
	if c.isStale(info) {
		addWarn(result, "runtime-lock", "stale runtime lock found")
		return
	}
	addOK(result, "runtime-lock", "runtime lock is not stale")
}

func (c Checker) checkRuntimeProcess(result *Result) {
	path := runtimeProcessMarkerPath(c.Paths)
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			addOK(result, "runtime-process", "no stale runtime process")
			return
		}
		addError(result, "runtime-process", clerr.Wrap(clerr.ConfigInvalid, "inspect runtime process marker", err), "runtime process marker is unavailable")
		return
	}
	if info.IsDir() {
		addError(result, "runtime-process", clerr.New(clerr.ConfigInvalid, "runtime process marker path is a directory"), "runtime process marker is unavailable")
		return
	}
	if c.isStale(info) {
		addWarn(result, "runtime-process", "stale runtime process marker found")
		return
	}
	addOK(result, "runtime-process", "runtime process marker is not stale")
}

func (c Checker) checkTempFiles(result *Result) {
	dir := filepath.Join(c.Paths.CacheDir, tempDirName)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			addOK(result, "temp-files", "no stale temporary files")
			return
		}
		addError(result, "temp-files", clerr.Wrap(clerr.ConfigInvalid, "inspect temporary directory", err), "temporary directory is unavailable")
		return
	}

	stale := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "credlease-") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			addError(result, "temp-files", clerr.Wrap(clerr.ConfigInvalid, "inspect temporary file", err), "temporary directory is unavailable")
			return
		}
		if c.isStale(info) {
			stale++
		}
	}
	if stale == 0 {
		addOK(result, "temp-files", "no stale temporary files")
		return
	}
	addWarn(result, "temp-files", fmt.Sprintf("%d stale temporary file%s found", stale, pluralS(stale)))
}

func (c Checker) repairRuntimeLock(result *Result) {
	path := filepath.Join(c.Paths.CacheDir, runtimeLockDir)
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			addOK(result, "repair-runtime-lock", "no stale runtime lock")
			return
		}
		addError(result, "repair-runtime-lock", clerr.Wrap(clerr.ConfigInvalid, "inspect runtime lock", err), "runtime lock repair failed")
		return
	}
	if !info.IsDir() {
		addError(result, "repair-runtime-lock", clerr.New(clerr.ConfigInvalid, "runtime lock path is not a directory"), "runtime lock repair failed")
		return
	}
	if !c.isStale(info) {
		addOK(result, "repair-runtime-lock", "runtime lock is not stale")
		return
	}
	if err := os.RemoveAll(path); err != nil {
		addError(result, "repair-runtime-lock", clerr.Wrap(clerr.CleanupFailed, "remove stale runtime lock", err), "runtime lock repair failed")
		return
	}
	addOK(result, "repair-runtime-lock", "removed stale runtime lock")
}

func (c Checker) repairRuntimeProcess(result *Result) {
	path := runtimeProcessMarkerPath(c.Paths)
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			addOK(result, "repair-runtime-process", "no stale runtime process")
			return
		}
		addError(result, "repair-runtime-process", clerr.Wrap(clerr.ConfigInvalid, "inspect runtime process marker", err), "runtime process repair failed")
		return
	}
	if info.IsDir() {
		addError(result, "repair-runtime-process", clerr.New(clerr.ConfigInvalid, "runtime process marker path is a directory"), "runtime process repair failed")
		return
	}
	if !c.isStale(info) {
		addOK(result, "repair-runtime-process", "runtime process marker is not stale")
		return
	}

	marker, err := readRuntimeProcessMarker(path)
	if err != nil {
		addError(result, "repair-runtime-process", err, "runtime process repair failed")
		return
	}
	stopped, err := stopRuntimeProcess(marker)
	if err != nil {
		addError(result, "repair-runtime-process", err, "runtime process repair failed")
		return
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		addError(result, "repair-runtime-process", clerr.Wrap(clerr.CleanupFailed, "remove runtime process marker", err), "runtime process repair failed")
		return
	}
	if stopped {
		addOK(result, "repair-runtime-process", "stopped stale managed talos process")
		return
	}
	addOK(result, "repair-runtime-process", "removed stale runtime process marker")
}

func (c Checker) repairTempFiles(result *Result) {
	dir := filepath.Join(c.Paths.CacheDir, tempDirName)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			addOK(result, "repair-temp-files", "no stale temporary files")
			return
		}
		addError(result, "repair-temp-files", clerr.Wrap(clerr.ConfigInvalid, "inspect temporary directory", err), "temporary file repair failed")
		return
	}

	removed := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "credlease-") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			addError(result, "repair-temp-files", clerr.Wrap(clerr.ConfigInvalid, "inspect temporary file", err), "temporary file repair failed")
			return
		}
		if !c.isStale(info) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
			addError(result, "repair-temp-files", clerr.Wrap(clerr.CleanupFailed, "remove stale temporary file", err), "temporary file repair failed")
			return
		}
		removed++
	}
	if removed == 0 {
		addOK(result, "repair-temp-files", "no stale temporary files")
		return
	}
	addOK(result, "repair-temp-files", fmt.Sprintf("removed %d stale temporary file%s", removed, pluralS(removed)))
}

func (c Checker) isStale(info os.FileInfo) bool {
	return c.now().Sub(info.ModTime()) >= c.repairStaleAfter()
}

func (c Checker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c Checker) repairStaleAfter() time.Duration {
	if c.RepairStaleAfter > 0 {
		return c.RepairStaleAfter
	}
	return 15 * time.Minute
}

func (c Checker) runtimeManifest() (runtimetalos.Manifest, error) {
	if c.RuntimeManifest.Version != "" || len(c.RuntimeManifest.Artifacts) > 0 {
		return c.RuntimeManifest, nil
	}
	return runtimetalos.DefaultReleaseManifest()
}

func (c Checker) runtimePlatform() runtimetalos.Platform {
	if c.RuntimePlatform.OS != "" || c.RuntimePlatform.Arch != "" {
		return c.RuntimePlatform
	}
	return runtimetalos.Platform{OS: goruntime.GOOS, Arch: goruntime.GOARCH}
}

type runtimeProcessMarker struct {
	PID        int       `json:"pid"`
	BinaryPath string    `json:"binary_path"`
	ConfigPath string    `json:"config_path"`
	StartedAt  time.Time `json:"started_at"`
}

func runtimeProcessMarkerPath(paths config.Paths) string {
	return filepath.Join(paths.CacheDir, runtimeLockDir, runtimeProcessFile)
}

func readRuntimeProcessMarker(path string) (runtimeProcessMarker, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return runtimeProcessMarker{}, clerr.Wrap(clerr.ConfigInvalid, "read runtime process marker", err)
	}
	var marker runtimeProcessMarker
	if err := json.Unmarshal(body, &marker); err != nil {
		return runtimeProcessMarker{}, clerr.Wrap(clerr.ConfigInvalid, "parse runtime process marker", err)
	}
	if marker.PID <= 0 {
		return runtimeProcessMarker{}, clerr.New(clerr.ConfigInvalid, "runtime process marker pid is invalid")
	}
	return marker, nil
}

func stopRuntimeProcess(marker runtimeProcessMarker) (bool, error) {
	if goruntime.GOOS == "windows" {
		return false, nil
	}
	command, running, err := runtimeProcessCommand(marker.PID)
	if err != nil {
		return false, err
	}
	if !running {
		return false, nil
	}
	if marker.ConfigPath == "" || !strings.Contains(command, marker.ConfigPath) {
		return false, nil
	}

	process, err := os.FindProcess(marker.PID)
	if err != nil {
		return false, clerr.Wrap(clerr.CleanupFailed, "find runtime process", err)
	}
	_ = process.Signal(os.Interrupt)
	if waitRuntimeProcessExit(marker.PID, 2*time.Second) {
		return true, nil
	}
	_ = process.Kill()
	if waitRuntimeProcessExit(marker.PID, 2*time.Second) {
		return true, nil
	}
	return false, clerr.New(clerr.CleanupFailed, "runtime process did not stop")
}

func runtimeProcessCommand(pid int) (string, bool, error) {
	cmd := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "command=")
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", false, nil
		}
		return "", false, clerr.Wrap(clerr.CleanupFailed, "inspect runtime process", err)
	}
	command := strings.TrimSpace(string(out))
	if command == "" {
		return "", false, nil
	}
	return command, true, nil
}

func waitRuntimeProcessExit(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		_, running, _ := runtimeProcessCommand(pid)
		if !running {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func validateJWKS(body []byte) (int, error) {
	var parsed struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return 0, clerr.Wrap(clerr.ConfigInvalid, "parse jwks", err)
	}
	if parsed.Keys == nil {
		return 0, clerr.New(clerr.ConfigInvalid, "jwks keys array is required")
	}
	for _, key := range parsed.Keys {
		for _, field := range privateJWKFields {
			if _, exists := key[field]; exists {
				return 0, clerr.New(clerr.ConfigInvalid, "jwks must not contain private key material")
			}
		}
	}
	return len(parsed.Keys), nil
}

var privateJWKFields = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

func requireRegularFile(path, action string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return clerr.New(clerr.RuntimeUnavailable, "talos runtime artifact missing")
		}
		return clerr.Wrap(clerr.RuntimeUnavailable, action, err)
	}
	if info.IsDir() {
		return clerr.New(clerr.RuntimeUnavailable, "talos runtime artifact path is a directory")
	}
	return nil
}

func fileMatchesSHA256(path, want string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, clerr.New(clerr.RuntimeUnavailable, "talos runtime artifact missing")
		}
		return false, clerr.Wrap(clerr.RuntimeUnavailable, "open talos runtime artifact", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return false, clerr.Wrap(clerr.RuntimeUnavailable, "hash talos runtime artifact", err)
	}
	got := hex.EncodeToString(hash.Sum(nil))
	return got == want, nil
}

func addOK(result *Result, name, message string) {
	result.Checks = append(result.Checks, Check{
		Name:    name,
		Status:  StatusOK,
		Message: message,
	})
}

func addWarn(result *Result, name, message string) {
	result.Checks = append(result.Checks, Check{
		Name:    name,
		Status:  StatusWarn,
		Message: message,
	})
}

func addError(result *Result, name string, err error, message string) {
	code, ok := clerr.CodeOf(err)
	if !ok {
		code = clerr.ConfigInvalid
	}
	result.Checks = append(result.Checks, Check{
		Name:    name,
		Status:  StatusError,
		Code:    code,
		Message: message,
	})
}

func pluralY(count int) string {
	if count == 1 {
		return "y"
	}
	return "ies"
}

func pluralS(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
