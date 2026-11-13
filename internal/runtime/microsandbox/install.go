// Package microsandbox manages the optional native launcher without linking its SDK.
package microsandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const Helper = "envvault-microsandbox"
const releaseBase = "https://github.com/trknhr/envvault/releases/download/"
const maxBinaryBytes = 128 << 20

var releaseVersion = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
var checksumPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Manager struct {
	Dir     string
	Version string
	HTTP    *http.Client
}

type receipt struct {
	SHA256 string `json:"sha256"`
}

func (m Manager) versionDir() (string, error) {
	if m.Version != "dev" && !releaseVersion.MatchString(m.Version) {
		return "", errors.New("Microsandbox setup requires a release version or a development build")
	}
	if m.Dir == "" || !filepath.IsAbs(m.Dir) {
		return "", errors.New("Microsandbox helper directory must be absolute")
	}
	versionDir := filepath.Join(m.Dir, m.Version)
	dir := filepath.Join(versionDir, runtime.GOOS+"-"+runtime.GOARCH)
	for _, path := range []string{versionDir, dir} {
		if err := rejectSymlink(path); err != nil {
			return "", err
		}
	}
	return dir, nil
}

// Resolve checks the installed bytes on every launch. Receipts contain a digest,
// never an executable path supplied by an external manifest.
func (m Manager) Resolve() (string, error) {
	dir, err := m.versionDir()
	if err != nil {
		return "", err
	}
	receiptPath := filepath.Join(dir, "current.json")
	if err := rejectSymlink(receiptPath); err != nil {
		return "", err
	}
	f, err := os.Open(receiptPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1025))
	var r receipt
	if err != nil || len(data) > 1024 || json.Unmarshal(data, &r) != nil || !checksumPattern.MatchString(r.SHA256) {
		return "", errors.New("invalid Microsandbox installation receipt; run envvault sandbox setup --force")
	}
	binary := filepath.Join(dir, r.SHA256, Helper)
	if err := rejectSymlink(filepath.Dir(binary)); err != nil {
		return "", err
	}
	info, err := os.Lstat(binary)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		return "", errors.New("invalid installed Microsandbox helper; run envvault sandbox setup --force")
	}
	f, err = os.Open(binary)
	if err != nil {
		return "", err
	}
	defer f.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(f, maxBinaryBytes+1))
	if err != nil || size > maxBinaryBytes || hex.EncodeToString(hash.Sum(nil)) != r.SHA256 {
		return "", errors.New("Microsandbox helper checksum mismatch; run envvault sandbox setup --force")
	}
	return binary, nil
}

// Install downloads the helper from the same release as the core CLI. Source
// builds may explicitly supply a trusted local helper instead.
func (m Manager) Install(ctx context.Context, source string, force bool) (string, error) {
	if err := supportedPlatform(); err != nil {
		return "", err
	}
	dir, err := m.versionDir()
	if err != nil {
		return "", err
	}
	if source == "" && !force {
		if binary, err := m.Resolve(); err == nil {
			return binary, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
	if source == "" && m.Version == "dev" {
		return "", errors.New("development build: use envvault sandbox setup --helper /absolute/path/envvault-microsandbox")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	stage, err := os.MkdirTemp(dir, ".install-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(stage)
	f, err := os.OpenFile(filepath.Join(stage, Helper), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		return "", err
	}
	defer f.Close()
	hash := sha256.New()
	writer := io.MultiWriter(f, hash)
	if source != "" {
		err = copyLocal(ctx, source, writer)
	} else {
		name := Helper + "_" + m.Version + "_" + runtime.GOOS + "_" + runtime.GOARCH
		var sums strings.Builder
		err = m.download(ctx, releaseBase+m.Version+"/MICROSANDBOX_SHA256SUMS", &sums, 64<<10)
		if err == nil {
			var expected string
			expected, err = checksumFor(sums.String(), name)
			if err == nil {
				err = m.download(ctx, releaseBase+m.Version+"/"+name, writer, maxBinaryBytes)
				if err == nil && hex.EncodeToString(hash.Sum(nil)) != expected {
					err = errors.New("downloaded Microsandbox helper checksum mismatch")
				}
			}
		}
	}
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	finalDir := filepath.Join(dir, digest)
	if err := rejectSymlink(finalDir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(finalDir, 0700); err != nil {
		return "", err
	}
	// Content-addressed binaries keep active sessions valid while setup switches
	// the receipt atomically to a newly installed development build.
	if err := os.Rename(filepath.Join(stage, Helper), filepath.Join(finalDir, Helper)); err != nil {
		return "", err
	}
	data, _ := json.Marshal(receipt{SHA256: digest})
	receiptPath := filepath.Join(stage, "current.json")
	if err := os.WriteFile(receiptPath, data, 0600); err != nil {
		return "", err
	}
	if err := os.Rename(receiptPath, filepath.Join(dir, "current.json")); err != nil {
		return "", err
	}
	return m.Resolve()
}

func supportedPlatform() error {
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" || runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64") {
		return nil
	}
	return fmt.Errorf("Microsandbox helper is unavailable for %s/%s; use Apple Silicon macOS or amd64/arm64 Linux", runtime.GOOS, runtime.GOARCH)
}

func rejectSymlink(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("Microsandbox installation must not contain symlinks")
	}
	return nil
}

func copyLocal(ctx context.Context, source string, dst io.Writer) error {
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&0111 == 0 || info.Size() == 0 || info.Size() > maxBinaryBytes {
		return errors.New("--helper must name a nonempty executable file no larger than 128 MiB")
	}
	f, err := os.Open(source)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&0111 == 0 || info.Size() == 0 || info.Size() > maxBinaryBytes {
		return errors.New("--helper must name a nonempty executable file no larger than 128 MiB")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	size, err := io.Copy(dst, io.LimitReader(f, maxBinaryBytes+1))
	if err == nil && (size == 0 || size > maxBinaryBytes) {
		return errors.New("invalid local Microsandbox helper size")
	}
	return err
}

func (m Manager) download(ctx context.Context, url string, dst io.Writer, limit int64) error {
	client := &http.Client{Timeout: 5 * time.Minute}
	if m.HTTP != nil {
		*client = *m.HTTP
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" || len(via) >= 10 {
			return errors.New("unsafe Microsandbox release redirect")
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download Microsandbox helper: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Microsandbox release %s returned HTTP %d; update EnvVault if this release has no helper assets", m.Version, resp.StatusCode)
	}
	size, err := io.Copy(dst, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if size == 0 || size > limit {
		return errors.New("invalid Microsandbox release download size")
	}
	return nil
}

func checksumFor(sums, name string) (string, error) {
	var found string
	for _, line := range strings.Split(sums, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[1] != name {
			continue
		}
		if found != "" || !checksumPattern.MatchString(fields[0]) {
			return "", errors.New("invalid Microsandbox release checksums")
		}
		found = fields[0]
	}
	if found == "" {
		return "", errors.New("Microsandbox release checksum is missing for this platform")
	}
	return found, nil
}
