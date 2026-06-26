package talos

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/trknhr/envvault/internal/clerr"
)

type Manifest struct {
	Version   string         `json:"version" yaml:"version"`
	SourceURL string         `json:"source_url,omitempty" yaml:"source_url,omitempty"`
	Checksums ChecksumSource `json:"checksums,omitempty" yaml:"checksums,omitempty"`
	Artifacts []Artifact     `json:"artifacts" yaml:"artifacts"`
}

type ChecksumSource struct {
	URL    string `json:"url" yaml:"url"`
	SHA256 string `json:"sha256" yaml:"sha256"`
}

type Artifact struct {
	OS     string `json:"os" yaml:"os"`
	Arch   string `json:"arch" yaml:"arch"`
	URL    string `json:"url" yaml:"url"`
	SHA256 string `json:"sha256" yaml:"sha256"`
}

type Platform struct {
	OS   string
	Arch string
}

type InstalledArtifact struct {
	Version string
	Path    string
	SHA256  string
}

type CachedArtifactPaths struct {
	Binary  string
	Archive string
	SHA256  string
}

type archiveKind string

const (
	archiveNone  archiveKind = ""
	archiveTarGz archiveKind = "tar.gz"
	archiveZip   archiveKind = "zip"
)

//go:embed release_manifest.json
var defaultReleaseManifestJSON []byte

func DefaultReleaseManifest() (Manifest, error) {
	var manifest Manifest
	if err := json.Unmarshal(defaultReleaseManifestJSON, &manifest); err != nil {
		return Manifest{}, clerr.Wrap(clerr.RuntimeIncompatible, "parse talos release manifest", err)
	}
	if err := manifest.ValidateRelease(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func (m Manifest) ValidateRelease() error {
	if m.Version == "" {
		return clerr.New(clerr.RuntimeIncompatible, "talos manifest version is required")
	}
	if err := validateHTTPSURL(m.SourceURL, "talos release source url"); err != nil {
		return err
	}
	if err := validateHTTPSURL(m.Checksums.URL, "talos checksums url"); err != nil {
		return err
	}
	if err := validateSHA256(m.Checksums.SHA256, "talos checksums sha256"); err != nil {
		return err
	}
	if len(m.Artifacts) == 0 {
		return clerr.New(clerr.RuntimeIncompatible, "talos release manifest has no artifacts")
	}

	seen := map[Platform]struct{}{}
	for _, artifact := range m.Artifacts {
		platform := Platform{OS: artifact.OS, Arch: artifact.Arch}
		if platform.OS == "" || platform.Arch == "" {
			return clerr.New(clerr.RuntimeIncompatible, "talos artifact platform is required")
		}
		if _, exists := seen[platform]; exists {
			return clerr.New(clerr.RuntimeIncompatible, "talos release manifest has duplicate platform artifact")
		}
		seen[platform] = struct{}{}
		if err := validateHTTPSURL(artifact.URL, "talos artifact url"); err != nil {
			return err
		}
		if err := validateSHA256(artifact.SHA256, "talos artifact sha256"); err != nil {
			return err
		}
	}
	return nil
}

type Installer struct {
	http     *http.Client
	cacheDir string
}

func NewInstaller(httpClient *http.Client, cacheDir string) *Installer {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Installer{http: httpClient, cacheDir: cacheDir}
}

func (i *Installer) Install(ctx context.Context, manifest Manifest, platform Platform) (InstalledArtifact, error) {
	artifact, err := manifest.artifactFor(platform)
	if err != nil {
		return InstalledArtifact{}, err
	}
	if err := os.MkdirAll(i.cacheDir, 0o700); err != nil {
		return InstalledArtifact{}, clerr.Wrap(clerr.RuntimeUnavailable, "create talos cache directory", err)
	}

	binaryPath := filepath.Join(i.cacheDir, artifact.filename(manifest.Version))
	if artifact.archiveKind() == archiveNone {
		if ok, err := fileMatches(binaryPath, artifact.SHA256); err != nil {
			return InstalledArtifact{}, err
		} else if ok {
			return InstalledArtifact{Version: manifest.Version, Path: binaryPath, SHA256: artifact.SHA256}, nil
		}
		if err := i.downloadVerified(ctx, artifact.URL, binaryPath, artifact.SHA256, 0o755); err != nil {
			return InstalledArtifact{}, err
		}
		return InstalledArtifact{Version: manifest.Version, Path: binaryPath, SHA256: artifact.SHA256}, nil
	}

	archivePath := filepath.Join(i.cacheDir, artifact.archiveFilename(manifest.Version))
	if ok, err := fileMatches(archivePath, artifact.SHA256); err != nil {
		return InstalledArtifact{}, err
	} else if !ok {
		if err := i.downloadVerified(ctx, artifact.URL, archivePath, artifact.SHA256, 0o600); err != nil {
			return InstalledArtifact{}, err
		}
	}
	if err := i.extractArchiveBinary(archivePath, binaryPath, artifact); err != nil {
		return InstalledArtifact{}, err
	}
	return InstalledArtifact{Version: manifest.Version, Path: binaryPath, SHA256: artifact.SHA256}, nil
}

func (m Manifest) CachedArtifactPaths(cacheDir string, platform Platform) (CachedArtifactPaths, error) {
	artifact, err := m.artifactFor(platform)
	if err != nil {
		return CachedArtifactPaths{}, err
	}
	paths := CachedArtifactPaths{
		Binary: filepath.Join(cacheDir, artifact.filename(m.Version)),
		SHA256: artifact.SHA256,
	}
	if artifact.archiveKind() != archiveNone {
		paths.Archive = filepath.Join(cacheDir, artifact.archiveFilename(m.Version))
	}
	return paths, nil
}

func (i *Installer) downloadVerified(ctx context.Context, rawURL, targetPath, wantSHA256 string, mode os.FileMode) error {
	tmp, err := os.CreateTemp(i.cacheDir, ".talos-download-*")
	if err != nil {
		return clerr.Wrap(clerr.RuntimeUnavailable, "create temporary talos artifact", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if err := i.download(ctx, rawURL, tmp); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return clerr.Wrap(clerr.RuntimeUnavailable, "close talos artifact", err)
	}
	if ok, err := fileMatches(tmpName, wantSHA256); err != nil {
		return err
	} else if !ok {
		return clerr.New(clerr.RuntimeIncompatible, "talos artifact checksum mismatch")
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return clerr.Wrap(clerr.RuntimeUnavailable, "set talos artifact permissions", err)
	}
	_ = os.Remove(targetPath)
	if err := os.Rename(tmpName, targetPath); err != nil {
		return clerr.Wrap(clerr.RuntimeUnavailable, "install talos artifact", err)
	}
	if err := os.Chmod(targetPath, mode); err != nil {
		return clerr.Wrap(clerr.RuntimeUnavailable, "set final talos artifact permissions", err)
	}
	return nil
}

func (i *Installer) download(ctx context.Context, rawURL string, writer io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return clerr.Wrap(clerr.RuntimeUnavailable, "create talos download request", err)
	}
	resp, err := i.http.Do(req)
	if err != nil {
		return clerr.Wrap(clerr.RuntimeUnavailable, "download talos artifact", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return clerr.New(clerr.RuntimeUnavailable, fmt.Sprintf("talos download returned HTTP %d", resp.StatusCode))
	}
	if _, err := io.Copy(writer, resp.Body); err != nil {
		return clerr.Wrap(clerr.RuntimeUnavailable, "write talos artifact", err)
	}
	return nil
}

func (m Manifest) artifactFor(platform Platform) (Artifact, error) {
	if m.Version == "" {
		return Artifact{}, clerr.New(clerr.RuntimeIncompatible, "talos manifest version is required")
	}
	for _, artifact := range m.Artifacts {
		if artifact.OS == platform.OS && artifact.Arch == platform.Arch {
			if artifact.URL == "" || artifact.SHA256 == "" {
				return Artifact{}, clerr.New(clerr.RuntimeIncompatible, "talos artifact url and sha256 are required")
			}
			return artifact, nil
		}
	}
	return Artifact{}, clerr.New(clerr.RuntimeIncompatible, "no compatible talos artifact")
}

func (a Artifact) filename(version string) string {
	suffix := ""
	if a.OS == "windows" {
		suffix = ".exe"
	}
	return fmt.Sprintf("talos-%s-%s-%s%s", version, a.OS, a.Arch, suffix)
}

func (a Artifact) archiveFilename(version string) string {
	return fmt.Sprintf("talos-%s-%s-%s.%s", version, a.OS, a.Arch, a.archiveKind())
}

func (a Artifact) archiveKind() archiveKind {
	rawPath := a.URL
	if parsed, err := url.Parse(a.URL); err == nil {
		rawPath = parsed.Path
	}
	lower := strings.ToLower(rawPath)
	switch {
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		return archiveTarGz
	case strings.HasSuffix(lower, ".zip"):
		return archiveZip
	default:
		return archiveNone
	}
}

func (a Artifact) binaryName() string {
	if a.OS == "windows" {
		return "talos.exe"
	}
	return "talos"
}

func (i *Installer) extractArchiveBinary(archivePath, binaryPath string, artifact Artifact) error {
	tmp, err := os.CreateTemp(i.cacheDir, ".talos-extract-*")
	if err != nil {
		return clerr.Wrap(clerr.RuntimeUnavailable, "create temporary talos binary", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	switch artifact.archiveKind() {
	case archiveTarGz:
		err = extractTarGzBinary(archivePath, artifact.binaryName(), tmp)
	case archiveZip:
		err = extractZipBinary(archivePath, artifact.binaryName(), tmp)
	default:
		err = clerr.New(clerr.RuntimeIncompatible, "unsupported talos archive format")
	}
	if err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return clerr.Wrap(clerr.RuntimeUnavailable, "close temporary talos binary", err)
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return clerr.Wrap(clerr.RuntimeUnavailable, "set talos binary permissions", err)
	}
	_ = os.Remove(binaryPath)
	if err := os.Rename(tmpName, binaryPath); err != nil {
		return clerr.Wrap(clerr.RuntimeUnavailable, "install talos binary", err)
	}
	if err := os.Chmod(binaryPath, 0o755); err != nil {
		return clerr.Wrap(clerr.RuntimeUnavailable, "set final talos binary permissions", err)
	}
	return nil
}

func extractTarGzBinary(archivePath, binaryName string, writer io.Writer) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return clerr.Wrap(clerr.RuntimeUnavailable, "open talos archive", err)
	}
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return clerr.Wrap(clerr.RuntimeIncompatible, "read talos gzip archive", err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return clerr.Wrap(clerr.RuntimeIncompatible, "read talos tar archive", err)
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			continue
		}
		if archiveBase(header.Name) != binaryName {
			continue
		}
		if _, err := io.Copy(writer, tarReader); err != nil {
			return clerr.Wrap(clerr.RuntimeUnavailable, "extract talos binary", err)
		}
		return nil
	}
	return clerr.New(clerr.RuntimeIncompatible, "talos archive missing executable")
}

func extractZipBinary(archivePath, binaryName string, writer io.Writer) error {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return clerr.Wrap(clerr.RuntimeIncompatible, "read talos zip archive", err)
	}
	defer reader.Close()

	for _, file := range reader.File {
		if file.FileInfo().IsDir() || archiveBase(file.Name) != binaryName {
			continue
		}
		body, err := file.Open()
		if err != nil {
			return clerr.Wrap(clerr.RuntimeIncompatible, "open talos binary in zip archive", err)
		}
		_, copyErr := io.Copy(writer, body)
		closeErr := body.Close()
		if copyErr != nil {
			return clerr.Wrap(clerr.RuntimeUnavailable, "extract talos binary", copyErr)
		}
		if closeErr != nil {
			return clerr.Wrap(clerr.RuntimeUnavailable, "close talos binary in zip archive", closeErr)
		}
		return nil
	}
	return clerr.New(clerr.RuntimeIncompatible, "talos archive missing executable")
}

func archiveBase(name string) string {
	return path.Base(strings.ReplaceAll(name, "\\", "/"))
}

func fileMatches(path, want string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, clerr.Wrap(clerr.RuntimeUnavailable, "open talos artifact", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return false, clerr.Wrap(clerr.RuntimeUnavailable, "hash talos artifact", err)
	}
	got := hex.EncodeToString(hash.Sum(nil))
	return got == want, nil
}

func validateHTTPSURL(rawURL, label string) error {
	if rawURL == "" {
		return clerr.New(clerr.RuntimeIncompatible, label+" is required")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return clerr.New(clerr.RuntimeIncompatible, label+" must be an https URL")
	}
	return nil
}

func validateSHA256(value, label string) error {
	if len(value) != sha256.Size*2 {
		return clerr.New(clerr.RuntimeIncompatible, label+" must be 64 lowercase hex characters")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return clerr.New(clerr.RuntimeIncompatible, label+" must be 64 lowercase hex characters")
	}
	if hex.EncodeToString(decoded) != value {
		return clerr.New(clerr.RuntimeIncompatible, label+" must be lowercase")
	}
	return nil
}
