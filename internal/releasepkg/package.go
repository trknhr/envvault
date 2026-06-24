package releasepkg

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Platform struct {
	OS   string
	Arch string
}

type PackageOptions struct {
	RepoRoot   string
	DistDir    string
	Version    string
	Platform   Platform
	BinaryPath string
}

type Artifact struct {
	Name   string
	Path   string
	SHA256 string
}

var packageDocs = []string{
	"README.md",
	"docs/quickstart.md",
	"docs/threat-model.md",
	"docs/uninstall.md",
	"docs/recovery.md",
	"docs/third-party-notices.md",
}

func Package(options PackageOptions) (Artifact, error) {
	if strings.TrimSpace(options.RepoRoot) == "" {
		return Artifact{}, fmt.Errorf("repo root is required")
	}
	if strings.TrimSpace(options.DistDir) == "" {
		return Artifact{}, fmt.Errorf("dist directory is required")
	}
	if strings.TrimSpace(options.Version) == "" {
		return Artifact{}, fmt.Errorf("version is required")
	}
	if options.Platform.OS == "" || options.Platform.Arch == "" {
		return Artifact{}, fmt.Errorf("release platform is required")
	}
	if strings.TrimSpace(options.BinaryPath) == "" {
		return Artifact{}, fmt.Errorf("binary path is required")
	}
	if err := requireRegularFile(options.BinaryPath); err != nil {
		return Artifact{}, fmt.Errorf("inspect credlease binary: %w", err)
	}
	for _, rel := range packageDocs {
		if err := requireRegularFile(filepath.Join(options.RepoRoot, rel)); err != nil {
			return Artifact{}, fmt.Errorf("inspect package file %s: %w", rel, err)
		}
	}
	if err := os.MkdirAll(options.DistDir, 0o755); err != nil {
		return Artifact{}, fmt.Errorf("create dist directory: %w", err)
	}

	name := archiveName(options.Version, options.Platform)
	path := filepath.Join(options.DistDir, name)
	tmpPath := path + ".tmp"
	_ = os.Remove(tmpPath)
	if options.Platform.OS == "windows" {
		if err := writeZipPackage(tmpPath, options); err != nil {
			_ = os.Remove(tmpPath)
			return Artifact{}, err
		}
	} else {
		if err := writeTarGzPackage(tmpPath, options); err != nil {
			_ = os.Remove(tmpPath)
			return Artifact{}, err
		}
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return Artifact{}, fmt.Errorf("install release package: %w", err)
	}
	sum, err := fileSHA256(path)
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{Name: name, Path: path, SHA256: sum}, nil
}

func WriteChecksums(distDir string, artifacts []Artifact) error {
	return writeChecksums(distDir, artifacts)
}

func ReadChecksums(path string) ([]Artifact, error) {
	return readChecksums(path)
}

func UpdateChecksums(distDir string, artifacts []Artifact) error {
	existing, err := readChecksums(filepath.Join(distDir, "SHA256SUMS"))
	if err != nil {
		return err
	}
	byName := map[string]Artifact{}
	for _, artifact := range existing {
		byName[artifact.Name] = artifact
	}
	for _, artifact := range artifacts {
		byName[artifact.Name] = artifact
	}
	merged := make([]Artifact, 0, len(byName))
	for _, artifact := range byName {
		merged = append(merged, artifact)
	}
	return writeChecksums(distDir, merged)
}

func writeChecksums(distDir string, artifacts []Artifact) error {
	if strings.TrimSpace(distDir) == "" {
		return fmt.Errorf("dist directory is required")
	}
	if err := os.MkdirAll(distDir, 0o755); err != nil {
		return fmt.Errorf("create dist directory: %w", err)
	}
	artifacts = append([]Artifact(nil), artifacts...)
	sort.Slice(artifacts, func(i, j int) bool {
		return artifacts[i].Name < artifacts[j].Name
	})
	var builder strings.Builder
	for _, artifact := range artifacts {
		if artifact.Name == "" || artifact.SHA256 == "" {
			return fmt.Errorf("artifact name and sha256 are required")
		}
		builder.WriteString(artifact.SHA256)
		builder.WriteString("  ")
		builder.WriteString(artifact.Name)
		builder.WriteByte('\n')
	}
	path := filepath.Join(distDir, "SHA256SUMS")
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(builder.String()), 0o644); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write checksums: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("install checksums: %w", err)
	}
	return nil
}

func readChecksums(path string) ([]Artifact, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read checksums: %w", err)
	}
	lines := strings.Split(string(body), "\n")
	artifacts := make([]Artifact, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid checksum line")
		}
		artifacts = append(artifacts, Artifact{
			SHA256: parts[0],
			Name:   parts[1],
		})
	}
	return artifacts, nil
}

func archiveName(version string, platform Platform) string {
	base := packageRoot(version, platform)
	if platform.OS == "windows" {
		return base + ".zip"
	}
	return base + ".tar.gz"
}

func packageRoot(version string, platform Platform) string {
	return fmt.Sprintf("credlease_%s_%s_%s", version, platform.OS, platform.Arch)
}

func packageBinaryName(platform Platform) string {
	if platform.OS == "windows" {
		return "credlease.exe"
	}
	return "credlease"
}

func writeTarGzPackage(path string, options PackageOptions) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("create release package: %w", err)
	}
	defer file.Close()
	gzipWriter := gzip.NewWriter(file)
	defer gzipWriter.Close()
	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	root := packageRoot(options.Version, options.Platform)
	if err := addTarFile(tarWriter, options.BinaryPath, root+"/"+packageBinaryName(options.Platform), 0o755); err != nil {
		return err
	}
	for _, rel := range packageDocs {
		if err := addTarFile(tarWriter, filepath.Join(options.RepoRoot, rel), root+"/"+rel, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func addTarFile(writer *tar.Writer, srcPath, archivePath string, mode int64) error {
	info, err := os.Stat(srcPath)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", srcPath, err)
	}
	header := &tar.Header{
		Name:    filepath.ToSlash(archivePath),
		Mode:    mode,
		Size:    info.Size(),
		ModTime: info.ModTime(),
	}
	if err := writer.WriteHeader(header); err != nil {
		return fmt.Errorf("write tar header %s: %w", archivePath, err)
	}
	return copyFileBody(writer, srcPath)
}

func writeZipPackage(path string, options PackageOptions) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("create release package: %w", err)
	}
	defer file.Close()
	writer := zip.NewWriter(file)
	defer writer.Close()

	root := packageRoot(options.Version, options.Platform)
	if err := addZipFile(writer, options.BinaryPath, root+"/"+packageBinaryName(options.Platform), 0o755); err != nil {
		return err
	}
	for _, rel := range packageDocs {
		if err := addZipFile(writer, filepath.Join(options.RepoRoot, rel), root+"/"+rel, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func addZipFile(writer *zip.Writer, srcPath, archivePath string, mode os.FileMode) error {
	info, err := os.Stat(srcPath)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", srcPath, err)
	}
	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return fmt.Errorf("create zip header %s: %w", archivePath, err)
	}
	header.Name = filepath.ToSlash(archivePath)
	header.Method = zip.Deflate
	header.SetMode(mode)
	body, err := writer.CreateHeader(header)
	if err != nil {
		return fmt.Errorf("write zip header %s: %w", archivePath, err)
	}
	return copyFileBody(body, srcPath)
}

func copyFileBody(writer io.Writer, srcPath string) error {
	file, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", srcPath, err)
	}
	defer file.Close()
	if _, err := io.Copy(writer, file); err != nil {
		return fmt.Errorf("copy %s: %w", srcPath, err)
	}
	return nil
}

func requireRegularFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("path is a directory")
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open artifact for checksum: %w", err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash artifact: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
