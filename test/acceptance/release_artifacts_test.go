package acceptance_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	releasepkg "github.com/trknhr/envvault/internal/releasepkg"
	runtimetalos "github.com/trknhr/envvault/internal/runtime/talos"
	"gopkg.in/yaml.v3"
)

func TestReleaseIncludesThirdPartyLicenseNotices(t *testing.T) {
	repoRoot := findRepoRoot(t)
	noticesPath := filepath.Join(repoRoot, "docs", "third-party-notices.md")
	body, err := os.ReadFile(noticesPath)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", noticesPath, err)
	}
	notices := string(body)
	if !strings.Contains(notices, "# Third-Party Notices") {
		t.Fatalf("third-party notices file is missing the expected title")
	}
	if !strings.Contains(strings.ToLower(notices), "license") {
		t.Fatalf("third-party notices file does not mention licenses")
	}

	var missing []string
	for _, mod := range listGoModules(t, repoRoot) {
		if mod.Main {
			continue
		}
		moduleVersion := mod.Path + " " + mod.Version
		if !strings.Contains(notices, moduleVersion) {
			missing = append(missing, moduleVersion)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("third-party notices missing Go modules:\n%s", strings.Join(missing, "\n"))
	}
}

func TestReleasePinsTalosRuntimeManifest(t *testing.T) {
	manifest, err := runtimetalos.DefaultReleaseManifest()
	if err != nil {
		t.Fatalf("DefaultReleaseManifest() error = %v", err)
	}
	if manifest.Version == "" {
		t.Fatal("manifest version is empty")
	}
	if manifest.SourceURL != "https://github.com/ory/talos/releases/tag/"+manifest.Version {
		t.Fatalf("SourceURL = %q", manifest.SourceURL)
	}
	assertReleaseURL(t, manifest.Checksums.URL, manifest.Version)
	assertReleaseSHA256(t, manifest.Checksums.SHA256)

	requiredPlatforms := []runtimetalos.Platform{
		{OS: "darwin", Arch: "amd64"},
		{OS: "darwin", Arch: "arm64"},
		{OS: "linux", Arch: "amd64"},
		{OS: "linux", Arch: "arm64"},
		{OS: "windows", Arch: "amd64"},
	}
	for _, platform := range requiredPlatforms {
		artifact, ok := releaseArtifactFor(manifest, platform)
		if !ok {
			t.Fatalf("manifest missing artifact for %s/%s", platform.OS, platform.Arch)
		}
		assertReleaseURL(t, artifact.URL, manifest.Version)
		assertReleaseSHA256(t, artifact.SHA256)
	}
}

func TestReleasePackagesContainSingleBinaryDocsNoticesAndChecksums(t *testing.T) {
	repoRoot := findRepoRoot(t)
	distDir := t.TempDir()
	binaryDir := t.TempDir()
	unixBinary := filepath.Join(binaryDir, "envvault")
	if err := os.WriteFile(unixBinary, []byte("fake unix binary"), 0o755); err != nil {
		t.Fatalf("WriteFile(unix binary) error = %v", err)
	}
	windowsBinary := filepath.Join(binaryDir, "envvault.exe")
	if err := os.WriteFile(windowsBinary, []byte("fake windows binary"), 0o755); err != nil {
		t.Fatalf("WriteFile(windows binary) error = %v", err)
	}

	linuxArtifact, err := releasepkg.Package(releasepkg.PackageOptions{
		RepoRoot:   repoRoot,
		DistDir:    distDir,
		Version:    "v0.1.0",
		Platform:   releasepkg.Platform{OS: "linux", Arch: "amd64"},
		BinaryPath: unixBinary,
	})
	if err != nil {
		t.Fatalf("Package(linux) error = %v", err)
	}
	windowsArtifact, err := releasepkg.Package(releasepkg.PackageOptions{
		RepoRoot:   repoRoot,
		DistDir:    distDir,
		Version:    "v0.1.0",
		Platform:   releasepkg.Platform{OS: "windows", Arch: "amd64"},
		BinaryPath: windowsBinary,
	})
	if err != nil {
		t.Fatalf("Package(windows) error = %v", err)
	}
	if err := releasepkg.WriteChecksums(distDir, []releasepkg.Artifact{linuxArtifact, windowsArtifact}); err != nil {
		t.Fatalf("WriteChecksums() error = %v", err)
	}

	assertReleaseSHA256(t, linuxArtifact.SHA256)
	assertReleaseSHA256(t, windowsArtifact.SHA256)
	linuxEntries := readTarGzEntries(t, linuxArtifact.Path)
	assertReleasePackageEntries(t, linuxEntries, "envvault_v0.1.0_linux_amd64", "envvault")
	windowsEntries := readZipEntries(t, windowsArtifact.Path)
	assertReleasePackageEntries(t, windowsEntries, "envvault_v0.1.0_windows_amd64", "envvault.exe")

	checksums, err := os.ReadFile(filepath.Join(distDir, "SHA256SUMS"))
	if err != nil {
		t.Fatalf("ReadFile(SHA256SUMS) error = %v", err)
	}
	for _, artifact := range []releasepkg.Artifact{linuxArtifact, windowsArtifact} {
		line := artifact.SHA256 + "  " + artifact.Name
		if !strings.Contains(string(checksums), line) {
			t.Fatalf("SHA256SUMS = %q, want line %q", string(checksums), line)
		}
	}
}

func TestReleasePackageManagerManifestsReferenceArchivesAndChecksums(t *testing.T) {
	distDir := t.TempDir()
	baseURL := "https://github.com/trknhr/envvault/releases/download/v0.1.0"
	artifacts := []releasepkg.Artifact{
		{Name: "envvault_v0.1.0_darwin_amd64.tar.gz", SHA256: strings.Repeat("a", 64)},
		{Name: "envvault_v0.1.0_darwin_arm64.tar.gz", SHA256: strings.Repeat("b", 64)},
		{Name: "envvault_v0.1.0_linux_amd64.tar.gz", SHA256: strings.Repeat("c", 64)},
		{Name: "envvault_v0.1.0_linux_arm64.tar.gz", SHA256: strings.Repeat("d", 64)},
		{Name: "envvault_v0.1.0_windows_amd64.zip", SHA256: strings.Repeat("e", 64)},
	}

	paths, err := releasepkg.WritePackageManagerManifests(releasepkg.PackageManagerManifestOptions{
		DistDir:   distDir,
		Version:   "v0.1.0",
		BaseURL:   baseURL,
		Artifacts: artifacts,
	})
	if err != nil {
		t.Fatalf("WritePackageManagerManifests() error = %v", err)
	}

	homebrew, err := os.ReadFile(paths.HomebrewFormula)
	if err != nil {
		t.Fatalf("ReadFile(HomebrewFormula) error = %v", err)
	}
	homebrewText := string(homebrew)
	for _, artifact := range artifacts[:4] {
		assertReleaseSHA256(t, artifact.SHA256)
		url := baseURL + "/" + artifact.Name
		if !strings.Contains(homebrewText, `url "`+url+`"`) {
			t.Fatalf("homebrew formula missing archive URL %q:\n%s", url, homebrewText)
		}
		if !strings.Contains(homebrewText, `sha256 "`+artifact.SHA256+`"`) {
			t.Fatalf("homebrew formula missing checksum %q:\n%s", artifact.SHA256, homebrewText)
		}
	}
	for _, forbidden := range []string{
		"envvault_v0.1.0_windows_amd64.zip",
		"secret-canary",
		"Authorization: Bearer",
		"parent-secret",
	} {
		if strings.Contains(homebrewText, forbidden) {
			t.Fatalf("homebrew formula contains forbidden text %q:\n%s", forbidden, homebrewText)
		}
	}

	scoop, err := os.ReadFile(paths.ScoopManifest)
	if err != nil {
		t.Fatalf("ReadFile(ScoopManifest) error = %v", err)
	}
	var scoopManifest map[string]any
	if err := json.Unmarshal(scoop, &scoopManifest); err != nil {
		t.Fatalf("scoop manifest is invalid JSON: %v\n%s", err, scoop)
	}
	windowsArtifact := artifacts[4]
	assertReleaseSHA256(t, windowsArtifact.SHA256)
	if scoopManifest["version"] != "0.1.0" {
		t.Fatalf("scoop version = %#v, want 0.1.0", scoopManifest["version"])
	}
	architecture, ok := scoopManifest["architecture"].(map[string]any)
	if !ok {
		t.Fatalf("scoop architecture missing or wrong type: %#v", scoopManifest["architecture"])
	}
	amd64, ok := architecture["64bit"].(map[string]any)
	if !ok {
		t.Fatalf("scoop 64bit architecture missing or wrong type: %#v", architecture["64bit"])
	}
	if got, want := amd64["url"], baseURL+"/"+windowsArtifact.Name; got != want {
		t.Fatalf("scoop 64bit url = %#v, want %q", got, want)
	}
	if got, want := amd64["hash"], windowsArtifact.SHA256; got != want {
		t.Fatalf("scoop 64bit hash = %#v, want %q", got, want)
	}
	if strings.Contains(string(scoop), "secret-canary") || strings.Contains(string(scoop), "Authorization: Bearer") {
		t.Fatalf("scoop manifest contains forbidden secret marker:\n%s", scoop)
	}
}

func TestReleaseDocsCoverProfilesBrowserSessionAndRemoteSTS(t *testing.T) {
	repoRoot := findRepoRoot(t)
	requiredDocs := map[string][]string{
		"docs/profiles.md": {
			"# Profiles",
			"process",
			"browser-session",
			"project binding",
			"scope",
			"resource",
			"TTL",
			"OS credential store",
		},
		"docs/browser-session.md": {
			"# Browser Session Protocol",
			"exchange endpoint",
			"complete endpoint",
			"one-time code",
			"Authorization header",
			"Cache-Control: no-store",
			"SameSite",
		},
		"docs/remote-sts.md": {
			"# Remote STS",
			"Local MVP",
			"out of scope",
			"JWKS",
			"centralized STS",
			"future",
		},
		"docs/release-gate.md": {
			"# Release Gate",
			"AT-INIT-001",
			"AT-SEC-001",
			"AT-BROWSER-001",
			"AT-RESET-001",
			"go test -race ./...",
		},
	}
	for rel, wants := range requiredDocs {
		path := filepath.Join(repoRoot, rel)
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", rel, err)
		}
		text := string(body)
		for _, want := range wants {
			if !strings.Contains(text, want) {
				t.Fatalf("%s missing %q:\n%s", rel, want, text)
			}
		}
		for _, forbidden := range []string{"secret-canary", "parent-secret", "0123456789abcdef0123456789abcdef"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s contains forbidden secret marker %q", rel, forbidden)
			}
		}
	}

	readme, err := os.ReadFile(filepath.Join(repoRoot, "README.md"))
	if err != nil {
		t.Fatalf("ReadFile(README.md) error = %v", err)
	}
	for _, want := range []string{
		"[Profiles](docs/profiles.md)",
		"[Browser session protocol](docs/browser-session.md)",
		"[Release gate](docs/release-gate.md)",
		"[Remote STS notes](docs/remote-sts.md)",
	} {
		if !strings.Contains(string(readme), want) {
			t.Fatalf("README.md missing documentation link %q", want)
		}
	}
}

func TestSpecLayoutIncludesExamplesAndFakeKeyringFixture(t *testing.T) {
	repoRoot := findRepoRoot(t)
	requiredFiles := map[string][]string{
		"examples/backend-typescript/README.md": {
			"# TypeScript Backend Example",
			"Authorization",
			"envvault_resource",
			"browser session",
		},
		"examples/backend-typescript/server.mjs": {
			"/documents/read",
			"/auth/envvault/browser-sessions",
			"Cache-Control",
			"no-store",
		},
		"examples/browser-session-go/README.md": {
			"# Browser Session Go Example",
			"pkg/browsersession",
			"SQLite",
			"Authorization",
		},
		"examples/browser-session-go/cmd/server/main.go": {
			"browsersession.NewSQLiteStore",
			"/auth/envvault/browser-sessions",
			"/auth/envvault/complete",
		},
		"examples/codex/README.md": {
			"# Codex Example",
			"envvault exec",
			"envvault://backend-a/dev",
		},
		"examples/codex/.env.example": {
			"BACKEND_A_TOKEN=envvault://backend-a/dev",
		},
		"test/fake-keyring/store.go": {
			"package fakekeyring",
			"type Store",
			"keyring.Store",
		},
	}
	for rel, wants := range requiredFiles {
		body, err := os.ReadFile(filepath.Join(repoRoot, rel))
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", rel, err)
		}
		text := string(body)
		for _, want := range wants {
			if !strings.Contains(text, want) {
				t.Fatalf("%s missing %q:\n%s", rel, want, text)
			}
		}
		for _, forbidden := range []string{"secret-canary", "parent-secret", "Authorization: Bearer"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s contains forbidden marker %q", rel, forbidden)
			}
		}
	}

	readme, err := os.ReadFile(filepath.Join(repoRoot, "README.md"))
	if err != nil {
		t.Fatalf("ReadFile(README.md) error = %v", err)
	}
	for _, want := range []string{
		"[TypeScript backend example](examples/backend-typescript/README.md)",
		"[Browser session Go example](examples/browser-session-go/README.md)",
		"[Codex example](examples/codex/README.md)",
	} {
		if !strings.Contains(string(readme), want) {
			t.Fatalf("README.md missing example link %q", want)
		}
	}
}

func TestLocalMVPCIWorkflowRunsReleaseGateAndSecretScan(t *testing.T) {
	repoRoot := findRepoRoot(t)
	workflowPath := filepath.Join(repoRoot, ".github", "workflows", "local-mvp.yml")
	body, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", workflowPath, err)
	}
	var parsed map[string]any
	if err := yaml.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("workflow YAML is invalid: %v", err)
	}
	if parsed["jobs"] == nil {
		t.Fatalf("workflow has no jobs: %#v", parsed)
	}
	workflow := string(body)
	for _, want := range []string{
		"push:",
		"pull_request:",
		"workflow_dispatch:",
		"ubuntu-latest",
		"ubuntu-24.04",
		"macos-latest",
		"macos-14",
		"go test ./...",
		"go vet ./...",
		"go test -race ./...",
		"go test ./test/acceptance -run TestRelease -count=1",
		"go run ./cmd/envvault-ci secret-scan .",
	} {
		if !strings.Contains(workflow, want) {
			t.Fatalf("workflow missing %q:\n%s", want, workflow)
		}
	}
}

type goModule struct {
	Path    string
	Version string
	Main    bool
}

func listGoModules(t *testing.T, repoRoot string) []goModule {
	t.Helper()
	cmd := exec.Command("go", "list", "-m", "-json", "all")
	cmd.Dir = repoRoot
	body, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -m -json all error = %v\n%s", err, body)
	}

	dec := json.NewDecoder(bytes.NewReader(body))
	var modules []goModule
	for {
		var mod goModule
		err := dec.Decode(&mod)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("decode go module JSON error = %v", err)
		}
		modules = append(modules, mod)
	}
	return modules
}

func releaseArtifactFor(manifest runtimetalos.Manifest, platform runtimetalos.Platform) (runtimetalos.Artifact, bool) {
	for _, artifact := range manifest.Artifacts {
		if artifact.OS == platform.OS && artifact.Arch == platform.Arch {
			return artifact, true
		}
	}
	return runtimetalos.Artifact{}, false
}

func assertReleaseURL(t *testing.T, rawURL, version string) {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse URL %q: %v", rawURL, err)
	}
	if parsed.Scheme != "https" || parsed.Host != "github.com" {
		t.Fatalf("release URL = %q, want github.com HTTPS URL", rawURL)
	}
	if !strings.HasPrefix(parsed.Path, "/ory/talos/releases/download/"+version+"/") {
		t.Fatalf("release URL path = %q, want pinned Ory Talos release asset", parsed.Path)
	}
}

func assertReleaseSHA256(t *testing.T, value string) {
	t.Helper()
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(value) {
		t.Fatalf("SHA256 %q is not 64 lowercase hex characters", value)
	}
}

func readTarGzEntries(t *testing.T, path string) map[string]os.FileMode {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open(%s) error = %v", path, err)
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatalf("NewReader(%s) error = %v", path, err)
	}
	defer gzipReader.Close()
	reader := tar.NewReader(gzipReader)
	entries := map[string]os.FileMode{}
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("tar Next() error = %v", err)
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		entries[header.Name] = os.FileMode(header.Mode)
	}
	return entries
}

func readZipEntries(t *testing.T, path string) map[string]os.FileMode {
	t.Helper()
	reader, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("OpenReader(%s) error = %v", path, err)
	}
	defer reader.Close()
	entries := map[string]os.FileMode{}
	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		entries[file.Name] = file.FileInfo().Mode().Perm()
	}
	return entries
}

func assertReleasePackageEntries(t *testing.T, entries map[string]os.FileMode, root, binaryName string) {
	t.Helper()
	for _, want := range []string{
		root + "/" + binaryName,
		root + "/README.md",
		root + "/docs/quickstart.md",
		root + "/docs/threat-model.md",
		root + "/docs/uninstall.md",
		root + "/docs/recovery.md",
		root + "/docs/third-party-notices.md",
	} {
		if _, ok := entries[want]; !ok {
			t.Fatalf("release package entries missing %q; entries=%v", want, entries)
		}
	}
	if mode := entries[root+"/"+binaryName]; mode&0o111 == 0 {
		t.Fatalf("binary mode = %v, want executable bit", mode)
	}
	for entry := range entries {
		if strings.Contains(entry, "/internal/") || strings.Contains(entry, "/test/") || strings.HasSuffix(entry, ".env") {
			t.Fatalf("release package contains source or environment file: %q", entry)
		}
	}
}
