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
	if !strings.Contains(homebrewText, `desc "Lightweight local secret launcher for envvault references"`) {
		t.Fatalf("homebrew formula missing current description:\n%s", homebrewText)
	}
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
		"short-lived scoped credentials",
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
	if scoopManifest["description"] != "Lightweight local secret launcher for envvault references" {
		t.Fatalf("scoop description = %#v", scoopManifest["description"])
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

func TestReleaseDocsCoverCredentialAndProxyFlows(t *testing.T) {
	repoRoot := findRepoRoot(t)
	requiredDocs := map[string][]string{
		"docs/quickstart.md": {
			"# Quickstart",
			"Add a Credential",
			"envvault://openai/dev",
			"Advanced: API Proxy Mode",
			"envvault://openai/dev/base-url",
			"envvault://openai/dev/token",
			"npx skills add trknhr/envvault --skill envvault",
		},
		"docs/proxies.md": {
			"# Proxies",
			"proxy add",
			"project binding",
			"target_url",
			"allowed_paths",
			"OS credential store",
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
		"https://trknhr.github.io/envvault/",
		"[Quickstart](docs/quickstart.md)",
		"[Proxies](docs/proxies.md)",
		"[Threat model](docs/threat-model.md)",
	} {
		if !strings.Contains(string(readme), want) {
			t.Fatalf("README.md missing documentation link %q", want)
		}
	}
}

func TestSpecLayoutIncludesCurrentExamplesAndFakeKeyringFixture(t *testing.T) {
	repoRoot := findRepoRoot(t)
	requiredFiles := map[string][]string{
		"examples/env-app/README.md": {
			"# Env App Example",
			"envvault credential add database/dev",
			"envvault://database/dev",
		},
		"examples/env-app/app.sh": {
			"DATABASE_URL",
			"postgres://",
		},
		"examples/openai-proxy-app/README.md": {
			"# OpenAI-Compatible Proxy App Example",
			"envvault proxy add openai/dev",
			"mock-provider",
		},
		"examples/openai-proxy-app/app.sh": {
			"OPENAI_BASE_URL",
			"OPENAI_API_KEY",
			"/chat/completions",
		},
		"examples/openai-proxy-app/mock-provider.go": {
			"/v1/chat/completions",
			"missing provider bearer",
		},
		"examples/gemini-sdk-app/README.md": {
			"# Gemini SDK App Example",
			"envvault credential add gemini/dev",
			"@google/genai",
		},
		"examples/gemini-sdk-app/app.mjs": {
			"GoogleGenAI",
			"interactions.create",
			"GEMINI_API_KEY",
		},
		"examples/gemini-sdk-app/package.json": {
			"@google/genai",
			"start",
		},
		"examples/gemini-sdk-app/.env": {
			"GEMINI_API_KEY=envvault://gemini/dev",
			"GEMINI_MODEL",
		},
		"examples/gemini-ai-sdk-proxy-app/README.md": {
			"# Gemini AI SDK Proxy App Example",
			"envvault proxy add gemini-openai/dev",
			"@ai-sdk/openai-compatible",
		},
		"examples/gemini-ai-sdk-proxy-app/app.mjs": {
			"createOpenAICompatible",
			"generateText",
			"ENVVAULT_PROXY_URL",
			"ENVVAULT_PROXY_TOKEN",
		},
		"examples/gemini-ai-sdk-proxy-app/package.json": {
			"@ai-sdk/openai-compatible",
			"ai",
		},
		"examples/gemini-ai-sdk-proxy-app/.env": {
			"ENVVAULT_PROXY_URL=envvault://gemini-openai/dev/base-url",
			"ENVVAULT_PROXY_TOKEN=envvault://gemini-openai/dev/token",
		},
		"package.json": {
			"vitepress",
			"docs:dev",
			"docs:build",
		},
		"docs/.vitepress/config.mts": {
			"defineConfig",
			"EnvVault",
			"base: '/envvault/'",
			"sidebar",
			"outDir: '../site'",
		},
		"test/manual-e2e.md": {
			"# Manual E2E Playbook",
			"Direct Credential Flow",
			"API Proxy Flow",
			"envvault://openai/dev/base-url",
		},
		"skills/envvault/SKILL.md": {
			"name: envvault",
			"envvault exec --env-file .env -- <command>",
			"envvault://openai-proxy/dev/base-url",
			"envvault://database/dev",
			"stay within the admin, credential, proxy, exec",
		},
		".github/workflows/pages.yml": {
			"name: Deploy Docs",
			"pages: write",
			"npm run docs:build",
			"actions/deploy-pages",
		},
		".github/workflows/release.yml": {
			"name: Release",
			"tags:",
			"v*",
			"HOMEBREW_TAP_TOKEN",
			"trknhr/homebrew-tap",
			"envvault-release package",
			"github.com/trknhr/envvault/internal/cli.version",
			"github.com/trknhr/envvault/internal/cli.commit",
			"gh release create",
		},
		"docs/.vitepress/theme/custom.css": {
			"--vp-c-brand-1",
			"VPDoc",
			"VPHero",
		},
		"docs/index.md": {
			"# EnvVault",
			"Store once. Resolve at launch.",
			"Admin UI",
			"Direct credential",
			"npx skills add trknhr/envvault --skill envvault",
			"Credential Flows",
			"Advanced API Proxy",
		},
		"docs/examples.md": {
			"# Examples",
			"Direct Credential Examples",
			"Advanced Proxy Examples",
			"Gemini SDK app",
			"/examples/gemini-ai-sdk-proxy-app",
			"/examples/openai-proxy-app",
		},
		"docs/examples/gemini-ai-sdk-proxy-app.md": {
			"# Gemini AI SDK Proxy App Example",
			"@ai-sdk/openai-compatible",
			"envvault proxy add gemini-openai/dev",
			"prints this `.env` snippet",
			"ENVVAULT_PROXY_URL=envvault://gemini-openai/dev/base-url",
		},
		"docs/examples/openai-proxy-app.md": {
			"# OpenAI-Compatible Proxy App Example",
			"envvault proxy add openai/dev",
			"same generated references",
			"mock-provider",
			"OPENAI_BASE_URL=envvault://openai/dev/base-url",
		},
		"site/index.html": {
			"EnvVault",
			"VitePress",
			"Store once. Resolve at launch.",
			"Admin UI",
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
	removedFiles := []string{
		"docs/browser-session.md",
		"docs/remote-sts.md",
		"docs/implementation-spec.md",
		"docs/manual-e2e.md",
		"docs/profiles.md",
		"docs/release-gate.md",
		"docs/release.md",
		"docs/superpowers/plans/2026-06-22-core-foundation.md",
		"examples/backend-go/backend.go",
		"examples/inject-app/README.md",
		"examples/inject-app/app.sh",
		"examples/local-mvp-app/README.md",
	}
	for _, rel := range removedFiles {
		if _, err := os.Stat(filepath.Join(repoRoot, rel)); err == nil {
			t.Fatalf("removed file still exists: %s", rel)
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Stat(%s) error = %v", rel, err)
		}
	}
	siteIndex, err := os.ReadFile(filepath.Join(repoRoot, "site/index.html"))
	if err != nil {
		t.Fatalf("ReadFile(site/index.html) error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(repoRoot, "site", "superpowers")); err == nil {
		t.Fatalf("site includes internal superpowers docs")
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Stat(site/superpowers) error = %v", err)
	}
	for _, forbidden := range []string{
		"First-party process token",
		"BACKEND_A_TOKEN",
		"envvault-flow.svg",
		"https://github.com/trknhr/envvault/blob/feat/local-mvp/examples/",
		"href=\"../",
		"Local MVP docs",
		"quickstart-panel",
	} {
		if strings.Contains(string(siteIndex), forbidden) {
			t.Fatalf("site/index.html contains removed docs artifact %q", forbidden)
		}
	}
	siteExamples, err := os.ReadFile(filepath.Join(repoRoot, "site", "examples.html"))
	if err != nil {
		t.Fatalf("ReadFile(site/examples.html) error = %v", err)
	}
	for _, forbidden := range []string{
		"Third-party API proxy",
		"First-party backend flow",
	} {
		if strings.Contains(string(siteExamples), forbidden) {
			t.Fatalf("site/examples.html contains confusing example section %q", forbidden)
		}
	}

	readme, err := os.ReadFile(filepath.Join(repoRoot, "README.md"))
	if err != nil {
		t.Fatalf("ReadFile(README.md) error = %v", err)
	}
	for _, want := range []string{
		"[Documentation site](https://trknhr.github.io/envvault/)",
		"npx skills add trknhr/envvault --skill envvault",
		"npx skills add . --skill envvault",
		"[OpenAI-compatible proxy app example](examples/openai-proxy-app/README.md)",
		"[Gemini SDK app example](examples/gemini-sdk-app/README.md)",
		"[Gemini AI SDK proxy app example](examples/gemini-ai-sdk-proxy-app/README.md)",
		"[Env app example](examples/env-app/README.md)",
	} {
		if !strings.Contains(string(readme), want) {
			t.Fatalf("README.md missing example link %q", want)
		}
	}
}

func TestCIWorkflowRunsReleaseGateDocsAndSecretScan(t *testing.T) {
	repoRoot := findRepoRoot(t)
	workflowPath := filepath.Join(repoRoot, ".github", "workflows", "ci.yml")
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
		"actions/setup-node@v4",
		"npm ci",
		"npm run docs:build",
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
		root + "/site/index.html",
		root + "/site/logo.svg",
		root + "/site/quickstart.html",
		root + "/site/vp-icons.css",
	} {
		if _, ok := entries[want]; !ok {
			t.Fatalf("release package entries missing %q; entries=%v", want, entries)
		}
	}
	hasSiteAsset := false
	for entry := range entries {
		if strings.HasPrefix(entry, root+"/site/assets/") {
			hasSiteAsset = true
			break
		}
	}
	if !hasSiteAsset {
		t.Fatalf("release package entries missing VitePress site/assets entry; entries=%v", entries)
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
