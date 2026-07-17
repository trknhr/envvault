package acceptance_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/cli"
	"github.com/trknhr/envvault/internal/config"
	"github.com/trknhr/envvault/internal/issuer"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/process"
	"github.com/trknhr/envvault/internal/profile"
)

func TestExecResolvesCredentialReferenceAndDoesNotPassParentAuthority(t *testing.T) {
	repoRoot := findRepoRoot(t)
	inspectChild := buildFixture(t, repoRoot, "inspect-child")
	projectRoot := t.TempDir()
	envFile := filepath.Join(projectRoot, ".env")
	originalEnv := "TOKEN=envvault://backend-a/dev\nPLAIN=file-value\n"
	if err := os.WriteFile(envFile, []byte(originalEnv), 0o600); err != nil {
		t.Fatalf("WriteFile(.env) error = %v", err)
	}

	app := newCredentialExecApp(t, projectRoot, map[string]string{"backend-a/dev": "stored-backend-token"})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"exec",
		"--env-file", envFile,
		"--", inspectChild, "arg1",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	var child inspectSnapshot
	if err := json.Unmarshal(stdout.Bytes(), &child); err != nil {
		t.Fatalf("Unmarshal(inspect-child) error = %v; stdout=%q", err, stdout.String())
	}
	if got := child.Env["TOKEN"]; got != "stored-backend-token" {
		t.Fatalf("child TOKEN = %q, want credential value", got)
	}
	if got := child.Env["PLAIN"]; got != "file-value" {
		t.Fatalf("child PLAIN = %q, want file value", got)
	}
	for _, key := range []string{
		"ENVVAULT_TALOS_HMAC_SECRET",
		"ENVVAULT_TALOS_SIGNING_KEY",
		"ENVVAULT_PROFILE_PARENT_KEY",
	} {
		if _, ok := child.Env[key]; ok {
			t.Fatalf("child environment leaked %s", key)
		}
	}
	if strings.Contains(stdout.String(), "raw-parent-secret") || strings.Contains(stderr.String(), "raw-parent-secret") {
		t.Fatalf("raw parent secret leaked; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	assertFileContent(t, envFile, originalEnv)
}

func TestExecUnknownCredentialFailsClosedWithoutParentFallback(t *testing.T) {
	projectRoot := t.TempDir()
	envFile := filepath.Join(projectRoot, ".env")
	if err := os.WriteFile(envFile, []byte("TOKEN=envvault://unknown/dev\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(.env) error = %v", err)
	}

	app := newCredentialExecApp(t, projectRoot, nil)
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"exec",
		"--env-file", envFile,
		"--", buildFixture(t, findRepoRoot(t), "inspect-child"),
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), string(clerr.KeyringUnavailable)) {
		t.Fatalf("stderr = %q, want keyring failure", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want child not started", stdout.String())
	}
	if strings.Contains(stderr.String(), "raw-parent-secret") {
		t.Fatalf("stderr leaked parent fallback secret: %q", stderr.String())
	}
}

func TestExecRejectsQueryReferenceBeforeStartingChild(t *testing.T) {
	projectRoot := t.TempDir()
	envFile := filepath.Join(projectRoot, ".env")
	if err := os.WriteFile(envFile, []byte("TOKEN=envvault://backend-a/dev?scope=admin&ttl=24h\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(.env) error = %v", err)
	}

	app := newCredentialExecApp(t, projectRoot, map[string]string{"backend-a/dev": "stored-backend-token"})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"exec",
		"--env-file", envFile,
		"--", buildFixture(t, findRepoRoot(t), "inspect-child"),
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), string(clerr.ReferenceInvalid)) {
		t.Fatalf("stderr = %q, want reference invalid", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want child not started", stdout.String())
	}
	if strings.Contains(stderr.String(), "scope=admin") || strings.Contains(stderr.String(), "ttl=24h") {
		t.Fatalf("stderr leaked rejected reference details: %q", stderr.String())
	}
}

func TestExecPropagatesChildExitCode(t *testing.T) {
	repoRoot := findRepoRoot(t)
	exitCode := buildFixture(t, repoRoot, "exit-code")
	projectRoot := t.TempDir()
	app := newCredentialExecApp(t, projectRoot, nil)
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"exec",
		"--", exitCode, "--code", "42",
	}, &stdout, &stderr)

	if code != 42 {
		t.Fatalf("Run() code = %d, want child exit code 42; stderr=%q", code, stderr.String())
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q, want both empty", stdout.String(), stderr.String())
	}
}

func TestExecResolvesProjectJSONTemplatesWithoutLeakingSecrets(t *testing.T) {
	repoRoot := findRepoRoot(t)
	inspectHome := buildFixture(t, repoRoot, "inspect-home")
	projectRoot := t.TempDir()
	realHome := filepath.Join(t.TempDir(), "real-home")
	templateDirectory := filepath.Join(projectRoot, "config")
	for _, directory := range []string{realHome, templateDirectory} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatalf("MkdirAll(%s) error = %v", directory, err)
		}
	}
	const secret = "home-secret-canary"
	const nestedSecret = "nested-secret-canary\n"
	templates := map[string][]byte{
		"config/hogehoge.json": []byte(`{"endpoint":"https://api.example.test","token":"envvault://hogehoge/auth"}`),
		"config/session.json":  []byte(`{"enabled":true,"session":"envvault://hogehoge/session"}`),
	}
	for source, body := range templates {
		if err := os.WriteFile(filepath.Join(projectRoot, filepath.FromSlash(source)), body, 0o600); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", source, err)
		}
	}
	app := newCredentialExecApp(t, projectRoot, map[string]string{
		"hogehoge/auth":    secret,
		"hogehoge/session": nestedSecret,
	}, "HOME="+realHome)
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"exec",
		"--home-file", ".hogehoge=config/hogehoge.json",
		"--home-file", ".config/hogehoge/session.json=config/session.json",
		"--", inspectHome, ".hogehoge", ".config/hogehoge/session.json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	var child homeSnapshot
	if err := json.Unmarshal(stdout.Bytes(), &child); err != nil {
		t.Fatalf("Unmarshal(inspect-home) error = %v; stdout=%q", err, stdout.String())
	}
	primaryOutput, err := json.MarshalIndent(map[string]any{
		"endpoint": "https://api.example.test",
		"token":    secret,
	}, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent(primary output) error = %v", err)
	}
	primaryOutput = append(primaryOutput, '\n')
	digest := sha256.Sum256(primaryOutput)
	if got := child.Files[".hogehoge"].SHA256; got != hex.EncodeToString(digest[:]) {
		t.Fatalf("home file digest = %q", got)
	}
	nestedOutput, err := json.MarshalIndent(map[string]any{
		"enabled": true,
		"session": nestedSecret,
	}, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent(nested output) error = %v", err)
	}
	nestedOutput = append(nestedOutput, '\n')
	nestedDigest := sha256.Sum256(nestedOutput)
	if got := child.Files[".config/hogehoge/session.json"].SHA256; got != hex.EncodeToString(nestedDigest[:]) {
		t.Fatalf("nested home file digest = %q", got)
	}
	if child.Home == "" || child.Home == realHome {
		t.Fatalf("child HOME = %q, want isolated home", child.Home)
	}
	if _, err := os.Stat(child.Home); !os.IsNotExist(err) {
		t.Fatalf("isolated home still exists: %v", err)
	}
	for source, want := range templates {
		after, err := os.ReadFile(filepath.Join(projectRoot, filepath.FromSlash(source)))
		if err != nil {
			t.Fatalf("ReadFile(source %s) error = %v", source, err)
		}
		if !bytes.Equal(after, want) {
			t.Fatalf("source template %s changed: %q", source, after)
		}
		if bytes.Contains(after, []byte("secret-canary")) {
			t.Fatalf("source template %s contains resolved secret", source)
		}
	}
	for _, destination := range []string{".hogehoge", ".config/hogehoge/session.json"} {
		if _, err := os.Stat(filepath.Join(realHome, filepath.FromSlash(destination))); !os.IsNotExist(err) {
			t.Fatalf("real home destination %s was modified: %v", destination, err)
		}
	}
	output := stdout.String() + stderr.String()
	if strings.Contains(output, "home-secret-canary") || strings.Contains(output, "nested-secret-canary") {
		t.Fatalf("output leaked home file secret; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

type inspectSnapshot struct {
	Env       map[string]string            `json:"env"`
	StartedAt string                       `json:"started_at"`
	Ports     map[string]inspectPortStatus `json:"ports"`
}

type inspectPortStatus struct {
	Reachable bool   `json:"reachable"`
	Error     string `json:"error,omitempty"`
}

type homeSnapshot struct {
	Home  string                    `json:"home"`
	Files map[string]homeFileStatus `json:"files"`
}

type homeFileStatus struct {
	SHA256 string      `json:"sha256"`
	Mode   os.FileMode `json:"mode"`
	Size   int64       `json:"size"`
}

type fakeProfileResolver map[string]profile.Profile

func (r fakeProfileResolver) Profile(name string) (profile.Profile, error) {
	p, ok := r[name]
	if !ok {
		return profile.Profile{}, clerr.New(clerr.ProfileNotFound, name)
	}
	return p, nil
}

type fakeIssuer struct {
	token  string
	grants []issuer.Grant
}

func (f *fakeIssuer) Issue(_ context.Context, grant issuer.Grant) (issuer.Credential, error) {
	f.grants = append(f.grants, grant)
	return issuer.Credential{
		AccessToken: f.token,
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(grant.TTL),
		Scopes:      append([]string(nil), grant.Scopes...),
	}, nil
}

func newCredentialExecApp(t *testing.T, projectRoot string, credentials map[string]string, extraParentEnv ...string) cli.App {
	t.Helper()
	secrets := keyring.NewMemoryStore()
	for name, value := range credentials {
		if err := secrets.Put(context.Background(), keyring.CredentialValue(name), []byte(value)); err != nil {
			t.Fatalf("Put(%q) error = %v", name, err)
		}
	}
	parent := credentialExecParentEnv()
	parent = append(parent, extraParentEnv...)
	return cli.New(cli.Options{
		Paths: config.Paths{
			CacheDir: filepath.Join(projectRoot, ".envvault-cache"),
		},
		ParentEnv:       parent,
		ProjectStartDir: projectRoot,
		Secrets:         secrets,
		Runner:          process.Runner{},
	})
}

func newExecApp(projectRoot string, profiles fakeProfileResolver, tokenIssuer issuer.Issuer) cli.App {
	return newExecAppWithParentEnv(projectRoot, profiles, tokenIssuer)
}

func newExecAppWithParentEnv(projectRoot string, profiles fakeProfileResolver, tokenIssuer issuer.Issuer, extraParentEnv ...string) cli.App {
	parent := append([]string{}, os.Environ()...)
	parent = append(parent,
		"TOKEN=raw-parent-secret",
		"ENVVAULT_TALOS_HMAC_SECRET=hmac-secret-canary",
		"ENVVAULT_TALOS_SIGNING_KEY=signing-secret-canary",
		"ENVVAULT_PROFILE_PARENT_KEY=parent-secret-canary",
	)
	parent = append(parent, extraParentEnv...)
	return cli.New(cli.Options{
		ParentEnv:       parent,
		ProjectStartDir: projectRoot,
		Profiles:        profiles,
		Issuer:          tokenIssuer,
		Runner:          process.Runner{},
	})
}

func fakeProfiles() fakeProfileResolver {
	return fakeProfileResolver{
		"backend-a/dev": {
			Name:        "backend-a/dev",
			Kind:        profile.KindProcess,
			Resource:    "https://api.dev.example.com",
			Scopes:      []string{"repository:read"},
			TokenTTL:    10 * time.Minute,
			MaxTokenTTL: 30 * time.Minute,
		},
	}
}

func buildFixture(t *testing.T, repoRoot, name string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), name)
	if strings.Contains(name, string(os.PathSeparator)) {
		t.Fatalf("fixture name must be a single path element: %q", name)
	}
	cmd := exec.Command("go", "build", "-o", out, filepath.Join(repoRoot, "test", "fixtures", name))
	cmd.Dir = repoRoot
	body, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build fixture %s: %v\n%s", name, err, body)
	}
	return out
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repository root with go.mod not found")
		}
		dir = parent
	}
}

func assertFileContent(t *testing.T, path string, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	if string(got) != want {
		t.Fatalf("%s = %q, want %q", path, got, want)
	}
}
