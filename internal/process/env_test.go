package process_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/issuer"
	"github.com/trknhr/envvault/internal/issuer/local"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/process"
	"github.com/trknhr/envvault/internal/profile"
	"github.com/trknhr/envvault/internal/projectbinding"
)

func TestBuildEnvResolvesEnvFileReferenceWithoutParentFallback(t *testing.T) {
	envFile := writeEnvFile(t, "TOKEN=envvault://backend-a/dev\nPLAIN=file-value\n")
	issuer := &fakeIssuer{}

	env, err := process.BuildEnv(context.Background(), process.EnvInput{
		Parent:          []string{"TOKEN=raw-parent-secret", "PLAIN=parent-value", "HOME=/tmp/home"},
		EnvFiles:        []string{envFile},
		ProjectIdentity: testProjectIdentity(t),
	}, fakeProfiles(), issuer)
	if err != nil {
		t.Fatalf("BuildEnv() error = %v", err)
	}

	if got := env["TOKEN"]; got != "jwt-for-backend-a/dev" {
		t.Fatalf("TOKEN = %q, want issued JWT", got)
	}
	if got := env["PLAIN"]; got != "file-value" {
		t.Fatalf("PLAIN = %q, want file-value", got)
	}
	if got := env["HOME"]; got != "/tmp/home" {
		t.Fatalf("HOME = %q, want parent value", got)
	}
	if len(issuer.grants) != 1 {
		t.Fatalf("issued grants = %d, want 1", len(issuer.grants))
	}
	assertFileContent(t, envFile, "TOKEN=envvault://backend-a/dev\nPLAIN=file-value\n")
}

func TestBuildEnvInlineEnvOverridesEnvFileReference(t *testing.T) {
	envFile := writeEnvFile(t, "TOKEN=envvault://backend-a/dev\n")
	issuer := &fakeIssuer{}

	env, err := process.BuildEnv(context.Background(), process.EnvInput{
		Parent:    []string{"TOKEN=raw-parent-secret"},
		EnvFiles:  []string{envFile},
		InlineEnv: []string{"TOKEN=literal-inline"},
	}, fakeProfiles(), issuer)
	if err != nil {
		t.Fatalf("BuildEnv() error = %v", err)
	}

	if got := env["TOKEN"]; got != "literal-inline" {
		t.Fatalf("TOKEN = %q, want literal-inline", got)
	}
	if len(issuer.grants) != 0 {
		t.Fatalf("issued grants = %d, want 0", len(issuer.grants))
	}
}

func TestBuildEnvUnknownProfileFailsClosedWithoutParentFallback(t *testing.T) {
	envFile := writeEnvFile(t, "TOKEN=envvault://unknown/dev\n")
	issuer := &fakeIssuer{}

	_, err := process.BuildEnv(context.Background(), process.EnvInput{
		Parent:   []string{"TOKEN=raw-parent-secret"},
		EnvFiles: []string{envFile},
	}, fakeProfiles(), issuer)
	if err == nil {
		t.Fatal("BuildEnv() error = nil, want error")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.ProfileNotFound {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.ProfileNotFound)
	}
	if len(issuer.grants) != 0 {
		t.Fatalf("issued grants = %d, want 0", len(issuer.grants))
	}
}

func TestBuildEnvReusesTokenForSameProfileWithinExec(t *testing.T) {
	envFile := writeEnvFile(t, "TOKEN_A=envvault://backend-a/dev\nTOKEN_B=envvault://backend-a/dev\n")
	issuer := &fakeIssuer{}

	env, err := process.BuildEnv(context.Background(), process.EnvInput{
		EnvFiles:        []string{envFile},
		ProjectIdentity: testProjectIdentity(t),
	}, fakeProfiles(), issuer)
	if err != nil {
		t.Fatalf("BuildEnv() error = %v", err)
	}

	if env["TOKEN_A"] != "jwt-for-backend-a/dev" || env["TOKEN_B"] != "jwt-for-backend-a/dev" {
		t.Fatalf("tokens = %q/%q, want shared issued token", env["TOKEN_A"], env["TOKEN_B"])
	}
	if len(issuer.grants) != 1 {
		t.Fatalf("issued grants = %d, want 1", len(issuer.grants))
	}
}

func TestBuildEnvGrantIncludesEnvVaultClaims(t *testing.T) {
	envFile := writeEnvFile(t, "TOKEN=envvault://backend-a/dev\n")
	issuer := &fakeIssuer{}
	projectRoot := filepath.Join(t.TempDir(), "repo")
	wantProjectID, err := projectbinding.PathHash(projectRoot)
	if err != nil {
		t.Fatalf("PathHash() error = %v", err)
	}

	_, err = process.BuildEnv(context.Background(), process.EnvInput{
		EnvFiles:        []string{envFile},
		ProjectIdentity: projectbinding.Identity{Root: projectRoot},
	}, fakeProfiles(), issuer)
	if err != nil {
		t.Fatalf("BuildEnv() error = %v", err)
	}

	if len(issuer.grants) != 1 {
		t.Fatalf("issued grants = %d, want 1", len(issuer.grants))
	}
	claims := issuer.grants[0].Claims
	for key, want := range map[string]any{
		"envvault_profile":    "backend-a/dev",
		"envvault_resource":   "https://api.dev.example.com",
		"envvault_purpose":    "process",
		"envvault_project_id": wantProjectID,
		"environment":         "dev",
	} {
		if got := claims[key]; got != want {
			t.Fatalf("Claims[%s] = %#v, want %#v", key, got, want)
		}
	}
	if got := claims["envvault_project_id"].(string); got == "" || got == projectRoot {
		t.Fatalf("Claims[envvault_project_id] = %q, want non-empty hash without raw path", got)
	}
	if claims["envvault_session_id"] == "" {
		t.Fatal("Claims[envvault_session_id] is empty")
	}
}

func TestProcessClaimsKeepsEnvVaultBindingClaimsAuthoritative(t *testing.T) {
	projectRoot := filepath.Join(t.TempDir(), "repo")
	claims, err := process.ProcessClaims(profile.Profile{
		Name:     "backend-a/dev",
		Resource: "https://api.dev.example.com",
		Claims: map[string]string{
			"envvault_profile":  "other-profile",
			"envvault_resource": "https://evil.example.com",
			"envvault_purpose":  "admin",
			"environment":       "dev",
		},
	}, projectbinding.Identity{Root: projectRoot})
	if err != nil {
		t.Fatalf("ProcessClaims() error = %v", err)
	}

	for key, want := range map[string]any{
		"envvault_profile":  "backend-a/dev",
		"envvault_resource": "https://api.dev.example.com",
		"envvault_purpose":  "process",
		"environment":       "dev",
	} {
		if got := claims[key]; got != want {
			t.Fatalf("Claims[%s] = %#v, want %#v", key, got, want)
		}
	}
}

func TestBuildEnvRejectsMalformedInlineReference(t *testing.T) {
	_, err := process.BuildEnv(context.Background(), process.EnvInput{
		InlineEnv: []string{"TOKEN=envvault://backend-a/dev?ttl=24h"},
	}, fakeProfiles(), &fakeIssuer{})
	if err == nil {
		t.Fatal("BuildEnv() error = nil, want error")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.ReferenceInvalid {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.ReferenceInvalid)
	}
}

func TestBuildEnvRejectsUnapprovedProjectBindingBeforeIssuingToken(t *testing.T) {
	approvedRoot := filepath.Join(t.TempDir(), "repo")
	binding, err := projectbinding.Approve(profile.ProjectBindingPathHash, projectbinding.Identity{Root: approvedRoot})
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	profiles := fakeProfiles()
	p := profiles["backend-a/dev"]
	p.ProjectBinding = binding
	profiles["backend-a/dev"] = p
	issuer := &fakeIssuer{}

	_, err = process.BuildEnv(context.Background(), process.EnvInput{
		EnvFiles:        []string{writeEnvFile(t, "TOKEN=envvault://backend-a/dev\n")},
		ProjectIdentity: projectbinding.Identity{Root: filepath.Join(t.TempDir(), "repo")},
	}, profiles, issuer)
	if err == nil {
		t.Fatal("BuildEnv() error = nil, want project not trusted")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.ProjectNotTrusted {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.ProjectNotTrusted)
	}
	if len(issuer.grants) != 0 {
		t.Fatalf("issued grants = %d, want 0", len(issuer.grants))
	}
}

func TestBuildEnvWorksWithLocalIssuerAndDropsEnvVaultAuthorityEnv(t *testing.T) {
	ctx := context.Background()
	envFile := writeEnvFile(t, "TOKEN=envvault://backend-a/dev\n")
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(ctx, keyring.ProfileParentKey("backend-a/dev"), []byte("parent-secret")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	deriver := &fakeDeriver{}
	tokenIssuer := local.NewIssuer(fakeProfiles(), secrets, deriver)

	env, err := process.BuildEnv(ctx, process.EnvInput{
		Parent: []string{
			"ENVVAULT_TALOS_HMAC_SECRET=hmac-secret",
			"ENVVAULT_TALOS_SIGNING_KEY=signing-secret",
			"ENVVAULT_PROFILE_PARENT_KEY=parent-secret",
		},
		EnvFiles:        []string{envFile},
		ProjectIdentity: testProjectIdentity(t),
	}, fakeProfiles(), tokenIssuer)
	if err != nil {
		t.Fatalf("BuildEnv() error = %v", err)
	}

	if env["TOKEN"] != "leased-jwt" {
		t.Fatalf("TOKEN = %q, want leased-jwt", env["TOKEN"])
	}
	for _, key := range []string{
		"ENVVAULT_TALOS_HMAC_SECRET",
		"ENVVAULT_TALOS_SIGNING_KEY",
		"ENVVAULT_PROFILE_PARENT_KEY",
	} {
		if _, ok := env[key]; ok {
			t.Fatalf("%s leaked into child environment", key)
		}
	}
	if deriver.parentKey != "parent-secret" {
		t.Fatalf("deriver parent key = %q", deriver.parentKey)
	}
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
	grants []issuer.Grant
}

func (f *fakeIssuer) Issue(_ context.Context, grant issuer.Grant) (issuer.Credential, error) {
	f.grants = append(f.grants, grant)
	return issuer.Credential{
		AccessToken: "jwt-for-" + grant.Profile,
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(grant.TTL),
		Scopes:      append([]string(nil), grant.Scopes...),
	}, nil
}

type fakeDeriver struct {
	parentKey string
}

func (d *fakeDeriver) DeriveJWT(_ context.Context, parentKey string, grant issuer.Grant) (issuer.Credential, error) {
	d.parentKey = parentKey
	return issuer.Credential{
		AccessToken: "leased-jwt",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(grant.TTL),
		Scopes:      append([]string(nil), grant.Scopes...),
	}, nil
}

func fakeProfiles() fakeProfileResolver {
	return fakeProfileResolver{
		"backend-a/dev": {
			Name:        "backend-a/dev",
			Kind:        profile.KindProcess,
			Resource:    "https://api.dev.example.com",
			Scopes:      []string{"repository:read", "issue:read"},
			Claims:      map[string]string{"environment": "dev"},
			TokenTTL:    10 * time.Minute,
			MaxTokenTTL: 30 * time.Minute,
		},
	}
}

func writeEnvFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if got := string(raw); got != want {
		t.Fatalf("%s content = %q, want %q", path, got, want)
	}
}

func testProjectIdentity(t *testing.T) projectbinding.Identity {
	t.Helper()
	return projectbinding.Identity{Root: filepath.Join(t.TempDir(), "repo")}
}
