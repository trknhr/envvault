package admin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/admin"
	"github.com/trknhr/envvault/internal/config"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/profile"
)

func TestServerRequiresAdminTokenAndLocalHost(t *testing.T) {
	server := admin.Server{Token: "admin-token"}

	missingToken := httptest.NewRequest(http.MethodGet, "/api/profiles", nil)
	missingToken.Host = "127.0.0.1:32123"
	missingTokenRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(missingTokenRecorder, missingToken)
	if missingTokenRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("missing token status = %d, want %d", missingTokenRecorder.Code, http.StatusUnauthorized)
	}

	badHost := httptest.NewRequest(http.MethodGet, "/api/profiles", nil)
	badHost.Host = "evil.example"
	badHost.Header.Set("Authorization", "Bearer admin-token")
	badHostRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(badHostRecorder, badHost)
	if badHostRecorder.Code != http.StatusForbidden {
		t.Fatalf("bad host status = %d, want %d", badHostRecorder.Code, http.StatusForbidden)
	}

	badOrigin := httptest.NewRequest(http.MethodPost, "/api/credentials", strings.NewReader(`{"name":"x","value":"y"}`))
	badOrigin.Host = "localhost:32123"
	badOrigin.Header.Set("Authorization", "Bearer admin-token")
	badOrigin.Header.Set("Origin", "https://evil.example")
	badOriginRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(badOriginRecorder, badOrigin)
	if badOriginRecorder.Code != http.StatusForbidden {
		t.Fatalf("bad origin status = %d, want %d", badOriginRecorder.Code, http.StatusForbidden)
	}
}

func TestServerHealthRequiresAdminToken(t *testing.T) {
	server := admin.Server{Token: "admin-token"}

	missingToken := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	missingToken.Host = "127.0.0.1:32123"
	missingTokenRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(missingTokenRecorder, missingToken)
	if missingTokenRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("missing token status = %d, want %d", missingTokenRecorder.Code, http.StatusUnauthorized)
	}

	req := authorizedRequest(http.MethodGet, "/api/health", "")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("body = %q, want ok health", rec.Body.String())
	}
}

func TestServerIndexContainsAdminFormsAndBearerAPIClient(t *testing.T) {
	server := admin.Server{Token: "admin-token"}
	req := httptest.NewRequest(http.MethodGet, "/?token=admin-token", nil)
	req.Host = "localhost:32123"
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusOK, rec.Body.String())
	}
	for _, want := range []string{
		"id=\"credential-form\"",
		"id=\"credentials\"",
		"id=\"credential-options\"",
		"id=\"proxy-profile-form\"",
		"id=\"proxies\"",
		"id=\"proxy-env-snippet\"",
		"id=\"copy-proxy-snippet\"",
		"Copy ref",
		"Copy .env",
		"data-credential-ref",
		"data-dotenv",
		"copyButtonFeedback",
		"button.textContent = \"Copied\"",
		"window.setTimeout",
		"navigator.clipboard.writeText",
		"Authorization",
		"Bearer",
		"/api/credentials",
		"/api/proxies",
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("body missing %q: %s", want, rec.Body.String())
		}
	}
	for _, notWant := range []string{
		"id=\"inject-profile-form\"",
		"Add Inject Profile",
		"/api/inject-profiles",
		"/api/proxy-profiles",
		"id=\"profiles\"",
		"<h2>Profiles</h2>",
	} {
		if strings.Contains(rec.Body.String(), notWant) {
			t.Fatalf("body contains %q: %s", notWant, rec.Body.String())
		}
	}
}

func TestServerStoresCredentialWithoutReturningValue(t *testing.T) {
	ctx := context.Background()
	paths := testPaths(t)
	writeAdminConfig(t, paths)
	secrets := keyring.NewMemoryStore()
	server := admin.Server{ConfigPath: paths.ConfigFile, Secrets: secrets, Token: "admin-token"}

	req := authorizedRequest(http.MethodPost, "/api/credentials", `{"name":"openai-key/dev","value":"sk-secret"}`)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusCreated, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "sk-secret") {
		t.Fatalf("response leaked credential value: %q", rec.Body.String())
	}
	stored, err := secrets.Get(ctx, keyring.CredentialValue("openai-key/dev"))
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if string(stored) != "sk-secret" {
		t.Fatalf("stored credential = %q", stored)
	}
	cfg, err := config.Load(paths.ConfigFile)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if strings.Join(cfg.Credentials, ",") != "openai-key/dev" {
		t.Fatalf("Credentials = %#v", cfg.Credentials)
	}

	req = authorizedRequest(http.MethodGet, "/api/profiles", "")
	rec = httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusOK, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "sk-secret") {
		t.Fatalf("profiles response leaked credential value: %q", rec.Body.String())
	}
}

func TestServerListsCredentialNamesWithoutValues(t *testing.T) {
	paths := testPaths(t)
	writeAdminConfig(t, paths)
	cfg, err := config.Load(paths.ConfigFile)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	cfg.Credentials = []string{"z-dev", "openai-key/dev"}
	if err := config.Save(paths.ConfigFile, cfg); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	server := admin.Server{ConfigPath: paths.ConfigFile, Secrets: keyring.NewMemoryStore(), Token: "admin-token"}

	req := authorizedRequest(http.MethodGet, "/api/credentials", "")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"credentials":["openai-key/dev","z-dev"]`) {
		t.Fatalf("body = %q, want sorted credential names", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "sk-secret") {
		t.Fatalf("response leaked credential value: %q", rec.Body.String())
	}
}

func TestServerListsEmptyCredentialsWithoutConfig(t *testing.T) {
	paths := testPaths(t)
	server := admin.Server{ConfigPath: paths.ConfigFile, Secrets: keyring.NewMemoryStore(), Token: "admin-token"}

	req := authorizedRequest(http.MethodGet, "/api/credentials", "")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"credentials":[]`) {
		t.Fatalf("body = %q, want empty credential list", rec.Body.String())
	}
}

func TestServerListsEmptyProfilesWithoutConfig(t *testing.T) {
	paths := testPaths(t)
	server := admin.Server{ConfigPath: paths.ConfigFile, Secrets: keyring.NewMemoryStore(), Token: "admin-token"}

	req := authorizedRequest(http.MethodGet, "/api/profiles", "")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"profiles":[]`) {
		t.Fatalf("body = %q, want empty profile list", rec.Body.String())
	}
	if _, err := os.Stat(paths.ConfigFile); !os.IsNotExist(err) {
		t.Fatalf("config was written during profile list: %v", err)
	}
}

func TestServerListsProxiesWithDotenvSnippet(t *testing.T) {
	paths := testPaths(t)
	writeAdminConfig(t, paths)
	cfg, err := config.Load(paths.ConfigFile)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	cfg.Profiles["gemini-openai/dev"] = config.Profile{
		Kind:           profile.KindProviderProxy,
		CredentialName: "gemini-api-key",
		AuthMode:       "bearer",
		Provider:       "openai-compatible",
		TargetURL:      "https://generativelanguage.googleapis.com/v1beta/openai",
		AllowedPaths:   []string{"/chat/completions"},
		AllowedMethods: []string{http.MethodPost},
		LocalTokenTTL:  config.Duration(10 * time.Minute),
		ProjectBinding: config.ProjectBinding{Mode: profile.ProjectBindingNone},
	}
	cfg.Profiles["database/dev"] = config.Profile{
		Kind:           profile.KindInject,
		CredentialName: "database-url/dev",
		ProjectBinding: config.ProjectBinding{Mode: profile.ProjectBindingNone},
	}
	if err := config.Save(paths.ConfigFile, cfg); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	server := admin.Server{ConfigPath: paths.ConfigFile, Secrets: keyring.NewMemoryStore(), Token: "admin-token"}

	req := authorizedRequest(http.MethodGet, "/api/proxies", "")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusOK, rec.Body.String())
	}
	var response struct {
		Proxies []struct {
			Name   string `json:"name"`
			Kind   string `json:"kind"`
			Dotenv string `json:"dotenv"`
		} `json:"proxies"`
	}
	decodeJSON(t, rec.Body.String(), &response)
	byName := map[string]string{}
	for _, got := range response.Proxies {
		byName[got.Name] = got.Dotenv
	}
	wantSnippet := "ENVVAULT_PROXY_URL=envvault://gemini-openai/dev/base-url\nENVVAULT_PROXY_TOKEN=envvault://gemini-openai/dev/token\n"
	if byName["gemini-openai/dev"] != wantSnippet {
		t.Fatalf("proxy dotenv = %q, want %q; body=%q", byName["gemini-openai/dev"], wantSnippet, rec.Body.String())
	}
	if _, ok := byName["database/dev"]; ok {
		t.Fatalf("proxy list included non-proxy profile: %q", rec.Body.String())
	}
}

func TestServerAddsProxyProfileWithoutExistingConfig(t *testing.T) {
	paths := testPaths(t)
	server := admin.Server{ConfigPath: paths.ConfigFile, Secrets: keyring.NewMemoryStore(), Token: "admin-token"}

	req := authorizedRequest(http.MethodPost, "/api/proxies", `{
		"name":"openai/dev",
		"credential":"openai-key/dev",
		"provider":"generic",
		"target_url":"https://api.openai.com/v1",
		"allowed_paths":["/chat/completions"],
		"allowed_methods":["POST"],
		"project_binding":"none"
	}`)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("proxy status = %d, want %d; body=%q", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var response struct {
		Name   string `json:"name"`
		Dotenv string `json:"dotenv"`
	}
	decodeJSON(t, rec.Body.String(), &response)
	if response.Name != "openai/dev" {
		t.Fatalf("response name = %q, want openai/dev", response.Name)
	}
	wantSnippet := "ENVVAULT_PROXY_URL=envvault://openai/dev/base-url\nENVVAULT_PROXY_TOKEN=envvault://openai/dev/token\n"
	if response.Dotenv != wantSnippet {
		t.Fatalf("dotenv = %q, want %q", response.Dotenv, wantSnippet)
	}
	cfg, err := config.Load(paths.ConfigFile)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	got, err := cfg.Profile("openai/dev")
	if err != nil {
		t.Fatalf("Profile() error = %v", err)
	}
	if got.Kind != profile.KindProviderProxy || got.CredentialName != "openai-key/dev" {
		t.Fatalf("profile = %#v", got)
	}
}

func TestServerAddsInjectAndProxyProfiles(t *testing.T) {
	paths := testPaths(t)
	writeAdminConfig(t, paths)
	server := admin.Server{ConfigPath: paths.ConfigFile, Secrets: keyring.NewMemoryStore(), Token: "admin-token"}

	req := authorizedRequest(http.MethodPost, "/api/inject-profiles", `{"name":"database/dev","credential":"database-url/dev","project_binding":"none"}`)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("inject status = %d, want %d; body=%q", rec.Code, http.StatusCreated, rec.Body.String())
	}

	req = authorizedRequest(http.MethodPost, "/api/proxy-profiles", `{
		"name":"openai/dev",
		"credential":"openai-key/dev",
		"provider":"generic",
		"target_url":"https://api.openai.com/v1",
		"allowed_paths":["/chat/completions"],
		"allowed_methods":["POST"],
		"project_binding":"none"
	}`)
	rec = httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("proxy status = %d, want %d; body=%q", rec.Code, http.StatusCreated, rec.Body.String())
	}

	cfg, err := config.Load(paths.ConfigFile)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	injectProfile, err := cfg.Profile("database/dev")
	if err != nil {
		t.Fatalf("inject Profile() error = %v", err)
	}
	if injectProfile.Kind != profile.KindInject || injectProfile.CredentialName != "database-url/dev" {
		t.Fatalf("inject profile = %#v", injectProfile)
	}
	proxyProfile, err := cfg.Profile("openai/dev")
	if err != nil {
		t.Fatalf("proxy Profile() error = %v", err)
	}
	if proxyProfile.Kind != profile.KindProviderProxy || proxyProfile.CredentialName != "openai-key/dev" {
		t.Fatalf("proxy profile = %#v", proxyProfile)
	}
	if proxyProfile.LocalTokenTTL != 10*time.Minute {
		t.Fatalf("LocalTokenTTL = %s, want 10m", proxyProfile.LocalTokenTTL)
	}
}

func authorizedRequest(method, target, body string) *http.Request {
	var reader *bytes.Reader
	if body == "" {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader([]byte(body))
	}
	req := httptest.NewRequest(method, target, reader)
	req.Host = "localhost:32123"
	req.Header.Set("Authorization", "Bearer admin-token")
	return req
}

func testPaths(t *testing.T) config.Paths {
	t.Helper()
	root := t.TempDir()
	return config.Paths{
		ConfigDir:  filepath.Join(root, "config"),
		ConfigFile: filepath.Join(root, "config", "config.yaml"),
		DataDir:    filepath.Join(root, "data"),
		CacheDir:   filepath.Join(root, "cache"),
	}
}

func writeAdminConfig(t *testing.T, paths config.Paths) {
	t.Helper()
	cfg := config.File{
		Version: 1,
		Installation: config.Installation{
			ID: "01JADMINTEST",
		},
		Runtime: config.Runtime{
			Talos: config.TalosRuntime{
				Mode:      "managed",
				Version:   "test-talos",
				Lifecycle: "on-demand",
			},
		},
		Defaults: config.Defaults{
			TokenTTL:    config.Duration(10 * time.Minute),
			MaxTokenTTL: config.Duration(time.Hour),
		},
		Credentials: []string{},
		Profiles:    map[string]config.Profile{},
	}
	if err := os.MkdirAll(paths.ConfigDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := config.Save(paths.ConfigFile, cfg); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
}

func decodeJSON(t *testing.T, body string, out any) {
	t.Helper()
	if err := json.Unmarshal([]byte(body), out); err != nil {
		t.Fatalf("Unmarshal(%q) error = %v", body, err)
	}
}
