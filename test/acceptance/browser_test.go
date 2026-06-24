package acceptance_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	backendgo "github.com/trknhr/credlease/examples/backend-go"
	"github.com/trknhr/credlease/internal/browser"
	"github.com/trknhr/credlease/internal/cli"
	"github.com/trknhr/credlease/internal/issuer"
	"github.com/trknhr/credlease/internal/profile"
)

func TestOpenCreatesBrowserSessionThroughSampleBackend(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	key := newAcceptanceRSAKey(t)
	server, browserProfile, recorder := newAcceptanceBrowserBackend(t, key, now)
	fakeBrowser := buildFixture(t, findRepoRoot(t), "fake-browser")
	capturePath := filepath.Join(t.TempDir(), "fake-browser.jsonl")
	t.Setenv("CREDLEASE_FAKE_BROWSER_CAPTURE", capturePath)

	tokenIssuer := &signingAcceptanceIssuer{
		key:    key,
		issuer: "credlease-local:test-install",
		now:    now,
	}
	app := cli.New(cli.Options{
		ProjectStartDir: t.TempDir(),
		Profiles: fakeProfileResolver{
			browserProfile.Name: browserProfile,
		},
		Browser: browser.Client{
			HTTP:   server.Client(),
			Issuer: tokenIssuer,
			Opener: browser.CommandOpener{},
		},
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"open", browserProfile.Name,
		"--browser", fakeBrowser,
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want no launch URL without --print-url", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	if len(tokenIssuer.grants) != 1 {
		t.Fatalf("issuer grants = %d, want 1", len(tokenIssuer.grants))
	}
	grant := tokenIssuer.grants[0]
	if grant.Claims["credlease_purpose"] != "browser-bootstrap" {
		t.Fatalf("grant purpose = %#v, want browser-bootstrap", grant.Claims["credlease_purpose"])
	}
	sessionID, _ := grant.Claims["credlease_session_id"].(string)
	if sessionID == "" {
		t.Fatalf("grant claims missing session id: %#v", grant.Claims)
	}

	exchanges := recorder.exchanges
	if len(exchanges) != 1 {
		t.Fatalf("exchange requests = %d, want 1", len(exchanges))
	}
	if exchanges[0].Authorization != "Bearer "+tokenIssuer.token {
		t.Fatalf("exchange Authorization = %q, want issued bearer token", exchanges[0].Authorization)
	}
	if exchanges[0].CacheControl != "no-store" {
		t.Fatalf("exchange Cache-Control = %q, want no-store", exchanges[0].CacheControl)
	}
	if strings.Contains(exchanges[0].URL, tokenIssuer.token) {
		t.Fatalf("exchange URL leaked bootstrap JWT: %q", exchanges[0].URL)
	}

	records := readFakeBrowserLaunches(t, capturePath)
	if len(records) != 1 {
		t.Fatalf("fake browser launches = %d, want 1", len(records))
	}
	launchURL := records[0].URL
	if !strings.Contains(launchURL, "code=opaque-code") {
		t.Fatalf("launch URL = %q, want one-time code", launchURL)
	}
	if strings.Contains(launchURL, tokenIssuer.token) {
		t.Fatalf("launch URL leaked bootstrap JWT: %q", launchURL)
	}

	first := completeWithoutRedirect(t, withRedirectAttempt(t, launchURL))
	defer first.Body.Close()
	if first.StatusCode != http.StatusSeeOther {
		t.Fatalf("complete status = %d, want 303", first.StatusCode)
	}
	if first.Header.Get("Location") != browserProfile.PostLoginURL {
		t.Fatalf("complete Location = %q, want %q", first.Header.Get("Location"), browserProfile.PostLoginURL)
	}
	if location := first.Header.Get("Location"); strings.Contains(location, "code=") || strings.Contains(location, "evil.example") {
		t.Fatalf("complete Location leaked code or accepted redirect: %q", location)
	}
	if first.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("complete Cache-Control = %q, want no-store", first.Header.Get("Cache-Control"))
	}
	if first.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("complete Referrer-Policy = %q, want no-referrer", first.Header.Get("Referrer-Policy"))
	}
	cookies := first.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("complete cookies = %d, want 1", len(cookies))
	}
	if !cookies[0].HttpOnly {
		t.Fatal("session cookie HttpOnly = false, want true")
	}
	if cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie SameSite = %v, want Lax", cookies[0].SameSite)
	}

	second := completeWithoutRedirect(t, launchURL)
	defer second.Body.Close()
	if second.StatusCode != http.StatusGone {
		t.Fatalf("reused code status = %d, want 410", second.StatusCode)
	}
	reusedBody, err := io.ReadAll(second.Body)
	if err != nil {
		t.Fatalf("ReadAll(reused body) error = %v", err)
	}
	if strings.Contains(string(reusedBody), "opaque-code") || strings.Contains(string(reusedBody), sessionID) {
		t.Fatalf("reused code error leaked code/session: %q", string(reusedBody))
	}
	if strings.Contains(stdout.String()+stderr.String(), tokenIssuer.token) || strings.Contains(stdout.String()+stderr.String(), "opaque-code") {
		t.Fatalf("CLI output leaked browser secret; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestATBROWSER004ExpiredLoginCodeDoesNotCreateSessionThroughSampleBackend(t *testing.T) {
	start := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	current := start
	key := newAcceptanceRSAKey(t)
	server, browserProfile, _ := newAcceptanceBrowserBackendWithConfig(t, key, acceptanceBrowserBackendConfig{
		Now:          func() time.Time { return current },
		LoginCodeTTL: 2 * time.Second,
		CodeGenerator: func() (string, error) {
			return "expiring-code", nil
		},
	})

	tokenIssuer := &signingAcceptanceIssuer{
		key:    key,
		issuer: "credlease-local:test-install",
		now:    start,
	}
	app := cli.New(cli.Options{
		ProjectStartDir: t.TempDir(),
		Profiles: fakeProfileResolver{
			browserProfile.Name: browserProfile,
		},
		Browser: browser.Client{
			HTTP:   server.Client(),
			Issuer: tokenIssuer,
		},
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"open", browserProfile.Name,
		"--print-url",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	launchURL := strings.TrimSpace(stdout.String())
	if !strings.Contains(launchURL, "code=expiring-code") {
		t.Fatalf("launch URL = %q, want expiring login code", launchURL)
	}
	if strings.Contains(launchURL, tokenIssuer.token) {
		t.Fatalf("launch URL leaked bootstrap JWT: %q", launchURL)
	}

	current = start.Add(3 * time.Second)
	expired := completeWithoutRedirect(t, launchURL)
	if expired.StatusCode != http.StatusGone {
		t.Fatalf("expired code status = %d, want 410; body=%s", expired.StatusCode, responseBody(t, expired))
	}
	if cookies := expired.Cookies(); len(cookies) != 0 {
		t.Fatalf("expired code set %d cookies, want none", len(cookies))
	}
	if location := expired.Header.Get("Location"); location != "" {
		t.Fatalf("expired code Location = %q, want none", location)
	}
	body := responseBody(t, expired)
	sessionID, _ := tokenIssuer.grants[0].Claims["credlease_session_id"].(string)
	if strings.Contains(body, "expiring-code") || strings.Contains(body, sessionID) || strings.Contains(body, tokenIssuer.token) {
		t.Fatalf("expired code error leaked browser secret: %q", body)
	}
}

func TestATBROWSER005BootstrapJWTReplayRejectedThroughSampleBackend(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	key := newAcceptanceRSAKey(t)
	generatedCodes := 0
	server, browserProfile, _ := newAcceptanceBrowserBackendWithConfig(t, key, acceptanceBrowserBackendConfig{
		Now:          func() time.Time { return now },
		LoginCodeTTL: 30 * time.Second,
		CodeGenerator: func() (string, error) {
			generatedCodes++
			return fmt.Sprintf("replay-code-%d", generatedCodes), nil
		},
	})
	token := acceptanceBrowserBootstrapJWT(t, key, now, browserProfile.Resource, "session-replay-1", time.Minute)

	first := exchangeBrowserSession(t, server, token)
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("first exchange status = %d, want 201; body=%s", first.StatusCode, responseBody(t, first))
	}
	if first.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("first Cache-Control = %q, want no-store", first.Header.Get("Cache-Control"))
	}
	firstBody := responseBody(t, first)
	var firstParsed struct {
		LaunchURL string `json:"launch_url"`
	}
	if err := json.Unmarshal([]byte(firstBody), &firstParsed); err != nil {
		t.Fatalf("Unmarshal(first exchange body) error = %v; body=%q", err, firstBody)
	}
	if !strings.Contains(firstParsed.LaunchURL, "code=replay-code-1") {
		t.Fatalf("first launch URL = %q, want first replay code", firstParsed.LaunchURL)
	}
	if strings.Contains(firstParsed.LaunchURL, token) || strings.Contains(firstParsed.LaunchURL, "session-replay-1") {
		t.Fatalf("first launch URL leaked bootstrap secret: %q", firstParsed.LaunchURL)
	}

	second := exchangeBrowserSession(t, server, token)
	if second.StatusCode != http.StatusUnauthorized {
		t.Fatalf("second exchange status = %d, want replay rejection; body=%s", second.StatusCode, responseBody(t, second))
	}
	secondBody := responseBody(t, second)
	if strings.Contains(secondBody, token) || strings.Contains(secondBody, "session-replay-1") || strings.Contains(secondBody, "replay-code") {
		t.Fatalf("replay rejection leaked browser secret: %q", secondBody)
	}
	if generatedCodes != 1 {
		t.Fatalf("generated codes = %d, want only first exchange to issue a code", generatedCodes)
	}
}

func TestATBROWSER006LaunchURLAllowlistRejectsEvilBackendResponse(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	key := newAcceptanceRSAKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost || req.URL.Path != "/auth/credlease/browser-sessions" {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"launch_url":"https://evil.example/auth/credlease/complete?code=evil-code","expires_at":"2026-06-22T12:00:30Z"}`))
	}))
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("Parse(server URL) error = %v", err)
	}
	browserProfile := profile.Profile{
		Name:              "admin-web/dev",
		Kind:              profile.KindBrowserSession,
		Resource:          server.URL,
		Scopes:            []string{"browser:session:create"},
		BootstrapTokenTTL: 60 * time.Second,
		LoginCodeTTL:      30 * time.Second,
		WebSessionTTL:     30 * time.Minute,
		ExchangeURL:       server.URL + "/auth/credlease/browser-sessions",
		CompleteURL:       server.URL + "/auth/credlease/complete",
		PostLoginURL:      server.URL + "/admin",
		AllowedHosts:      []string{parsed.Host},
	}
	fakeBrowser := buildFixture(t, findRepoRoot(t), "fake-browser")
	capturePath := filepath.Join(t.TempDir(), "fake-browser.jsonl")
	t.Setenv("CREDLEASE_FAKE_BROWSER_CAPTURE", capturePath)
	tokenIssuer := &signingAcceptanceIssuer{
		key:    key,
		issuer: "credlease-local:test-install",
		now:    now,
	}
	app := cli.New(cli.Options{
		ProjectStartDir: t.TempDir(),
		Profiles: fakeProfileResolver{
			browserProfile.Name: browserProfile,
		},
		Browser: browser.Client{
			HTTP:   server.Client(),
			Issuer: tokenIssuer,
			Opener: browser.CommandOpener{},
		},
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"open", browserProfile.Name,
		"--browser", fakeBrowser,
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("Run() code = %d, want launch URL rejection; stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "CREDLEASE_BROWSER_URL_REJECTED") {
		t.Fatalf("stderr = %q, want browser URL rejection", stderr.String())
	}
	if strings.Contains(stderr.String(), "evil-code") || strings.Contains(stderr.String(), tokenIssuer.token) {
		t.Fatalf("stderr leaked rejected launch secret: %q", stderr.String())
	}
	if _, err := os.Stat(capturePath); !os.IsNotExist(err) {
		t.Fatalf("fake browser capture path exists after rejected launch URL: %v", err)
	}
}

func TestATBROWSER007ProductionHTTPSCookieSecurityAttributesThroughSampleBackend(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	key := newAcceptanceRSAKey(t)
	server, browserProfile, _ := newAcceptanceBrowserBackendWithConfig(t, key, acceptanceBrowserBackendConfig{
		Now:           func() time.Time { return now },
		LoginCodeTTL:  30 * time.Second,
		SecureCookies: true,
		TLS:           true,
		CodeGenerator: func() (string, error) {
			return "secure-code", nil
		},
	})
	tokenIssuer := &signingAcceptanceIssuer{
		key:    key,
		issuer: "credlease-local:test-install",
		now:    now,
	}
	app := cli.New(cli.Options{
		ProjectStartDir: t.TempDir(),
		Profiles: fakeProfileResolver{
			browserProfile.Name: browserProfile,
		},
		Browser: browser.Client{
			HTTP:   server.Client(),
			Issuer: tokenIssuer,
		},
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"open", browserProfile.Name,
		"--print-url",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	launchURL := strings.TrimSpace(stdout.String())
	if !strings.Contains(launchURL, "code=secure-code") {
		t.Fatalf("launch URL = %q, want secure code", launchURL)
	}
	if strings.Contains(launchURL, tokenIssuer.token) {
		t.Fatalf("launch URL leaked bootstrap JWT: %q", launchURL)
	}

	complete := completeWithoutRedirectWithClient(t, server.Client(), launchURL)
	if complete.StatusCode != http.StatusSeeOther {
		t.Fatalf("complete status = %d, want 303; body=%s", complete.StatusCode, responseBody(t, complete))
	}
	if complete.Header.Get("Location") != browserProfile.PostLoginURL {
		t.Fatalf("complete Location = %q, want %q", complete.Header.Get("Location"), browserProfile.PostLoginURL)
	}
	if strings.Contains(complete.Header.Get("Location"), "code=") {
		t.Fatalf("complete Location leaked code: %q", complete.Header.Get("Location"))
	}
	cookies := complete.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("complete cookies = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if !cookie.HttpOnly {
		t.Fatal("session cookie HttpOnly = false, want true")
	}
	if !cookie.Secure {
		t.Fatal("session cookie Secure = false, want true")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie SameSite = %v, want Lax", cookie.SameSite)
	}
	_ = responseBody(t, complete)
}

type recordedExchange struct {
	Authorization string
	CacheControl  string
	URL           string
}

type recordingBackend struct {
	handler   http.Handler
	exchanges []recordedExchange
}

func (r *recordingBackend) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/auth/credlease/browser-sessions" {
		r.exchanges = append(r.exchanges, recordedExchange{
			Authorization: req.Header.Get("Authorization"),
			CacheControl:  req.Header.Get("Cache-Control"),
			URL:           req.URL.String(),
		})
	}
	r.handler.ServeHTTP(w, req)
}

type acceptanceBrowserBackendConfig struct {
	Now           func() time.Time
	LoginCodeTTL  time.Duration
	SecureCookies bool
	TLS           bool
	CodeGenerator func() (string, error)
}

func newAcceptanceBrowserBackend(t *testing.T, key *rsa.PrivateKey, now time.Time) (*httptest.Server, profile.Profile, *recordingBackend) {
	t.Helper()
	return newAcceptanceBrowserBackendWithConfig(t, key, acceptanceBrowserBackendConfig{
		Now:          func() time.Time { return now },
		LoginCodeTTL: 30 * time.Second,
		CodeGenerator: func() (string, error) {
			return "opaque-code", nil
		},
	})
}

func newAcceptanceBrowserBackendWithConfig(t *testing.T, key *rsa.PrivateKey, config acceptanceBrowserBackendConfig) (*httptest.Server, profile.Profile, *recordingBackend) {
	t.Helper()
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.LoginCodeTTL <= 0 {
		config.LoginCodeTTL = 30 * time.Second
	}
	if config.CodeGenerator == nil {
		config.CodeGenerator = func() (string, error) { return "opaque-code", nil }
	}
	server := httptest.NewUnstartedServer(nil)
	scheme := "http"
	if config.TLS {
		scheme = "https"
	}
	baseURL := scheme + "://" + server.Listener.Addr().String()
	backend, err := backendgo.New(backendgo.Config{
		JWKS:                 acceptanceJWKSForRSA(t, &key.PublicKey),
		Issuer:               "credlease-local:test-install",
		Resource:             baseURL,
		ClockSkew:            10 * time.Second,
		Now:                  config.Now,
		CompleteURL:          baseURL + "/auth/credlease/complete",
		PostLoginURL:         baseURL + "/admin",
		LoginCodeTTL:         config.LoginCodeTTL,
		WebSessionTTL:        30 * time.Minute,
		SecureCookies:        config.SecureCookies,
		CodeGeneratorForTest: config.CodeGenerator,
	})
	if err != nil {
		t.Fatalf("backendgo.New() error = %v", err)
	}
	recorder := &recordingBackend{handler: backend.Handler()}
	server.Config.Handler = recorder
	if config.TLS {
		server.StartTLS()
	} else {
		server.Start()
	}
	t.Cleanup(server.Close)

	parsed, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("Parse(%q) error = %v", baseURL, err)
	}
	return server, profile.Profile{
		Name:              "admin-web/dev",
		Kind:              profile.KindBrowserSession,
		Resource:          baseURL,
		Scopes:            []string{"browser:session:create"},
		BootstrapTokenTTL: 60 * time.Second,
		LoginCodeTTL:      config.LoginCodeTTL,
		WebSessionTTL:     30 * time.Minute,
		ExchangeURL:       baseURL + "/auth/credlease/browser-sessions",
		CompleteURL:       baseURL + "/auth/credlease/complete",
		PostLoginURL:      baseURL + "/admin",
		AllowedHosts:      []string{parsed.Host},
	}, recorder
}

func exchangeBrowserSession(t *testing.T, server *httptest.Server, token string) *http.Response {
	t.Helper()
	body := strings.NewReader(`{"requested_session_ttl_seconds":1800,"client":"credlease-cli","client_version":"0.1.0"}`)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, server.URL+"/auth/credlease/browser-sessions", body)
	if err != nil {
		t.Fatalf("NewRequest(exchange) error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "no-store")

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("Do(exchange) error = %v", err)
	}
	return resp
}

func acceptanceBrowserBootstrapJWT(t *testing.T, key *rsa.PrivateKey, now time.Time, resource, sessionID string, ttl time.Duration) string {
	t.Helper()
	token, err := signAcceptanceRS256(key, map[string]any{
		"iss":                  "credlease-local:test-install",
		"sub":                  "local-user",
		"nbf":                  now.Add(-time.Second).Unix(),
		"exp":                  now.Add(ttl).Unix(),
		"scope":                "browser:session:create",
		"credlease_profile":    "admin-web/dev",
		"credlease_resource":   resource,
		"credlease_session_id": sessionID,
		"credlease_client":     "credlease-cli",
		"credlease_purpose":    "browser-bootstrap",
	})
	if err != nil {
		t.Fatalf("signAcceptanceRS256() error = %v", err)
	}
	return token
}

type fakeBrowserLaunch struct {
	URL string `json:"url"`
}

func readFakeBrowserLaunches(t *testing.T, path string) []fakeBrowserLaunch {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open(%s) error = %v", path, err)
	}
	defer file.Close()

	var records []fakeBrowserLaunch
	dec := json.NewDecoder(file)
	for {
		var record fakeBrowserLaunch
		err := dec.Decode(&record)
		if errors.Is(err, io.EOF) {
			return records
		}
		if err != nil {
			t.Fatalf("Decode(fake browser capture) error = %v", err)
		}
		records = append(records, record)
	}
}

func withRedirectAttempt(t *testing.T, rawURL string) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("Parse(%q) error = %v", rawURL, err)
	}
	query := parsed.Query()
	query.Set("redirect", "https://evil.example")
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func completeWithoutRedirect(t *testing.T, rawURL string) *http.Response {
	t.Helper()
	return completeWithoutRedirectWithClient(t, http.DefaultClient, rawURL)
}

func completeWithoutRedirectWithClient(t *testing.T, base *http.Client, rawURL string) *http.Response {
	t.Helper()
	client := *base
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if client.Transport == nil && base == http.DefaultClient {
		client.Transport = http.DefaultTransport
	}
	resp, err := client.Get(rawURL)
	if err != nil {
		t.Fatalf("GET(%s) error = %v", rawURL, err)
	}
	return resp
}

type signingAcceptanceIssuer struct {
	key    *rsa.PrivateKey
	issuer string
	now    time.Time
	token  string
	grants []issuer.Grant
}

func (s *signingAcceptanceIssuer) Issue(ctx context.Context, grant issuer.Grant) (issuer.Credential, error) {
	if err := ctx.Err(); err != nil {
		return issuer.Credential{}, err
	}
	s.grants = append(s.grants, grant)

	claims := make(map[string]any, len(grant.Claims)+4)
	for key, value := range grant.Claims {
		claims[key] = value
	}
	claims["iss"] = s.issuer
	claims["nbf"] = s.now.Add(-time.Second).Unix()
	claims["exp"] = s.now.Add(grant.TTL).Unix()
	claims["scope"] = strings.Join(grant.Scopes, " ")

	token, err := signAcceptanceRS256(s.key, claims)
	if err != nil {
		return issuer.Credential{}, err
	}
	s.token = token
	return issuer.Credential{
		AccessToken: s.token,
		TokenType:   "Bearer",
		ExpiresAt:   s.now.Add(grant.TTL),
		Scopes:      append([]string(nil), grant.Scopes...),
	}, nil
}

func newAcceptanceRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	return key
}

func signAcceptanceRS256(key *rsa.PrivateKey, claims map[string]any) (string, error) {
	header, err := acceptanceJSON(map[string]any{"alg": "RS256", "kid": "acceptance-test-kid", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := acceptanceJSON(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("sign acceptance JWT: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func acceptanceJWKSForRSA(t *testing.T, key *rsa.PublicKey) []byte {
	t.Helper()
	return acceptanceMustJSON(t, map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"kid": "acceptance-test-kid",
				"alg": "RS256",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			},
		},
	})
}

func acceptanceMustJSON(t interface {
	Helper()
	Fatalf(string, ...any)
}, value any) []byte {
	t.Helper()
	raw, err := acceptanceJSON(value)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	return raw
}

func acceptanceJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal acceptance JSON: %w", err)
	}
	return raw, nil
}
