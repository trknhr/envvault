package browsersession_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/trknhr/credlease/pkg/browsersession"
)

func TestExchangeUsesAuthorizationBearerAndReturnsFixedCompleteURL(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	codeStore := browsersession.NewMemoryLoginCodeStore(func() time.Time { return now })
	codeStore.SetCodeGeneratorForTest(func() (string, error) { return "opaque-code", nil })
	verifier := &fakeBootstrapVerifier{
		grant: browsersession.BrowserGrant{
			Profile:   "admin-web/dev",
			Resource:  "https://admin.dev.example.com",
			Scopes:    []string{"browser:session:create"},
			SessionID: "session-1",
			Purpose:   "browser-bootstrap",
			ExpiresAt: now.Add(60 * time.Second),
		},
	}
	server := browsersession.Server{
		Verifier:     verifier,
		ReplayStore:  browsersession.NewMemoryReplayStore(func() time.Time { return now }),
		CodeStore:    codeStore,
		CompleteURL:  "https://admin.dev.example.com/auth/credlease/complete",
		LoginCodeTTL: 30 * time.Second,
		Now:          func() time.Time { return now },
	}

	request := httptest.NewRequest(http.MethodPost, "/auth/credlease/browser-sessions?redirect=https://evil.example", strings.NewReader(`{"requested_session_ttl_seconds":1800}`))
	request.Header.Set("Authorization", "Bearer bootstrap-jwt")
	response := httptest.NewRecorder()

	server.Exchange(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, http.StatusCreated, response.Body.String())
	}
	if verifier.token != "bootstrap-jwt" {
		t.Fatalf("verified token = %q, want bootstrap-jwt", verifier.token)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", response.Header().Get("Cache-Control"))
	}
	if response.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("Pragma = %q, want no-cache", response.Header().Get("Pragma"))
	}

	var body struct {
		LaunchURL string    `json:"launch_url"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if body.LaunchURL != "https://admin.dev.example.com/auth/credlease/complete?code=opaque-code" {
		t.Fatalf("launch_url = %q", body.LaunchURL)
	}
	if body.ExpiresAt != now.Add(30*time.Second) {
		t.Fatalf("expires_at = %s, want %s", body.ExpiresAt, now.Add(30*time.Second))
	}
	if strings.Contains(body.LaunchURL, "bootstrap-jwt") || strings.Contains(body.LaunchURL, "redirect=") {
		t.Fatalf("launch_url leaked token or accepted redirect: %q", body.LaunchURL)
	}
}

func TestExchangeRejectsBootstrapTokenOutsideAuthorizationHeader(t *testing.T) {
	server := browsersession.Server{
		Verifier:    &fakeBootstrapVerifier{},
		ReplayStore: browsersession.NewMemoryReplayStore(time.Now),
		CodeStore:   browsersession.NewMemoryLoginCodeStore(time.Now),
		CompleteURL: "https://admin.dev.example.com/auth/credlease/complete",
	}
	request := httptest.NewRequest(http.MethodPost, "/auth/credlease/browser-sessions?token=bootstrap-jwt", nil)
	response := httptest.NewRecorder()

	server.Exchange(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestExchangeRejectsBootstrapSessionReplay(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	codeStore := browsersession.NewMemoryLoginCodeStore(func() time.Time { return now })
	codeStore.SetCodeGeneratorForTest(func() (string, error) { return "opaque-code", nil })
	server := browsersession.Server{
		Verifier: &fakeBootstrapVerifier{
			grant: browsersession.BrowserGrant{
				SessionID: "session-1",
				Purpose:   "browser-bootstrap",
				ExpiresAt: now.Add(time.Minute),
			},
		},
		ReplayStore:  browsersession.NewMemoryReplayStore(func() time.Time { return now }),
		CodeStore:    codeStore,
		CompleteURL:  "https://admin.dev.example.com/auth/credlease/complete",
		LoginCodeTTL: 30 * time.Second,
		Now:          func() time.Time { return now },
	}

	first := httptest.NewRecorder()
	firstRequest := httptest.NewRequest(http.MethodPost, "/auth/credlease/browser-sessions", nil)
	firstRequest.Header.Set("Authorization", "Bearer bootstrap-jwt")
	server.Exchange(first, firstRequest)
	if first.Code != http.StatusCreated {
		t.Fatalf("first status = %d, want %d", first.Code, http.StatusCreated)
	}

	second := httptest.NewRecorder()
	secondRequest := httptest.NewRequest(http.MethodPost, "/auth/credlease/browser-sessions", nil)
	secondRequest.Header.Set("Authorization", "Bearer bootstrap-jwt")
	server.Exchange(second, secondRequest)
	if second.Code != http.StatusUnauthorized {
		t.Fatalf("second status = %d, want replay rejection", second.Code)
	}
}

func TestCompleteConsumesCodeSetsCookieAndRedirectsToFixedPostLoginURL(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	codeStore := browsersession.NewMemoryLoginCodeStore(func() time.Time { return now })
	codeStore.SetCodeGeneratorForTest(func() (string, error) { return "opaque-code", nil })
	grant := browsersession.BrowserGrant{
		Profile:   "admin-web/dev",
		Resource:  "https://admin.dev.example.com",
		SessionID: "session-1",
		Purpose:   "browser-bootstrap",
	}
	code, err := codeStore.Create(context.Background(), grant, 30*time.Second)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	sessionIssuer := &fakeWebSessionIssuer{
		cookie: browsersession.SessionCookie{
			Name:     "admin_session",
			Value:    "web-session",
			Path:     "/",
			Expires:  now.Add(30 * time.Minute),
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		},
	}
	server := browsersession.Server{
		CodeStore:     codeStore,
		SessionIssuer: sessionIssuer,
		PostLoginURL:  "https://admin.dev.example.com/",
		WebSessionTTL: 30 * time.Minute,
		SecureCookies: true,
	}
	request := httptest.NewRequest(http.MethodGet, "/auth/credlease/complete?code="+code+"&redirect=https://evil.example", nil)
	response := httptest.NewRecorder()

	server.Complete(response, request)

	if response.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, http.StatusSeeOther, response.Body.String())
	}
	if response.Header().Get("Location") != "https://admin.dev.example.com/" {
		t.Fatalf("Location = %q", response.Header().Get("Location"))
	}
	if strings.Contains(response.Header().Get("Location"), "code=") || strings.Contains(response.Header().Get("Location"), "evil.example") {
		t.Fatalf("Location leaked code or accepted redirect: %q", response.Header().Get("Location"))
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", response.Header().Get("Cache-Control"))
	}
	if response.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("Referrer-Policy = %q, want no-referrer", response.Header().Get("Referrer-Policy"))
	}
	if sessionIssuer.ttl != 30*time.Minute {
		t.Fatalf("session ttl = %s, want 30m", sessionIssuer.ttl)
	}
	if sessionIssuer.grant.SessionID != "session-1" {
		t.Fatalf("issued grant SessionID = %q", sessionIssuer.grant.SessionID)
	}

	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != "admin_session" || cookie.Value != "web-session" {
		t.Fatalf("cookie = %s=%s", cookie.Name, cookie.Value)
	}
	if !cookie.HttpOnly {
		t.Fatal("cookie HttpOnly = false, want true")
	}
	if !cookie.Secure {
		t.Fatal("cookie Secure = false, want true")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie SameSite = %v, want Lax", cookie.SameSite)
	}
}

func TestCompleteRejectsReusedCodeWithGenericError(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	codeStore := browsersession.NewMemoryLoginCodeStore(func() time.Time { return now })
	codeStore.SetCodeGeneratorForTest(func() (string, error) { return "opaque-code", nil })
	code, err := codeStore.Create(context.Background(), browsersession.BrowserGrant{SessionID: "session-1"}, 30*time.Second)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	server := browsersession.Server{
		CodeStore: codeStore,
		SessionIssuer: &fakeWebSessionIssuer{
			cookie: browsersession.SessionCookie{Name: "admin_session", Value: "web-session"},
		},
		PostLoginURL:  "https://admin.dev.example.com/",
		WebSessionTTL: time.Minute,
	}

	first := httptest.NewRecorder()
	server.Complete(first, httptest.NewRequest(http.MethodGet, "/auth/credlease/complete?code="+code, nil))
	if first.Code != http.StatusSeeOther {
		t.Fatalf("first status = %d, want %d", first.Code, http.StatusSeeOther)
	}

	second := httptest.NewRecorder()
	server.Complete(second, httptest.NewRequest(http.MethodGet, "/auth/credlease/complete?code="+code, nil))
	if second.Code != http.StatusGone {
		t.Fatalf("second status = %d, want generic used-code rejection", second.Code)
	}
	if strings.Contains(second.Body.String(), code) || strings.Contains(second.Body.String(), "session-1") {
		t.Fatalf("generic error leaked code/session: %q", second.Body.String())
	}
}

type fakeBootstrapVerifier struct {
	token string
	grant browsersession.BrowserGrant
	err   error
}

func (f *fakeBootstrapVerifier) VerifyBootstrap(_ context.Context, token string) (browsersession.BrowserGrant, error) {
	f.token = token
	if f.err != nil {
		return browsersession.BrowserGrant{}, f.err
	}
	return f.grant, nil
}

type fakeWebSessionIssuer struct {
	grant  browsersession.BrowserGrant
	ttl    time.Duration
	cookie browsersession.SessionCookie
	err    error
}

func (f *fakeWebSessionIssuer) Issue(_ context.Context, grant browsersession.BrowserGrant, ttl time.Duration) (browsersession.SessionCookie, error) {
	f.grant = grant
	f.ttl = ttl
	if f.err != nil {
		return browsersession.SessionCookie{}, f.err
	}
	if f.cookie.Name == "" {
		return browsersession.SessionCookie{}, errors.New("missing fake cookie")
	}
	return f.cookie, nil
}
