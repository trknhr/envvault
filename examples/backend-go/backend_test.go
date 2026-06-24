package backendgo_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	backendgo "github.com/trknhr/credlease/examples/backend-go"
)

func TestProcessJWTAuthorizesReadEndpointAndRejectsMissingScope(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	key := newTestRSAKey(t)
	backend, err := backendgo.New(backendgo.Config{
		JWKS:     jwksForRSA(t, &key.PublicKey),
		Issuer:   "credlease-local:test-install",
		Resource: "https://api.dev.example.com",
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	readToken := signRS256(t, key, map[string]any{
		"iss":                  "credlease-local:test-install",
		"sub":                  "local-user",
		"exp":                  now.Add(5 * time.Minute).Unix(),
		"scope":                "document:read",
		"credlease_profile":    "backend-a/dev",
		"credlease_resource":   "https://api.dev.example.com",
		"credlease_session_id": "session-process-1",
		"credlease_purpose":    "process",
	})

	read := httptest.NewRecorder()
	readRequest := httptest.NewRequest(http.MethodGet, "/documents/read", nil)
	readRequest.Header.Set("Authorization", "Bearer "+readToken)
	backend.Handler().ServeHTTP(read, readRequest)

	if read.Code != http.StatusOK {
		t.Fatalf("read status = %d, want %d; body=%s", read.Code, http.StatusOK, read.Body.String())
	}
	if !strings.Contains(read.Body.String(), `"scope":"document:read"`) {
		t.Fatalf("read body = %s", read.Body.String())
	}
	if strings.Contains(read.Body.String(), readToken) {
		t.Fatalf("read body leaked JWT: %s", read.Body.String())
	}

	write := httptest.NewRecorder()
	writeRequest := httptest.NewRequest(http.MethodPost, "/documents/write", nil)
	writeRequest.Header.Set("Authorization", "Bearer "+readToken)
	backend.Handler().ServeHTTP(write, writeRequest)

	if write.Code != http.StatusForbidden {
		t.Fatalf("write status = %d, want %d; body=%s", write.Code, http.StatusForbidden, write.Body.String())
	}
	if strings.Contains(write.Body.String(), readToken) {
		t.Fatalf("write error leaked JWT: %s", write.Body.String())
	}
}

func TestProcessJWTAuthorizesEd25519TalosToken(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	backend, err := backendgo.New(backendgo.Config{
		JWKS:     jwksForEd25519(t, publicKey),
		Issuer:   "credlease-local:test-install",
		Resource: "https://api.dev.example.com",
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	token := signEdDSA(t, privateKey, map[string]any{
		"iss":                  "credlease-local:test-install",
		"sub":                  "local-user",
		"exp":                  now.Add(5 * time.Minute).Unix(),
		"scope":                "document:read",
		"credlease_profile":    "backend-a/dev",
		"credlease_resource":   "https://api.dev.example.com",
		"credlease_session_id": "session-process-1",
		"credlease_purpose":    "process",
	})

	read := httptest.NewRecorder()
	readRequest := httptest.NewRequest(http.MethodGet, "/documents/read", nil)
	readRequest.Header.Set("Authorization", "Bearer "+token)
	backend.Handler().ServeHTTP(read, readRequest)

	if read.Code != http.StatusOK {
		t.Fatalf("read status = %d, want %d; body=%s", read.Code, http.StatusOK, read.Body.String())
	}
	if strings.Contains(read.Body.String(), token) {
		t.Fatalf("read body leaked JWT: %s", read.Body.String())
	}
}

func TestBrowserSessionExchangeAndCompleteSetSecureCookie(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	key := newTestRSAKey(t)
	backend, err := backendgo.New(backendgo.Config{
		JWKS:                 jwksForRSA(t, &key.PublicKey),
		Issuer:               "credlease-local:test-install",
		Resource:             "https://admin.dev.example.com",
		CompleteURL:          "https://admin.dev.example.com/auth/credlease/complete",
		PostLoginURL:         "https://admin.dev.example.com/",
		SecureCookies:        true,
		LoginCodeTTL:         30 * time.Second,
		WebSessionTTL:        30 * time.Minute,
		CodeGeneratorForTest: func() (string, error) { return "opaque-code", nil },
		Now:                  func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	bootstrap := signRS256(t, key, map[string]any{
		"iss":                  "credlease-local:test-install",
		"exp":                  now.Add(60 * time.Second).Unix(),
		"scope":                "browser:session:create",
		"credlease_profile":    "admin-web/dev",
		"credlease_resource":   "https://admin.dev.example.com",
		"credlease_session_id": "session-browser-1",
		"credlease_purpose":    "browser-bootstrap",
	})

	exchange := httptest.NewRecorder()
	exchangeRequest := httptest.NewRequest(http.MethodPost, "/auth/credlease/browser-sessions?redirect=https://evil.example", strings.NewReader(`{"requested_session_ttl_seconds":1800}`))
	exchangeRequest.Header.Set("Authorization", "Bearer "+bootstrap)
	backend.Handler().ServeHTTP(exchange, exchangeRequest)

	if exchange.Code != http.StatusCreated {
		t.Fatalf("exchange status = %d, want %d; body=%s", exchange.Code, http.StatusCreated, exchange.Body.String())
	}
	if exchange.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("exchange Cache-Control = %q", exchange.Header().Get("Cache-Control"))
	}
	var body struct {
		LaunchURL string    `json:"launch_url"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(exchange.Body).Decode(&body); err != nil {
		t.Fatalf("Decode(exchange) error = %v", err)
	}
	if body.LaunchURL != "https://admin.dev.example.com/auth/credlease/complete?code=opaque-code" {
		t.Fatalf("launch_url = %q", body.LaunchURL)
	}
	if strings.Contains(body.LaunchURL, bootstrap) || strings.Contains(body.LaunchURL, "redirect=") {
		t.Fatalf("launch_url leaked token or accepted redirect: %q", body.LaunchURL)
	}

	completeURL, err := url.Parse(body.LaunchURL)
	if err != nil {
		t.Fatalf("Parse(launch_url) error = %v", err)
	}
	complete := httptest.NewRecorder()
	completeRequest := httptest.NewRequest(http.MethodGet, completeURL.RequestURI()+"&redirect=https://evil.example", nil)
	backend.Handler().ServeHTTP(complete, completeRequest)

	if complete.Code != http.StatusSeeOther {
		t.Fatalf("complete status = %d, want %d; body=%s", complete.Code, http.StatusSeeOther, complete.Body.String())
	}
	if complete.Header().Get("Location") != "https://admin.dev.example.com/" {
		t.Fatalf("Location = %q", complete.Header().Get("Location"))
	}
	if strings.Contains(complete.Header().Get("Location"), "code=") || strings.Contains(complete.Header().Get("Location"), "evil.example") {
		t.Fatalf("Location leaked code or accepted redirect: %q", complete.Header().Get("Location"))
	}
	if complete.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("Referrer-Policy = %q", complete.Header().Get("Referrer-Policy"))
	}
	cookies := complete.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != "credlease_admin_session" || cookie.Value == "" {
		t.Fatalf("cookie = %s=%q", cookie.Name, cookie.Value)
	}
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie attributes: HttpOnly=%v Secure=%v SameSite=%v", cookie.HttpOnly, cookie.Secure, cookie.SameSite)
	}

	replay := httptest.NewRecorder()
	backend.Handler().ServeHTTP(replay, completeRequest.Clone(context.Background()))
	if replay.Code != http.StatusGone {
		t.Fatalf("replay status = %d, want %d", replay.Code, http.StatusGone)
	}
}

func newTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	return key
}

func signRS256(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header := mustJSON(t, map[string]any{"alg": "RS256", "kid": "test-kid", "typ": "JWT"})
	payload := mustJSON(t, claims)
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("SignPKCS1v15() error = %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func signEdDSA(t *testing.T, key ed25519.PrivateKey, claims map[string]any) string {
	t.Helper()
	header := mustJSON(t, map[string]any{"alg": "EdDSA", "kid": "test-ed25519-kid", "typ": "JWT"})
	payload := mustJSON(t, claims)
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	signature := ed25519.Sign(key, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func jwksForRSA(t *testing.T, key *rsa.PublicKey) []byte {
	t.Helper()
	return mustJSON(t, map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"kid": "test-kid",
				"alg": "RS256",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			},
		},
	})
}

func jwksForEd25519(t *testing.T, key ed25519.PublicKey) []byte {
	t.Helper()
	return mustJSON(t, map[string]any{
		"keys": []map[string]any{
			{
				"kty": "OKP",
				"kid": "test-ed25519-kid",
				"alg": "EdDSA",
				"use": "sig",
				"crv": "Ed25519",
				"x":   base64.RawURLEncoding.EncodeToString(key),
			},
		},
	})
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	return raw
}
