package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseConfigLoadsExplicitBackendConfig(t *testing.T) {
	jwksPath := filepath.Join(t.TempDir(), "jwks.json")
	jwks := []byte(`{"keys":[{"kty":"RSA","kid":"test"}]}`)
	if err := os.WriteFile(jwksPath, jwks, 0o600); err != nil {
		t.Fatalf("WriteFile(jwks) error = %v", err)
	}

	config, err := parseConfig([]string{
		"--addr", "127.0.0.1:0",
		"--jwks", jwksPath,
		"--issuer", "credlease-local:test-install",
		"--resource", "http://127.0.0.1:8080",
		"--complete-url", "http://127.0.0.1:8080/auth/credlease/complete",
		"--post-login-url", "http://127.0.0.1:8080/",
		"--clock-skew", "2s",
		"--login-code-ttl", "15s",
		"--web-session-ttl", "20m",
		"--secure-cookies",
	})
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}

	if config.Addr != "127.0.0.1:0" {
		t.Fatalf("Addr = %q", config.Addr)
	}
	if string(config.JWKS) != string(jwks) {
		t.Fatalf("JWKS = %s, want %s", config.JWKS, jwks)
	}
	if config.Issuer != "credlease-local:test-install" || config.Resource != "http://127.0.0.1:8080" {
		t.Fatalf("issuer/resource = %q/%q", config.Issuer, config.Resource)
	}
	if config.CompleteURL != "http://127.0.0.1:8080/auth/credlease/complete" {
		t.Fatalf("CompleteURL = %q", config.CompleteURL)
	}
	if config.PostLoginURL != "http://127.0.0.1:8080/" {
		t.Fatalf("PostLoginURL = %q", config.PostLoginURL)
	}
	if config.ClockSkew != 2*time.Second || config.LoginCodeTTL != 15*time.Second || config.WebSessionTTL != 20*time.Minute {
		t.Fatalf("durations = %s/%s/%s", config.ClockSkew, config.LoginCodeTTL, config.WebSessionTTL)
	}
	if !config.SecureCookies {
		t.Fatalf("SecureCookies = false, want true")
	}
}

func TestParseConfigRejectsMissingRequiredValues(t *testing.T) {
	jwksPath := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(jwksPath, []byte(`{"keys":[]}`), 0o600); err != nil {
		t.Fatalf("WriteFile(jwks) error = %v", err)
	}

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "jwks",
			args: []string{
				"--issuer", "credlease-local:test-install",
				"--resource", "http://127.0.0.1:8080",
				"--complete-url", "http://127.0.0.1:8080/auth/credlease/complete",
				"--post-login-url", "http://127.0.0.1:8080/",
			},
			want: "--jwks",
		},
		{
			name: "issuer",
			args: []string{
				"--jwks", jwksPath,
				"--resource", "http://127.0.0.1:8080",
				"--complete-url", "http://127.0.0.1:8080/auth/credlease/complete",
				"--post-login-url", "http://127.0.0.1:8080/",
			},
			want: "--issuer",
		},
		{
			name: "resource",
			args: []string{
				"--jwks", jwksPath,
				"--issuer", "credlease-local:test-install",
				"--complete-url", "http://127.0.0.1:8080/auth/credlease/complete",
				"--post-login-url", "http://127.0.0.1:8080/",
			},
			want: "--resource",
		},
		{
			name: "complete url",
			args: []string{
				"--jwks", jwksPath,
				"--issuer", "credlease-local:test-install",
				"--resource", "http://127.0.0.1:8080",
				"--post-login-url", "http://127.0.0.1:8080/",
			},
			want: "--complete-url",
		},
		{
			name: "post login url",
			args: []string{
				"--jwks", jwksPath,
				"--issuer", "credlease-local:test-install",
				"--resource", "http://127.0.0.1:8080",
				"--complete-url", "http://127.0.0.1:8080/auth/credlease/complete",
			},
			want: "--post-login-url",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseConfig(tc.args)
			if err == nil {
				t.Fatalf("parseConfig() error = nil, want missing %s", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to mention %s", err.Error(), tc.want)
			}
		})
	}
}

func TestNewHandlerFromConfigServesProcessJWTEndpoints(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	key := newTestRSAKey(t)
	handler, err := newHandler(appConfig{
		JWKS:         jwksForRSA(t, &key.PublicKey),
		Issuer:       "credlease-local:test-install",
		Resource:     "http://127.0.0.1:8080",
		CompleteURL:  "http://127.0.0.1:8080/auth/credlease/complete",
		PostLoginURL: "http://127.0.0.1:8080/",
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("newHandler() error = %v", err)
	}

	token := signRS256(t, key, map[string]any{
		"iss":                  "credlease-local:test-install",
		"exp":                  now.Add(5 * time.Minute).Unix(),
		"scope":                "document:read",
		"credlease_profile":    "backend-a/dev",
		"credlease_resource":   "http://127.0.0.1:8080",
		"credlease_session_id": "session-process-1",
		"credlease_purpose":    "process",
	})
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/documents/read", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, http.StatusOK, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"operation":"read"`) {
		t.Fatalf("body = %s", response.Body.String())
	}
	if strings.Contains(response.Body.String(), token) {
		t.Fatalf("response leaked JWT: %s", response.Body.String())
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

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	return raw
}
