package backendgo

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/trknhr/credlease/pkg/browsersession"
	"github.com/trknhr/credlease/pkg/verifier"
)

const (
	defaultReadScope           = "document:read"
	defaultWriteScope          = "document:write"
	defaultBrowserSessionScope = "browser:session:create"
	defaultSessionCookieName   = "credlease_admin_session"
)

type Config struct {
	JWKS         []byte
	Issuer       string
	Resource     string
	ClockSkew    time.Duration
	Now          func() time.Time
	ReadScope    string
	WriteScope   string
	BrowserScope string

	CompleteURL          string
	PostLoginURL         string
	LoginCodeTTL         time.Duration
	WebSessionTTL        time.Duration
	SecureCookies        bool
	CodeGeneratorForTest func() (string, error)
}

type Backend struct {
	verifier       *verifier.Verifier
	browserSession browsersession.Server
	mux            *http.ServeMux
	readScope      string
	writeScope     string
}

func New(config Config) (*Backend, error) {
	now := config.Now
	if now == nil {
		now = time.Now
	}
	v, err := verifier.New(verifier.Options{
		JWKS:          config.JWKS,
		Issuer:        config.Issuer,
		Resource:      config.Resource,
		ClockSkew:     config.ClockSkew,
		Now:           now,
		AllowedAlgs:   []string{"RS256", "EdDSA"},
		RequireIssuer: config.Issuer != "",
	})
	if err != nil {
		return nil, err
	}

	codeStore := browsersession.NewMemoryLoginCodeStore(now)
	if config.CodeGeneratorForTest != nil {
		codeStore.SetCodeGeneratorForTest(config.CodeGeneratorForTest)
	}
	browserScope := firstNonEmpty(config.BrowserScope, defaultBrowserSessionScope)
	backend := &Backend{
		verifier:   v,
		readScope:  firstNonEmpty(config.ReadScope, defaultReadScope),
		writeScope: firstNonEmpty(config.WriteScope, defaultWriteScope),
		browserSession: browsersession.Server{
			Verifier: verifier.BrowserBootstrapVerifier{
				Verifier: v,
				Scopes:   []string{browserScope},
			},
			ReplayStore:   browsersession.NewMemoryReplayStore(now),
			CodeStore:     codeStore,
			SessionIssuer: memorySessionIssuer{now: now},
			CompleteURL:   config.CompleteURL,
			PostLoginURL:  config.PostLoginURL,
			LoginCodeTTL:  config.LoginCodeTTL,
			WebSessionTTL: config.WebSessionTTL,
			SecureCookies: config.SecureCookies,
			Now:           now,
		},
	}
	backend.mux = http.NewServeMux()
	backend.mux.HandleFunc("/documents/read", backend.requireProcessScope(backend.readScope, backend.readDocument))
	backend.mux.HandleFunc("/documents/write", backend.requireProcessScope(backend.writeScope, backend.writeDocument))
	backend.mux.HandleFunc("/auth/credlease/browser-sessions", backend.browserSession.Exchange)
	backend.mux.HandleFunc("/auth/credlease/complete", backend.browserSession.Complete)
	return backend, nil
}

func (b *Backend) Handler() http.Handler {
	return b.mux
}

func (b *Backend) requireProcessScope(scope string, next func(http.ResponseWriter, *http.Request, verifier.Claims)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		claims, err := b.verifier.Verify(r.Context(), token, verifier.Requirements{
			Scopes:  []string{scope},
			Purpose: "process",
		})
		if err != nil {
			http.Error(w, "credential not authorized", processJWTFailureStatus(err))
			return
		}
		next(w, r, claims)
	}
}

func processJWTFailureStatus(err error) int {
	switch {
	case errors.Is(err, verifier.ErrScopeMissing),
		errors.Is(err, verifier.ErrResourceMismatch),
		errors.Is(err, verifier.ErrPurposeMismatch):
		return http.StatusForbidden
	default:
		return http.StatusUnauthorized
	}
}

func (b *Backend) readDocument(w http.ResponseWriter, r *http.Request, claims verifier.Claims) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]any{
		"ok":         true,
		"operation":  "read",
		"scope":      b.readScope,
		"profile":    claims.Profile,
		"session_id": claims.SessionID,
	})
}

func (b *Backend) writeDocument(w http.ResponseWriter, r *http.Request, claims verifier.Claims) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]any{
		"ok":         true,
		"operation":  "write",
		"scope":      b.writeScope,
		"profile":    claims.Profile,
		"session_id": claims.SessionID,
	})
}

type memorySessionIssuer struct {
	now func() time.Time
}

func (i memorySessionIssuer) Issue(ctx context.Context, _ browsersession.BrowserGrant, ttl time.Duration) (browsersession.SessionCookie, error) {
	if err := ctx.Err(); err != nil {
		return browsersession.SessionCookie{}, err
	}
	value, err := randomSessionValue()
	if err != nil {
		return browsersession.SessionCookie{}, err
	}
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	now := time.Now
	if i.now != nil {
		now = i.now
	}
	return browsersession.SessionCookie{
		Name:     defaultSessionCookieName,
		Value:    value,
		Path:     "/",
		Expires:  now().Add(ttl),
		MaxAge:   int(ttl.Seconds()),
		HTTPOnly: true,
		SameSite: http.SameSiteLaxMode,
	}, nil
}

func bearerToken(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	return token, token != "" && !strings.ContainsAny(token, " \t\r\n")
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(body)
}

func randomSessionValue() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", errors.New("generate session cookie")
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
