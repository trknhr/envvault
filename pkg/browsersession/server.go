package browsersession

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	ErrBootstrapInvalid     = errors.New("browser bootstrap token invalid")
	ErrServerMisconfigured  = errors.New("browser session server misconfigured")
	ErrSessionCookieInvalid = errors.New("browser session cookie invalid")
)

type BootstrapVerifier interface {
	VerifyBootstrap(ctx context.Context, token string) (BrowserGrant, error)
}

type WebSessionIssuer interface {
	Issue(ctx context.Context, grant BrowserGrant, ttl time.Duration) (SessionCookie, error)
}

type SessionCookie struct {
	Name     string
	Value    string
	Path     string
	Domain   string
	Expires  time.Time
	MaxAge   int
	Secure   bool
	HTTPOnly bool
	SameSite http.SameSite
}

type Server struct {
	Verifier      BootstrapVerifier
	ReplayStore   BrowserReplayStore
	CodeStore     BrowserLoginCodeStore
	SessionIssuer WebSessionIssuer
	CompleteURL   string
	PostLoginURL  string
	LoginCodeTTL  time.Duration
	WebSessionTTL time.Duration
	SecureCookies bool
	Now           func() time.Time
}

func (s Server) Exchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeExchangeError(w, http.StatusMethodNotAllowed)
		return
	}

	token, ok := bearerToken(r)
	if !ok {
		writeExchangeError(w, http.StatusUnauthorized)
		return
	}
	if err := rejectTokenOutsideAuthorization(r); err != nil {
		writeExchangeError(w, http.StatusUnauthorized)
		return
	}
	if err := s.exchangeReady(); err != nil {
		writeExchangeError(w, http.StatusInternalServerError)
		return
	}

	grant, err := s.Verifier.VerifyBootstrap(r.Context(), token)
	if err != nil || grant.Purpose != "browser-bootstrap" {
		writeExchangeError(w, http.StatusUnauthorized)
		return
	}
	if err := s.ReplayStore.ConsumeSessionID(r.Context(), grant.SessionID, grant.ExpiresAt); err != nil {
		writeExchangeError(w, http.StatusUnauthorized)
		return
	}

	code, err := s.CodeStore.Create(r.Context(), grant, s.loginCodeTTL())
	if err != nil {
		writeExchangeError(w, http.StatusInternalServerError)
		return
	}
	launchURL, err := addCodeToURL(s.CompleteURL, code)
	if err != nil {
		writeExchangeError(w, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(exchangeResponse{
		LaunchURL: launchURL,
		ExpiresAt: s.now().Add(s.loginCodeTTL()),
	})
}

func (s Server) Complete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeCompleteError(w, http.StatusMethodNotAllowed)
		return
	}
	if s.CodeStore == nil || s.SessionIssuer == nil || s.PostLoginURL == "" {
		writeCompleteError(w, http.StatusInternalServerError)
		return
	}

	code := r.URL.Query().Get("code")
	grant, err := s.CodeStore.Consume(r.Context(), code)
	if err != nil {
		writeCompleteError(w, http.StatusGone)
		return
	}

	cookie, err := s.SessionIssuer.Issue(r.Context(), grant, s.webSessionTTL())
	if err != nil {
		writeCompleteError(w, http.StatusInternalServerError)
		return
	}
	httpCookie, err := s.httpCookie(cookie)
	if err != nil {
		writeCompleteError(w, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.SetCookie(w, httpCookie)
	w.Header().Set("Location", s.PostLoginURL)
	w.WriteHeader(http.StatusSeeOther)
}

type exchangeResponse struct {
	LaunchURL string    `json:"launch_url"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s Server) exchangeReady() error {
	if s.Verifier == nil || s.ReplayStore == nil || s.CodeStore == nil || s.CompleteURL == "" {
		return ErrServerMisconfigured
	}
	return nil
}

func (s Server) loginCodeTTL() time.Duration {
	if s.LoginCodeTTL > 0 {
		return s.LoginCodeTTL
	}
	return 30 * time.Second
}

func (s Server) webSessionTTL() time.Duration {
	if s.WebSessionTTL > 0 {
		return s.WebSessionTTL
	}
	return 30 * time.Minute
}

func (s Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s Server) httpCookie(cookie SessionCookie) (*http.Cookie, error) {
	if cookie.Name == "" || cookie.Value == "" {
		return nil, ErrSessionCookieInvalid
	}
	path := cookie.Path
	if path == "" {
		path = "/"
	}
	sameSite := cookie.SameSite
	if sameSite == 0 || sameSite == http.SameSiteDefaultMode || sameSite == http.SameSiteNoneMode {
		sameSite = http.SameSiteLaxMode
	}
	return &http.Cookie{
		Name:     cookie.Name,
		Value:    cookie.Value,
		Path:     path,
		Domain:   cookie.Domain,
		Expires:  cookie.Expires,
		MaxAge:   cookie.MaxAge,
		Secure:   cookie.Secure || s.SecureCookies,
		HttpOnly: true,
		SameSite: sameSite,
	}, nil
}

func bearerToken(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", false
	}
	return token, true
}

func rejectTokenOutsideAuthorization(r *http.Request) error {
	for _, key := range tokenParameterNames {
		if r.URL.Query().Has(key) {
			return ErrBootstrapInvalid
		}
	}
	if r.Body == nil {
		return nil
	}

	var body map[string]json.RawMessage
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&body); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	for _, key := range tokenParameterNames {
		if _, exists := body[key]; exists {
			return ErrBootstrapInvalid
		}
	}
	return nil
}

var tokenParameterNames = []string{"token", "access_token", "jwt", "bootstrap_token"}

func addCodeToURL(rawURL, code string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set("code", code)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func writeExchangeError(w http.ResponseWriter, status int) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "browser session exchange failed", status)
}

func writeCompleteError(w http.ResponseWriter, status int) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Error(w, "browser session complete failed", status)
}
