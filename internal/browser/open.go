package browser

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/trknhr/envvault/internal/audit"
	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/issuer"
	"github.com/trknhr/envvault/internal/profile"
	"github.com/trknhr/envvault/internal/projectbinding"
)

type Issuer interface {
	Issue(ctx context.Context, grant issuer.Grant) (issuer.Credential, error)
}

type Opener interface {
	Open(ctx context.Context, rawURL string, browser string) error
}

type Client struct {
	HTTP   *http.Client
	Issuer Issuer
	Opener Opener
	Audit  audit.Recorder
}

type OpenRequest struct {
	Profile         profile.Profile
	Browser         string
	PrintURL        bool
	ProjectIdentity projectbinding.Identity
}

type OpenResult struct {
	LaunchURL string
	ExpiresAt time.Time
}

func (c Client) Open(ctx context.Context, request OpenRequest) (OpenResult, error) {
	p := request.Profile
	if p.Kind != profile.KindBrowserSession {
		return OpenResult{}, clerr.New(clerr.ProfileKindMismatch, p.Name)
	}
	if err := p.Validate(); err != nil {
		return OpenResult{}, err
	}
	sessionID, err := newSessionID()
	if err != nil {
		return OpenResult{}, err
	}

	claims := map[string]any{
		"envvault_profile":    p.Name,
		"envvault_resource":   p.Resource,
		"envvault_client":     "envvault-cli",
		"envvault_session_id": sessionID,
		"envvault_purpose":    "browser-bootstrap",
	}
	if request.ProjectIdentity.Root != "" {
		projectID, err := projectbinding.PathHash(request.ProjectIdentity.Root)
		if err != nil {
			return OpenResult{}, err
		}
		claims["envvault_project_id"] = projectID
	}

	credential, err := c.Issuer.Issue(ctx, issuer.Grant{
		Profile:  p.Name,
		Resource: p.Resource,
		Scopes:   append([]string(nil), p.Scopes...),
		TTL:      p.BootstrapTokenTTL,
		Claims:   claims,
	})
	if err != nil {
		_ = c.recordBrowserSessionRequested(ctx, p, sessionID, audit.ResultFailure, err)
		return OpenResult{}, err
	}

	response, err := c.exchange(ctx, p, credential.AccessToken)
	if err != nil {
		_ = c.recordBrowserSessionRequested(ctx, p, sessionID, audit.ResultFailure, err)
		return OpenResult{}, err
	}
	if err := p.ValidateLaunchURL(response.LaunchURL); err != nil {
		_ = c.recordBrowserSessionRequested(ctx, p, sessionID, audit.ResultFailure, err)
		return OpenResult{}, err
	}
	if !request.PrintURL {
		if c.Opener == nil {
			err := clerr.New(clerr.BrowserExchangeFailed, "browser opener is not configured")
			_ = c.recordBrowserSessionRequested(ctx, p, sessionID, audit.ResultFailure, err)
			return OpenResult{}, err
		}
		if err := c.Opener.Open(ctx, response.LaunchURL, request.Browser); err != nil {
			wrapped := clerr.Wrap(clerr.BrowserExchangeFailed, "open browser", err)
			_ = c.recordBrowserSessionRequested(ctx, p, sessionID, audit.ResultFailure, wrapped)
			return OpenResult{}, wrapped
		}
	}
	if err := c.recordBrowserSessionRequested(ctx, p, sessionID, audit.ResultSuccess, nil); err != nil {
		return OpenResult{}, err
	}
	return OpenResult{LaunchURL: response.LaunchURL, ExpiresAt: response.ExpiresAt}, nil
}

func (c Client) recordBrowserSessionRequested(ctx context.Context, p profile.Profile, sessionID string, result string, cause error) error {
	if c.Audit == nil {
		return nil
	}
	event := audit.Event{
		Event:     audit.EventBrowserSessionRequested,
		Profile:   p.Name,
		SessionID: sessionID,
		Result:    result,
	}
	if code, ok := clerr.CodeOf(cause); ok {
		event.ErrorCode = code
	}
	return c.Audit.Record(ctx, event)
}

type exchangeResponse struct {
	LaunchURL string    `json:"launch_url"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (c Client) exchange(ctx context.Context, p profile.Profile, token string) (exchangeResponse, error) {
	body := map[string]any{
		"requested_session_ttl_seconds": int64(p.WebSessionTTL.Seconds()),
		"client":                        "envvault-cli",
		"client_version":                "0.1.0",
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return exchangeResponse{}, clerr.Wrap(clerr.BrowserExchangeFailed, "marshal browser exchange request", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.ExchangeURL, bytes.NewReader(raw))
	if err != nil {
		return exchangeResponse{}, clerr.Wrap(clerr.BrowserExchangeFailed, "create browser exchange request", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "no-store")

	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return exchangeResponse{}, clerr.Wrap(clerr.BrowserExchangeFailed, "browser exchange request failed", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		drain(resp.Body)
		return exchangeResponse{}, clerr.New(clerr.BrowserExchangeFailed, fmt.Sprintf("browser exchange returned HTTP %d", resp.StatusCode))
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		drain(resp.Body)
		return exchangeResponse{}, clerr.New(clerr.BrowserExchangeFailed, "browser exchange response must use Cache-Control: no-store")
	}

	var parsed exchangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return exchangeResponse{}, clerr.Wrap(clerr.BrowserExchangeFailed, "decode browser exchange response", err)
	}
	if parsed.LaunchURL == "" {
		return exchangeResponse{}, clerr.New(clerr.BrowserExchangeFailed, "browser exchange response missing launch_url")
	}
	return parsed, nil
}

func drain(body io.Reader) {
	_, _ = io.Copy(io.Discard, body)
}

func newSessionID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", clerr.Wrap(clerr.IssueFailed, "generate session id", err)
	}
	return "hex:" + hex.EncodeToString(bytes[:]), nil
}
