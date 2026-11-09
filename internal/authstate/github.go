package authstate

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/trknhr/envvault/internal/keyring"
)

// GitHub owns the host-side OAuth exchange. Endpoints are fixed, never taken
// from imported authentication documents or sandbox requests.
type GitHub struct {
	HTTP *http.Client
	Now  func() time.Time
}
type Device struct {
	Code            string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURL string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

func (Device) String() string   { return "GitHub device authorization [REDACTED]" }
func (Device) GoString() string { return "GitHub device authorization [REDACTED]" }

type oauthResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_token_expires_in"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
}

func (g GitHub) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}
func (g GitHub) client() *http.Client {
	c := http.Client{Timeout: 30 * time.Second}
	if g.HTTP != nil {
		c = *g.HTTP
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

func (g GitHub) post(ctx context.Context, endpoint string, form url.Values, result any) error {
	r, err := http.NewRequestWithContext(ctx, "POST", "https://github.com"+endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return errors.New("GitHub authentication request failed")
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Accept", "application/json")
	response, err := g.client().Do(r)
	if err != nil {
		return errors.New("GitHub authentication service unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return errors.New("GitHub authentication was rejected")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	defer keyring.Zero(body)
	if err != nil || len(body) > 65536 || json.Unmarshal(body, result) != nil {
		return errors.New("invalid GitHub authentication response")
	}
	return nil
}

func (g GitHub) Begin(ctx context.Context, clientID string, scopes []string) (Device, error) {
	if clientID == "" {
		return Device{}, errors.New("GitHub OAuth client ID required")
	}
	var device Device
	if err := g.post(ctx, "/login/device/code", url.Values{"client_id": {clientID}, "scope": {strings.Join(scopes, " ")}}, &device); err != nil {
		return Device{}, err
	}
	if device.Code == "" || device.UserCode == "" || device.VerificationURL != "https://github.com/login/device" || device.ExpiresIn <= 0 || device.ExpiresIn > 1800 || device.Interval < 1 || device.Interval > 60 {
		return Device{}, errors.New("invalid GitHub device authorization")
	}
	return device, nil
}

func (g GitHub) Wait(ctx context.Context, clientID string, device Device) ([]byte, error) {
	if device.Interval < 1 || device.ExpiresIn < 1 {
		return nil, errors.New("invalid GitHub device authorization")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(device.ExpiresIn)*time.Second)
	defer cancel()
	interval := time.Duration(device.Interval) * time.Second
	for {
		select {
		case <-ctx.Done():
			return nil, errors.New("GitHub device authorization expired or cancelled")
		case <-time.After(interval):
		}
		var token oauthResponse
		err := g.post(ctx, "/login/oauth/access_token", url.Values{"client_id": {clientID}, "device_code": {device.Code}, "grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}}, &token)
		if err != nil {
			return nil, err
		}
		switch token.Error {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			continue
		case "":
			return g.document(token)
		default:
			return nil, errors.New("GitHub device authorization failed or was denied")
		}
	}
}

func (g GitHub) document(token oauthResponse) ([]byte, error) {
	if token.Error != "" || token.AccessToken == "" {
		return nil, errors.New("GitHub authentication requires sign-in")
	}
	doc := map[string]any{"access_token": token.AccessToken}
	if token.RefreshToken != "" {
		doc["refresh_token"] = token.RefreshToken
	}
	if token.ExpiresIn > 0 {
		doc["expires_at"] = g.now().Add(time.Duration(token.ExpiresIn) * time.Second).UTC().Format(time.RFC3339)
	}
	if token.RefreshExpiresIn > 0 {
		doc["refresh_expires_at"] = g.now().Add(time.Duration(token.RefreshExpiresIn) * time.Second).UTC().Format(time.RFC3339)
	}
	if token.Scope != "" {
		doc["scope"] = token.Scope
	}
	return json.Marshal(doc)
}

func (g GitHub) Refresh(ctx context.Context, metadata Metadata, document []byte) ([]byte, error) {
	if metadata.ClientID == "" || metadata.RefreshField == "" {
		return nil, errors.New("authentication expired; sign in on the host")
	}
	refresh, err := Field(document, metadata.RefreshField)
	if err != nil {
		return nil, errors.New("authentication requires host sign-in")
	}
	value, ok := refresh.(string)
	if !ok || value == "" {
		return nil, errors.New("authentication requires host sign-in")
	}
	var token oauthResponse
	if err := g.post(ctx, "/login/oauth/access_token", url.Values{"client_id": {metadata.ClientID}, "grant_type": {"refresh_token"}, "refresh_token": {value}}, &token); err != nil {
		return nil, err
	}
	if token.Error != "" || token.RefreshToken == "" || token.ExpiresIn <= 0 {
		return nil, errors.New("authentication refresh failed; sign in on the host")
	}
	return g.document(token)
}
