package talos

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/trknhr/credlease/internal/clerr"
	"github.com/trknhr/credlease/internal/issuer"
)

const (
	parentKeyPath = "/v2alpha1/admin/issuedApiKeys"
	derivePath    = "/v2alpha1/admin/apiKeys:derive"
	jwksPath      = "/v2alpha1/derivedKeys/jwks.json"
)

type Client struct {
	baseURL string
	http    *http.Client
}

type ParentKeyRequest struct {
	Profile        string
	InstallationID string
	Scopes         []string
	TTL            time.Duration
}

type ParentKey struct {
	ID     string
	Secret string
}

func NewClient(baseURL string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    httpClient,
	}
}

func (c *Client) IssueParentKey(ctx context.Context, request ParentKeyRequest) (ParentKey, error) {
	if request.Profile == "" {
		return ParentKey{}, clerr.New(clerr.ConfigInvalid, "profile is required")
	}
	if request.InstallationID == "" {
		return ParentKey{}, clerr.New(clerr.ConfigInvalid, "installation id is required")
	}
	if len(request.Scopes) == 0 {
		return ParentKey{}, clerr.New(clerr.ConfigInvalid, "parent key scopes are required")
	}
	if request.TTL <= 0 {
		return ParentKey{}, clerr.New(clerr.ConfigInvalid, "parent key ttl must be positive")
	}

	var response struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	body := map[string]any{
		"name":     "credlease:" + request.Profile,
		"actor_id": "credlease-local:" + request.InstallationID,
		"scopes":   append([]string(nil), request.Scopes...),
		"ttl":      request.TTL.String(),
		"metadata": map[string]string{
			"credlease_profile": request.Profile,
		},
	}
	if err := c.postJSON(ctx, parentKeyPath, body, &response); err != nil {
		return ParentKey{}, err
	}
	if response.Secret == "" {
		return ParentKey{}, clerr.New(clerr.IssueFailed, "talos parent key response missing secret")
	}
	return ParentKey{ID: response.ID, Secret: response.Secret}, nil
}

func (c *Client) DeriveJWT(ctx context.Context, parentKey string, grant issuer.Grant) (issuer.Credential, error) {
	if parentKey == "" {
		return issuer.Credential{}, clerr.New(clerr.ParentKeyMissing, "parent key is required")
	}
	if grant.Profile == "" {
		return issuer.Credential{}, clerr.New(clerr.ConfigInvalid, "grant profile is required")
	}
	if len(grant.Scopes) == 0 {
		return issuer.Credential{}, clerr.New(clerr.ConfigInvalid, "grant scopes are required")
	}
	if grant.TTL <= 0 {
		return issuer.Credential{}, clerr.New(clerr.ConfigInvalid, "grant ttl must be positive")
	}
	if err := validateCustomClaims(grant.Claims); err != nil {
		return issuer.Credential{}, err
	}

	var response struct {
		Token struct {
			Token string `json:"token"`
		} `json:"token"`
	}
	body := map[string]any{
		"credential":    parentKey,
		"algorithm":     "TOKEN_ALGORITHM_JWT",
		"ttl":           grant.TTL.String(),
		"scopes":        append([]string(nil), grant.Scopes...),
		"custom_claims": cloneClaims(grant.Claims),
	}
	if err := c.postJSON(ctx, derivePath, body, &response); err != nil {
		return issuer.Credential{}, err
	}
	if response.Token.Token == "" {
		return issuer.Credential{}, clerr.New(clerr.IssueFailed, "talos derive response missing token")
	}
	return issuer.Credential{
		AccessToken: response.Token.Token,
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(grant.TTL),
		Scopes:      append([]string(nil), grant.Scopes...),
	}, nil
}

func (c *Client) JWKS(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+jwksPath, nil)
	if err != nil {
		return nil, clerr.Wrap(clerr.IssueFailed, "create talos jwks request", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, clerr.Wrap(clerr.IssueFailed, "talos jwks request failed", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		drain(resp.Body)
		return nil, clerr.New(clerr.IssueFailed, fmt.Sprintf("talos jwks request returned HTTP %d", resp.StatusCode))
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, clerr.Wrap(clerr.IssueFailed, "read talos jwks response", err)
	}
	return raw, nil
}

func (c *Client) postJSON(ctx context.Context, path string, body any, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "marshal talos request", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(raw))
	if err != nil {
		return clerr.Wrap(clerr.IssueFailed, "create talos request", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return clerr.Wrap(clerr.IssueFailed, "talos request failed", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		drain(resp.Body)
		return clerr.New(clerr.IssueFailed, fmt.Sprintf("talos request returned HTTP %d", resp.StatusCode))
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return clerr.Wrap(clerr.IssueFailed, "decode talos response", err)
	}
	return nil
}

func validateCustomClaims(claims map[string]any) error {
	for claim := range claims {
		if reservedJWTClaims[claim] {
			return clerr.New(clerr.ConfigInvalid, "reserved jwt claim is not allowed in custom claims")
		}
	}
	return nil
}

var reservedJWTClaims = map[string]bool{
	"iss": true,
	"sub": true,
	"aud": true,
	"exp": true,
	"nbf": true,
	"iat": true,
	"jti": true,
}

func cloneClaims(claims map[string]any) map[string]any {
	if len(claims) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(claims))
	for key, value := range claims {
		out[key] = value
	}
	return out
}

func drain(body io.Reader) {
	_, _ = io.Copy(io.Discard, body)
}
