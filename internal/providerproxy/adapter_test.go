package providerproxy_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/connection"
	"github.com/trknhr/envvault/internal/connection/compatprofile"
	"github.com/trknhr/envvault/internal/connection/keyringprovider"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/providerproxy"
)

func TestHTTPAdapterStartsExistingProxyBehaviorAndClosesLease(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	var providerMu sync.Mutex
	var providerAuth, providerPath string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerMu.Lock()
		providerAuth = r.Header.Get("Authorization")
		providerPath = r.URL.Path
		providerMu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "created")
	}))
	defer target.Close()

	p := providerProfile(target.URL + "/v1")
	p.CredentialName = "openai-key/dev"
	policy, err := compatprofile.FromProviderProxyProfile(p)
	if err != nil {
		t.Fatalf("FromProviderProxyProfile() error = %v", err)
	}
	store := keyring.NewMemoryStore()
	if err := store.Put(ctx, keyring.CredentialValue("openai-key/dev"), []byte("secret-canary")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	credentials := keyringprovider.Provider{Store: store, Now: func() time.Time { return now }}
	grant := adapterGrant(policy, now)
	adapter := providerproxy.HTTPAdapter{HTTP: target.Client(), Now: func() time.Time { return now }}

	rawLease, err := adapter.Start(ctx, connection.AdapterStartRequest{
		Policy:      policy,
		Grant:       grant,
		Credentials: credentials,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	lease, ok := rawLease.(*providerproxy.HTTPAdapterLease)
	if !ok {
		t.Fatalf("lease type = %T", rawLease)
	}
	if lease.Endpoint().Network != "tcp" || lease.Endpoint().Address == "" {
		t.Fatalf("Endpoint() = %#v", lease.Endpoint())
	}
	if lease.ExpiresAt() != grant.ExpiresAt {
		t.Fatalf("ExpiresAt() = %s, want %s", lease.ExpiresAt(), grant.ExpiresAt)
	}
	if !strings.HasPrefix(lease.Token(), "envvault-local-") {
		t.Fatal("Token() did not return a local capability")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", lease, lease), "secret-canary") {
		t.Fatal("formatted adapter lease leaked upstream credential")
	}

	req, err := http.NewRequest(http.MethodPost, lease.BaseURL()+"/chat/completions", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+lease.Token())
	resp, err := target.Client().Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("allowed status = %d", resp.StatusCode)
	}
	providerMu.Lock()
	authOK := providerAuth == "Bearer secret-canary"
	pathOK := providerPath == "/v1/chat/completions"
	providerMu.Unlock()
	if !authOK || !pathOK {
		t.Fatalf("provider request mismatch (auth_ok=%t, path_ok=%t)", authOK, pathOK)
	}

	denied, err := http.NewRequest(http.MethodGet, lease.BaseURL()+"/chat/completions", nil)
	if err != nil {
		t.Fatalf("NewRequest(denied) error = %v", err)
	}
	denied.Header.Set("Authorization", "Bearer "+lease.Token())
	deniedResponse, err := target.Client().Do(denied)
	if err != nil {
		t.Fatalf("Do(denied) error = %v", err)
	}
	_ = deniedResponse.Body.Close()
	if deniedResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("denied status = %d", deniedResponse.StatusCode)
	}

	now = grant.ExpiresAt
	expired, err := http.NewRequest(http.MethodPost, lease.BaseURL()+"/chat/completions", nil)
	if err != nil {
		t.Fatalf("NewRequest(expired) error = %v", err)
	}
	expired.Header.Set("Authorization", "Bearer "+lease.Token())
	expiredResponse, err := target.Client().Do(expired)
	if err != nil {
		t.Fatalf("Do(expired) error = %v", err)
	}
	_ = expiredResponse.Body.Close()
	if expiredResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired status = %d", expiredResponse.StatusCode)
	}

	endpoint := lease.Endpoint().Address
	if err := lease.Close(ctx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if lease.Token() != "" {
		t.Fatal("Token() remained available after Close")
	}
	connection, err := net.DialTimeout("tcp", endpoint, 50*time.Millisecond)
	if err == nil {
		_ = connection.Close()
		t.Fatalf("adapter endpoint %s still accepts connections", endpoint)
	}
}

func adapterGrant(policy connection.Policy, now time.Time) connection.Grant {
	return connection.Grant{
		ID:             "grant-1",
		SessionID:      "session-1",
		SubjectID:      "subject-1",
		PolicyName:     policy.Name,
		PolicyRevision: "revision-1",
		Protocol:       policy.Protocol.Type,
		Destination:    policy.Destination,
		IssuedAt:       now,
		ExpiresAt:      now.Add(policy.Limits.SessionTTL),
		MaxConnections: 8,
	}
}
