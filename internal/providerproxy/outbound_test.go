package providerproxy_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/projectbinding"
	"github.com/trknhr/envvault/internal/providerproxy"
)

func TestOutboundResolverPreservesHTTPSURLAndInjectsCredential(t *testing.T) {
	ctx := context.Background()
	const upstreamSecret = "ENVVAULT_OUTBOUND_SECRET_DO_NOT_LOG"
	const credentialReference = "envvault://openai-key/outbound"
	var providerMu sync.Mutex
	var calls int
	var providerAuth, providerPath, providerQuery, providerBody string
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		providerMu.Lock()
		calls++
		providerAuth = r.Header.Get("Authorization")
		providerPath = r.URL.Path
		providerQuery = r.URL.RawQuery
		providerBody = string(body)
		providerMu.Unlock()
		w.Header().Set("X-Provider", "reached")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer target.Close()

	providerProfile := providerProfile(target.URL + "/v1")
	providerProfile.CredentialName = "openai-key/outbound"
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(ctx, keyring.CredentialValue(providerProfile.CredentialName), []byte(upstreamSecret)); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	resolver := providerproxy.OutboundResolver{
		Profiles: testProfiles{providerProfile.Name: providerProfile},
		Secrets:  secrets,
		HTTP:     target.Client(),
	}
	lease, err := resolver.Open(ctx, []string{providerProfile.Name}, projectbinding.Identity{}, "sandbox-test")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = lease.Close(closeCtx)
	})

	config := lease.ClientConfig()
	if config.ProxyURL == "" || len(config.CACertificatePEM) == 0 {
		t.Fatal("ClientConfig() did not return the proxy capability and public CA")
	}
	if len(config.CredentialReferences) != 1 || config.CredentialReferences[0] != credentialReference {
		t.Fatalf("ClientConfig() credential references = %#v", config.CredentialReferences)
	}
	if strings.Contains(config.ProxyURL, upstreamSecret) || strings.Contains(string(config.CACertificatePEM), upstreamSecret) {
		t.Fatal("ClientConfig() exposed the upstream credential")
	}
	if got := fmt.Sprintf("%v %#v", config, config); strings.Contains(got, config.ProxyURL) || strings.Contains(got, upstreamSecret) {
		t.Fatalf("formatted client config was not redacted: %q", got)
	}

	proxyURL, err := url.Parse(config.ProxyURL)
	if err != nil {
		t.Fatalf("Parse(proxy URL) error = %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(config.CACertificatePEM) {
		t.Fatal("ClientConfig() CA certificate is not valid PEM")
	}
	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
		},
	}}
	unauthorizedProxy := *proxyURL
	unauthorizedProxy.User = nil
	unauthorizedClient := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(&unauthorizedProxy),
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
		},
	}}
	unauthorizedRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, target.URL+"/v1/chat/completions", nil)
	if err != nil {
		t.Fatalf("NewRequest(unauthorized) error = %v", err)
	}
	unauthorizedResponse, unauthorizedErr := unauthorizedClient.Do(unauthorizedRequest)
	if unauthorizedResponse != nil {
		_ = unauthorizedResponse.Body.Close()
	}
	if unauthorizedErr == nil && unauthorizedResponse.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("unauthorized proxy status = %d, want 407", unauthorizedResponse.StatusCode)
	}
	if unauthorizedErr != nil && strings.Contains(unauthorizedErr.Error(), upstreamSecret) {
		t.Fatalf("unauthorized proxy error leaked upstream credential: %v", unauthorizedErr)
	}

	for _, requestCase := range []struct {
		method        string
		path          string
		authorization string
		body          string
		want          int
	}{
		{method: http.MethodGet, path: "/v1/chat/completions", authorization: "Bearer " + credentialReference, want: http.StatusForbidden},
		{method: http.MethodPost, path: "/v1/not-allowed", authorization: "Bearer " + credentialReference, want: http.StatusForbidden},
		{method: http.MethodPost, path: "/v1/ignored/../chat/completions", authorization: "Bearer " + credentialReference, want: http.StatusBadRequest},
		{method: http.MethodPost, path: "/v1/chat/completions", want: http.StatusUnauthorized},
		{method: http.MethodPost, path: "/v1/chat/completions", authorization: "Bearer envvault://other-key/outbound", want: http.StatusUnauthorized},
		{method: http.MethodPost, path: "/v1/chat/completions", authorization: "Bearer " + upstreamSecret, want: http.StatusUnauthorized},
		{method: http.MethodPost, path: "/v1/chat/completions?model=test", authorization: "Bearer " + credentialReference, body: `{"credential":"envvault://openai-key/outbound"}`, want: http.StatusCreated},
	} {
		request, err := http.NewRequestWithContext(ctx, requestCase.method, target.URL+requestCase.path, strings.NewReader(requestCase.body))
		if err != nil {
			t.Fatalf("NewRequest() error = %v", err)
		}
		if requestCase.authorization != "" {
			request.Header.Set("Authorization", requestCase.authorization)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("Do(%s %s) error = %v", requestCase.method, requestCase.path, err)
		}
		_ = response.Body.Close()
		if response.StatusCode != requestCase.want {
			t.Fatalf("Do(%s %s) status = %d, want %d", requestCase.method, requestCase.path, response.StatusCode, requestCase.want)
		}
	}

	providerMu.Lock()
	gotCalls := calls
	gotAuth := providerAuth
	gotPath := providerPath
	gotQuery := providerQuery
	gotBody := providerBody
	providerMu.Unlock()
	if gotCalls != 1 || gotAuth != "Bearer "+upstreamSecret || gotPath != "/v1/chat/completions" || gotQuery != "model=test" || gotBody != `{"credential":"envvault://openai-key/outbound"}` {
		t.Fatalf("provider request mismatch (calls=%d auth_ok=%t path=%q query=%q body=%q)", gotCalls, gotAuth == "Bearer "+upstreamSecret, gotPath, gotQuery, gotBody)
	}

	endpoint := lease.Endpoint().Address
	closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := lease.Close(closeCtx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := lease.ClientConfig(); got.ProxyURL != "" || len(got.CACertificatePEM) != 0 || len(got.CredentialReferences) != 0 {
		t.Fatal("ClientConfig() remained available after Close")
	}
	connection, err := net.DialTimeout("tcp", endpoint, 100*time.Millisecond)
	if err == nil {
		_ = connection.Close()
		t.Fatal("outbound proxy still accepted connections after Close")
	}
}

func TestOutboundResolverForwardsConfiguredLoopbackHTTPOnlyThroughAllowedRoute(t *testing.T) {
	ctx := context.Background()
	const upstreamSecret = "loopback-provider-secret"
	var calls int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer "+upstreamSecret {
			t.Error("provider did not receive the configured credential")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	p := providerProfile(target.URL + "/v1")
	p.CredentialName = "loopback/outbound"
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(ctx, keyring.CredentialValue(p.CredentialName), []byte(upstreamSecret)); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	lease, err := (providerproxy.OutboundResolver{
		Profiles: testProfiles{p.Name: p},
		Secrets:  secrets,
	}).Open(ctx, []string{p.Name}, projectbinding.Identity{}, "sandbox-test")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = lease.Close(context.Background()) }()

	proxyURL, err := url.Parse(lease.ClientConfig().ProxyURL)
	if err != nil {
		t.Fatalf("Parse(proxy URL) error = %v", err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	for _, requestCase := range []struct {
		path string
		want int
	}{
		{path: "/outside-base", want: http.StatusForbidden},
		{path: "/v1/chat/completions", want: http.StatusNoContent},
	} {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.URL+requestCase.path, nil)
		if err != nil {
			t.Fatalf("NewRequest() error = %v", err)
		}
		request.Header.Set("Authorization", "Bearer envvault://loopback/outbound")
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("Do(%s) error = %v", requestCase.path, err)
		}
		_ = response.Body.Close()
		if response.StatusCode != requestCase.want {
			t.Fatalf("Do(%s) status = %d, want %d", requestCase.path, response.StatusCode, requestCase.want)
		}
	}
	if calls != 1 {
		t.Fatalf("provider calls = %d, want 1", calls)
	}
}
