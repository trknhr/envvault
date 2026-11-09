package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/connection/keyringprovider"
	"github.com/trknhr/envvault/internal/keyring"
)

type agentCountingStore struct {
	keyring.Store
	reads atomic.Int32
	err   error
}

func (s *agentCountingStore) Get(ctx context.Context, key keyring.Key) ([]byte, error) {
	s.reads.Add(1)
	if s.err != nil {
		return nil, s.err
	}
	return s.Store.Get(ctx, key)
}

func testCredentialBinding() agentCredential {
	return agentCredential{Environment: "SERVICE_TOKEN", Reference: "envvault://sandbox/test", Host: "example.com", Methods: []string{"GET"}, Paths: []string{"/api", "/stream"}}
}

func TestAgentCredentialsAreScopedAndRotateOnHost(t *testing.T) {
	var arrivals atomic.Int32
	var expected atomic.Value
	expected.Store("first-canary")
	proxy, client, filename := testAgentProxyHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrivals.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+expected.Load().(string) {
			http.Error(w, "credential mismatch", 400)
			return
		}
		io.WriteString(w, "accepted")
	}))
	store := &agentCountingStore{Store: keyring.NewMemoryStore()}
	store.Put(context.Background(), keyring.CredentialValue("sandbox/test"), []byte("first-canary"))
	proxy.credentials = keyringprovider.Provider{Store: store}
	policy := agentPolicy{HTTPSHosts: []string{"example.com"}, Credentials: []agentCredential{testCredentialBinding()}}
	if err := writeAgentPolicy(filename, policy); err != nil {
		t.Fatal(err)
	}
	request := func(method, path, authorization string, code int) {
		t.Helper()
		req, _ := http.NewRequest(method, "https://example.com"+path, nil)
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		if response.StatusCode != code || strings.Contains(string(body), "canary") {
			t.Fatalf("request was not safely handled: status %d", response.StatusCode)
		}
	}
	request("POST", "/api", "Bearer envvault://sandbox/test", 403)
	request("GET", "/elsewhere", "Bearer envvault://sandbox/test", 403)
	request("GET", "/%61pi", "Bearer envvault://sandbox/test", 403)
	request("GET", "/api", "Bearer envvault://other/test", 401)
	request("GET", "/api", "Bearer first-canary", 401)
	request("GET", "/api", "", 401)
	if store.reads.Load() != 0 || arrivals.Load() != 0 {
		t.Fatal("blocked request acquired a credential or reached upstream")
	}
	request("GET", "/api", "Bearer envvault://sandbox/test", 200)
	expected.Store("rotated-canary")
	store.Put(context.Background(), keyring.CredentialValue("sandbox/test"), []byte("rotated-canary"))
	request("GET", "/api", "Bearer envvault://sandbox/test", 200)
	if store.reads.Load() != 2 || arrivals.Load() != 2 {
		t.Fatal("credential was not acquired afresh for each permitted request")
	}
	policy.Credentials = nil
	if err := writeAgentPolicy(filename, policy); err != nil {
		t.Fatal(err)
	}
	request("GET", "/api", "Bearer envvault://sandbox/test", 401)
	if store.reads.Load() != 2 || arrivals.Load() != 2 {
		t.Fatal("removed credential binding still resolved")
	}
}

func TestAgentCredentialErrorsAreRedacted(t *testing.T) {
	proxy, client, filename := testAgentProxy(t)
	proxy.credentials = keyringprovider.Provider{Store: &agentCountingStore{err: errors.New("private-canary-backend-detail")}}
	if err := writeAgentPolicy(filename, agentPolicy{HTTPSHosts: []string{"example.com"}, Credentials: []agentCredential{testCredentialBinding()}}); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", "https://example.com/api", nil)
	req.Header.Set("Authorization", "Bearer envvault://sandbox/test")
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != 503 || strings.Contains(string(body), "canary") {
		t.Fatal("credential failure was not safely redacted")
	}
}

func TestAgentCredentialScopeChangeRevokesExistingStream(t *testing.T) {
	proxy, client, filename := testAgentProxy(t)
	store := keyring.NewMemoryStore()
	store.Put(context.Background(), keyring.CredentialValue("sandbox/test"), []byte("stream-canary"))
	proxy.credentials = keyringprovider.Provider{Store: store}
	policy := agentPolicy{HTTPSHosts: []string{"example.com"}, Credentials: []agentCredential{testCredentialBinding()}}
	writeAgentPolicy(filename, policy)
	req, _ := http.NewRequest("GET", "https://example.com/stream", nil)
	req.Header.Set("Authorization", "Bearer envvault://sandbox/test")
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("credential stream did not start")
	}
	policy.Credentials[0].Paths = []string{"/api"}
	if err := writeAgentPolicy(filename, policy); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { io.Copy(io.Discard, response.Body); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("credential stream survived scope revocation")
	}
}

func TestAgentPolicyRejectsUnsafeCredentialBindings(t *testing.T) {
	for _, mutate := range []func(*agentCredential){
		func(c *agentCredential) { c.Reference = "raw-secret" },
		func(c *agentCredential) { c.Reference += "/token" },
		func(c *agentCredential) { c.Environment = "LD_PRELOAD" },
		func(c *agentCredential) { c.Host = "*.example.com" },
		func(c *agentCredential) { c.Header = "Host" },
		func(c *agentCredential) { c.Methods = nil },
		func(c *agentCredential) { c.Paths = []string{"/api/*"} },
		func(c *agentCredential) { c.Paths = []string{"/api/../admin"} },
	} {
		binding := testCredentialBinding()
		mutate(&binding)
		if err := validateAgentCredentials([]agentCredential{binding}); err == nil {
			t.Fatal("unsafe credential binding was accepted")
		}
	}
	filename := t.TempDir() + "/policy.json"
	for _, body := range []string{`{"https_hosts":[],"max_processes":-1}`, `{"max_processes":0}`, `{"max_processes":8193}`, `{"credentials":[{"value":"raw-canary"}]}`, `{"native_auth_hosts":["*.github.com"]}`} {
		os.WriteFile(filename, []byte(body), 0600)
		if _, err := readAgentPolicy(filename); err == nil {
			t.Fatal("unsafe policy was accepted")
		}
	}
}
