package main

import (
	"context"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/connection/keyringprovider"
	"github.com/trknhr/envvault/internal/keyring"
)

func TestAgentNativeAuthPermissionDoesNotResolveOrBypassReferenceRules(t *testing.T) {
	vault, _ := testVaultConfig(t)
	var arrivals atomic.Int32
	proxy, client, filename := testAgentProxyVaultHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrivals.Add(1)
		auth := r.Header.Get("Authorization")
		if auth != "token native-canary" && auth != "Bearer broker-canary" {
			http.Error(w, "unexpected credential", 400)
			return
		}
		io.WriteString(w, "accepted")
	}), vault)
	store := &agentCountingStore{Store: keyring.NewMemoryStore()}
	store.Put(context.Background(), keyring.CredentialValue("sandbox/first"), []byte("broker-canary"))
	proxy.credentials = keyringprovider.Provider{Store: store}
	request := func(path, authorization string, expected int) {
		t.Helper()
		r, _ := http.NewRequest("GET", "https://example.com"+path, nil)
		r.Header.Set("Authorization", authorization)
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != expected {
			t.Fatalf("native permission was not scoped: %d", response.StatusCode)
		}
	}
	request("/outside", "token native-canary", 403)
	policy := agentPolicy{HTTPSHosts: []string{"example.com"}, EnvVault: true, NativeAuthHosts: []string{"example.com"}}
	if err := writeAgentPolicy(filename, policy); err != nil {
		t.Fatal(err)
	}
	request("/outside", "token native-canary", 200)
	request("/outside", "token envvault://sandbox/first", 403)
	request("/v1/api", "token envvault://sandbox/missing", 403)
	request("/v1/api", "token envvault://sandbox/first", 200)
	if store.reads.Load() != 1 || arrivals.Load() != 2 {
		t.Fatal("native permission acquired or released an unexpected host credential")
	}
	policy.NativeAuthHosts = nil
	if err := writeAgentPolicy(filename, policy); err != nil {
		t.Fatal(err)
	}
	request("/outside", "token native-canary", 403)
	policy.NativeAuthHosts, policy.HTTPSHosts = []string{"example.com"}, nil
	if err := writeAgentPolicy(filename, policy); err != nil {
		t.Fatal(err)
	}
	r, _ := http.NewRequest("GET", "https://example.com/outside", nil)
	r.Header.Set("Authorization", "token native-canary")
	if response, err := client.Do(r); err == nil {
		response.Body.Close()
		if response.StatusCode != 403 {
			t.Fatal("native auth bypassed network policy")
		}
	}
	if store.reads.Load() != 1 || arrivals.Load() != 2 {
		t.Fatal("revoked native access reached upstream")
	}
}

func TestAgentNativeAuthRevocationClosesExistingStream(t *testing.T) {
	vault, _ := testVaultConfig(t)
	_, client, filename := testAgentProxyVaultHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ready\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}), vault)
	policy := agentPolicy{HTTPSHosts: []string{"example.com"}, EnvVault: true, NativeAuthHosts: []string{"example.com"}}
	if err := writeAgentPolicy(filename, policy); err != nil {
		t.Fatal(err)
	}
	r, _ := http.NewRequest("GET", "https://example.com/outside", nil)
	r.Header.Set("Authorization", "token native-canary")
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("native stream did not open")
	}
	policy.NativeAuthHosts = nil
	if err := writeAgentPolicy(filename, policy); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { io.Copy(io.Discard, response.Body); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("native stream survived revocation")
	}
}
