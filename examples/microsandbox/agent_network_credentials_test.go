package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/trknhr/envvault/internal/config"
	"github.com/trknhr/envvault/internal/connection/keyringprovider"
	"github.com/trknhr/envvault/internal/keyring"
)

func TestAgentVaultExplicitNetworkModeAllowsEveryStoredCredential(t *testing.T) {
	vault, cfg := testVaultConfig(t)
	// Explicit network mode requires no saved proxy profile or sandbox binding.
	cfg.Profiles = nil
	if err := config.Save(vault.filename, cfg); err != nil {
		t.Fatal(err)
	}
	var arrivals atomic.Int32
	proxy, client, filename := testAgentProxyVaultHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrivals.Add(1)
		if r.Header.Get("Authorization") != "Bearer network-canary" && r.Header.Get("X-API-Key") != "network-canary" && r.Header.Get("Api-Key") != "network-canary" && r.Header.Get("X-Goog-Api-Key") != "network-canary" {
			http.Error(w, "credential mismatch", 400)
			return
		}
		io.WriteString(w, "accepted")
	}), vault)
	store := &agentCountingStore{Store: keyring.NewMemoryStore()}
	for _, name := range cfg.CredentialNames() {
		if err := store.Put(context.Background(), keyring.CredentialValue(name), []byte("network-canary")); err != nil {
			t.Fatal(err)
		}
	}
	proxy.credentials = keyringprovider.Provider{Store: store}
	if err := writeAgentPolicy(filename, agentPolicy{HTTPSHosts: []string{"example.com"}, EnvVault: true, EnvVaultScope: "network"}); err != nil {
		t.Fatal(err)
	}
	request := func(header, value string, expected int) {
		t.Helper()
		r, _ := http.NewRequest("POST", "https://example.com/arbitrary-path", nil)
		r.Header.Set(header, value)
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		if response.StatusCode != expected || strings.Contains(string(body), "canary") {
			t.Fatalf("default credential access failed: status %d", response.StatusCode)
		}
	}
	request("Authorization", "Bearer envvault://sandbox/first", 200)
	request("Authorization", "Bearer envvault://sandbox/second", 200)
	request("Authorization", "Bearer envvault://sandbox/unscoped", 200)
	for _, header := range []string{"X-API-Key", "Api-Key", "X-Goog-Api-Key"} {
		request(header, "envvault://sandbox/unscoped", 200)
	}
	request("Authorization", "Bearer envvault://sandbox/missing", 401)
	request("Authorization", "Bearer envvault://sandbox/first/token", 401)
	request("X-Other", "envvault://sandbox/first", 401)
	if store.reads.Load() != 6 || arrivals.Load() != 6 {
		t.Fatal("unknown or misplaced reference reached the credential provider")
	}
	cfg.RemoveCredential("sandbox/unscoped")
	if err := config.Save(vault.filename, cfg); err != nil {
		t.Fatal(err)
	}
	request("Authorization", "Bearer envvault://sandbox/unscoped", 401)
	if err := writeAgentPolicy(filename, agentPolicy{EnvVault: true}); err != nil {
		t.Fatal(err)
	}
	r, _ := http.NewRequest("GET", "https://example.com/", nil)
	r.Header.Set("Authorization", "Bearer envvault://sandbox/first")
	if response, err := client.Do(r); err == nil {
		response.Body.Close()
		if response.StatusCode != 403 {
			t.Fatal("all-credential access bypassed the network allowlist")
		}
	}
	if store.reads.Load() != 6 || arrivals.Load() != 6 {
		t.Fatal("deleted or network-blocked credential still resolved")
	}
}

func TestAgentVaultRejectsAmbiguousOrEncodedNetworkReferences(t *testing.T) {
	p := agentPolicy{vaultReferences: []string{"envvault://sandbox/first"}}
	r, _ := http.NewRequest("GET", "https://example.com/", nil)
	r.Header.Set("Authorization", "Bearer envvault://sandbox/first")
	r.Header.Set("X-API-Key", "envvault://sandbox/first")
	if _, err := p.networkBinding(r); err == nil {
		t.Fatal("multiple credential fields were accepted")
	}
	r.Header.Del("X-API-Key")
	r.Header.Add("Authorization", "Bearer envvault://sandbox/first")
	if _, err := p.networkBinding(r); err == nil {
		t.Fatal("duplicate credential field was accepted")
	}
	r.Header.Set("Authorization", "Bearer envvault://sandbox/first")
	r.URL.Path, r.URL.RawPath = "/api", "/%61pi"
	binding, err := p.networkBinding(r)
	if err != nil || binding == nil || binding.allows(r) {
		t.Fatal("encoded path was accepted for injection")
	}
}
