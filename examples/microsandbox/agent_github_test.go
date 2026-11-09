package main

import (
	"context"
	"io"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/trknhr/envvault/internal/connection/keyringprovider"
	"github.com/trknhr/envvault/internal/keyring"
)

func TestAgentGitHubTokenHeaderStillRequiresExactReferenceAndScope(t *testing.T) {
	vault, _ := testVaultConfig(t)
	var arrivals atomic.Int32
	proxy, client, _ := testAgentProxyVaultHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrivals.Add(1)
		if r.Header.Get("Authorization") != "Bearer github-canary" {
			http.Error(w, "credential mismatch", 400)
			return
		}
		io.WriteString(w, "accepted")
	}), vault)
	store := &agentCountingStore{Store: keyring.NewMemoryStore()}
	if err := store.Put(context.Background(), keyring.CredentialValue("sandbox/first"), []byte("github-canary")); err != nil {
		t.Fatal(err)
	}
	proxy.credentials = keyringprovider.Provider{Store: store}
	for _, check := range []struct {
		header, method, path string
		expected             int
	}{
		{"token envvault://sandbox/first", "GET", "/v1/api", 200},
		{"Bearer envvault://sandbox/first", "GET", "/v1/api", 200},
		{"token github-canary", "GET", "/v1/api", 403},
		{"token envvault://sandbox/missing", "GET", "/v1/api", 403},
		{"token envvault://sandbox/first", "POST", "/v1/api", 403},
		{"token envvault://sandbox/first", "GET", "/outside", 403},
	} {
		r, _ := http.NewRequest(check.method, "https://example.com"+check.path, nil)
		r.Header.Set("Authorization", check.header)
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != check.expected {
			t.Fatalf("GitHub header compatibility changed authorization: status %d", response.StatusCode)
		}
	}
	if store.reads.Load() != 2 || arrivals.Load() != 2 {
		t.Fatal("denied token request acquired or used a credential")
	}
}
