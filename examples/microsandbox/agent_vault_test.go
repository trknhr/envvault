package main

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/config"
	"github.com/trknhr/envvault/internal/connection/keyringprovider"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/profile"
	"github.com/trknhr/envvault/internal/projectbinding"
)

func testVaultConfig(t *testing.T) (*agentVault, config.File) {
	t.Helper()
	cfg, err := config.DefaultFile()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Credentials = []string{"sandbox/first", "sandbox/second", "sandbox/unscoped"}
	cfg.Profiles["first"] = config.Profile{Kind: profile.KindProviderProxy, CredentialName: "sandbox/first", Provider: "generic",
		TargetURL: "https://example.com/v1", AllowedMethods: []string{"GET"}, AllowedPaths: []string{"/api", "/stream"}, LocalTokenTTL: config.Duration(time.Minute)}
	second := cfg.Profiles["first"]
	second.CredentialName = "sandbox/second"
	cfg.Profiles["second"] = second
	vault := &agentVault{filename: filepath.Join(t.TempDir(), "config.yaml"), identity: projectbinding.Identity{Root: t.TempDir()}}
	if err := config.Save(vault.filename, cfg); err != nil {
		t.Fatal(err)
	}
	return vault, cfg
}

func TestAgentVaultDiscoversAllWithoutAcquiringValues(t *testing.T) {
	vault, cfg := testVaultConfig(t)
	foreign := cfg.Profiles["first"]
	foreign.ProjectBinding = config.ProjectBinding{Mode: profile.ProjectBindingPathHash, PathHash: "sha256:another-project"}
	foreign.CredentialName = "sandbox/foreign"
	cfg.Credentials = append(cfg.Credentials, "sandbox/foreign")
	cfg.Profiles["foreign"] = foreign
	if err := config.Save(vault.filename, cfg); err != nil {
		t.Fatal(err)
	}
	snapshot, err := vault.load()
	if err != nil || len(snapshot.references) != 4 || len(snapshot.routes) != 2 {
		t.Fatalf("automatic discovery did not preserve credential and project boundaries: %v", err)
	}
	for _, route := range snapshot.routes {
		if route.Reference == "envvault://sandbox/foreign" {
			t.Fatal("another workspace's profile was authorized")
		}
		if route.Paths[0] != "/v1/api" {
			t.Fatal("profile base path was not preserved")
		}
	}
	policy := agentPolicy{vaultReferences: snapshot.references, vaultRoutes: snapshot.routes}
	if !strings.Contains(string(policy.credentialCatalog()), "envvault://sandbox/unscoped") {
		t.Fatal("unscoped credential reference was hidden from discovery")
	}
	if err := os.WriteFile(vault.filename, []byte("not valid: ["), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.load(); err == nil {
		t.Fatal("invalid host metadata was accepted")
	}
}

func TestAgentVaultAutomaticallyRoutesReferencesAndReloadsHostState(t *testing.T) {
	vault, cfg := testVaultConfig(t)
	var arrivals atomic.Int32
	proxy, client, filename := testAgentProxyVaultHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrivals.Add(1)
		value := r.Header.Get("Authorization")
		if value != "Bearer first-canary" && value != "Bearer second-canary" {
			http.Error(w, "credential mismatch", 400)
			return
		}
		io.WriteString(w, "accepted")
	}), vault)
	store := &agentCountingStore{Store: keyring.NewMemoryStore()}
	store.Put(context.Background(), keyring.CredentialValue("sandbox/first"), []byte("first-canary"))
	store.Put(context.Background(), keyring.CredentialValue("sandbox/second"), []byte("second-canary"))
	proxy.credentials = keyringprovider.Provider{Store: store}
	// An old policy with no EnvVault settings acquires the new defaults.
	if err := os.WriteFile(filename, []byte(`{"https_hosts":["example.com"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	defaults, err := readAgentPolicy(filename)
	if err != nil || !defaults.EnvVault || defaults.EnvVaultScope != "profiles" {
		t.Fatal("saved destination rules were not enabled by default")
	}
	request := func(ref, method, path string, expected int) {
		t.Helper()
		r, _ := http.NewRequest(method, "https://example.com"+path, nil)
		r.Header.Set("Authorization", "Bearer "+ref)
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		if response.StatusCode != expected || strings.Contains(string(body), "canary") {
			t.Fatalf("automatic reference request failed: status %d", response.StatusCode)
		}
	}
	// There are no entries in the sandbox's credentials array.
	request("envvault://sandbox/first", "GET", "/v1/api", 200)
	request("envvault://sandbox/second", "GET", "/v1/api", 200)
	request("envvault://sandbox/unscoped", "GET", "/v1/api", 403)
	request("first-canary", "GET", "/v1/api", 403)
	request("envvault://sandbox/first", "POST", "/v1/api", 403)
	request("envvault://sandbox/first", "GET", "/api", 403)
	ambiguous, _ := http.NewRequest("GET", "https://example.com/v1/api", nil)
	ambiguous.Header.Set("Authorization", "Bearer envvault://sandbox/first")
	ambiguous.Header.Set("X-API-Key", "envvault://sandbox/second")
	ambiguousResponse, err := client.Do(ambiguous)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, ambiguousResponse.Body)
	ambiguousResponse.Body.Close()
	if ambiguousResponse.StatusCode != 401 {
		t.Fatal("ambiguous credential headers were accepted")
	}
	if store.reads.Load() != 2 || arrivals.Load() != 2 {
		t.Fatal("denied request acquired or used a credential")
	}
	delete(cfg.Profiles, "first")
	if err := config.Save(vault.filename, cfg); err != nil {
		t.Fatal(err)
	}
	request("envvault://sandbox/first", "GET", "/v1/api", 403)
	request("envvault://sandbox/second", "GET", "/v1/api", 200)
	if err := os.WriteFile(vault.filename, []byte("invalid: ["), 0600); err != nil {
		t.Fatal(err)
	}
	if response, err := client.Get("https://example.com/v1/api"); err == nil {
		response.Body.Close()
		if response.StatusCode != 403 {
			t.Fatal("invalid metadata did not block new requests")
		}
	}
	if err := config.Save(vault.filename, cfg); err != nil {
		t.Fatal(err)
	}
	request("envvault://sandbox/second", "GET", "/v1/api", 200)
	if err := writeAgentPolicy(filename, agentPolicy{HTTPSHosts: []string{"example.com"}, EnvVault: false}); err != nil {
		t.Fatal(err)
	}
	request("envvault://sandbox/second", "GET", "/v1/api", 401)
	if store.reads.Load() != 4 || arrivals.Load() != 4 {
		t.Fatal("disabled discovery still resolved credentials")
	}
}

func TestAgentVaultHostConfigCannotBeEditedThroughWorkspace(t *testing.T) {
	workspace := t.TempDir()
	inside := filepath.Join(workspace, "envvault.yaml")
	if err := os.WriteFile(inside, []byte("public metadata"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := protectAgentVaultPath(inside, workspace); err == nil {
		t.Fatal("host config inside guest workspace was accepted")
	}
	outside := filepath.Join(t.TempDir(), "config.yaml")
	if err := protectAgentVaultPath(outside, workspace); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(inside, outside); err != nil {
		t.Fatal(err)
	}
	if err := protectAgentVaultPath(outside, workspace); err == nil {
		t.Fatal("host config symlink into guest workspace was accepted")
	}
}

func TestAgentVaultScopeRevocationClosesStreams(t *testing.T) {
	vault, cfg := testVaultConfig(t)
	proxy, client, filename := testAgentProxyVaultHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ready\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}), vault)
	store := keyring.NewMemoryStore()
	store.Put(context.Background(), keyring.CredentialValue("sandbox/first"), []byte("stream-canary"))
	proxy.credentials = keyringprovider.Provider{Store: store}
	if err := writeAgentPolicy(filename, agentPolicy{HTTPSHosts: []string{"example.com"}, EnvVault: true, EnvVaultScope: "profiles"}); err != nil {
		t.Fatal(err)
	}
	r, _ := http.NewRequest("GET", "https://example.com/v1/stream", nil)
	r.Header.Set("Authorization", "Bearer envvault://sandbox/first")
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("automatic stream did not open")
	}
	delete(cfg.Profiles, "first")
	if err := config.Save(vault.filename, cfg); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { io.Copy(io.Discard, response.Body); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stream survived saved destination rule removal")
	}
}
