package providerproxy_test

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/authstate"
	"github.com/trknhr/envvault/internal/config"
	"github.com/trknhr/envvault/internal/connection"
	"github.com/trknhr/envvault/internal/connection/authprovider"
	"github.com/trknhr/envvault/internal/connection/compatprofile"
	"github.com/trknhr/envvault/internal/envref"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/projectbinding"
	"github.com/trknhr/envvault/internal/providerproxy"
)

func TestManagedAuthenticationRotatesThroughAdapterAndRevokesOpenStream(t *testing.T) {
	ctx := context.Background()
	var expected atomic.Value
	expected.Store("first-canary")
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+expected.Load().(string) {
			http.Error(w, "credential mismatch", 401)
			return
		}
		io.WriteString(w, "accepted\n")
		if r.URL.Path == "/stream" {
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		}
	}))
	defer origin.Close()
	dir := t.TempDir()
	provider := authprovider.Provider{ConfigPath: filepath.Join(dir, "config.yaml"), DataDir: dir, Secrets: keyring.NewMemoryStore()}
	metadata, err := provider.Store().Put(ctx, authstate.Metadata{Name: "service/work", Provider: "generic", Format: "json", TokenField: "/access_token"}, []byte(`{"access_token":"first-canary","refresh_token":"host-only-canary"}`))
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.DefaultFile()
	cfg.Version, cfg.AuthProfiles = 2, map[string]string{metadata.Name: metadata.ID}
	if err := config.Save(provider.ConfigPath, cfg); err != nil {
		t.Fatal(err)
	}
	if err := provider.Secrets.Put(ctx, keyring.CredentialValue(metadata.Name), []byte("stale-opaque-canary")); err != nil {
		t.Fatal(err)
	}
	ref, _, _ := envref.ParseValue("envvault://" + metadata.Name)
	direct := &providerproxy.EnvResolver{Secrets: provider.Secrets, Credentials: provider}
	if value, err := direct.ResolveReference(ctx, ref, projectbinding.Identity{}); err == nil || value != "" {
		t.Fatal("host authentication was materialized through a stale opaque key")
	}
	p := providerProfile(origin.URL)
	p.CredentialName, p.AllowedMethods, p.AllowedPaths = metadata.Name, []string{"GET"}, []string{"/value", "/stream"}
	policy, err := compatprofile.FromProviderProxyProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	adapter := providerproxy.HTTPAdapter{HTTP: origin.Client()}
	raw, err := adapter.Start(ctx, connection.AdapterStartRequest{Policy: policy, Grant: adapterGrant(policy, time.Now()), Credentials: provider})
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close(ctx)
	lease := raw.(*providerproxy.HTTPAdapterLease)
	request := func(path string) *http.Response {
		t.Helper()
		r, _ := http.NewRequest("GET", lease.BaseURL()+path, nil)
		r.Header.Set("Authorization", "Bearer "+lease.Token())
		client := &http.Client{Timeout: 3 * time.Second}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("managed proxy request failed")
		}
		if response.StatusCode != 200 {
			response.Body.Close()
			t.Fatal("managed proxy credential mismatch")
		}
		return response
	}
	response := request("/value")
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	expected.Store("second-canary")
	if _, err := provider.Store().Put(ctx, metadata, []byte(`{"access_token":"second-canary"}`)); err != nil {
		t.Fatal(err)
	}
	response = request("/value")
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	stream := request("/stream")
	defer stream.Body.Close()
	reader := bufio.NewReader(stream.Body)
	if line, err := reader.ReadString('\n'); err != nil || line != "accepted\n" {
		t.Fatal("stream did not open")
	}
	delete(cfg.AuthProfiles, metadata.Name)
	if err := config.Save(provider.ConfigPath, cfg); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { io.Copy(io.Discard, reader); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("revoked host authentication retained an open stream")
	}
}
