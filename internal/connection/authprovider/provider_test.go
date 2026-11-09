package authprovider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/authstate"
	"github.com/trknhr/envvault/internal/config"
	"github.com/trknhr/envvault/internal/connection"
	"github.com/trknhr/envvault/internal/keyring"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func setup(t *testing.T, document string, metadata authstate.Metadata) (Provider, config.File) {
	t.Helper()
	dir := t.TempDir()
	p := Provider{ConfigPath: filepath.Join(dir, "config.yaml"), DataDir: dir, Secrets: keyring.NewMemoryStore()}
	m, err := p.Store().Put(context.Background(), metadata, []byte(document))
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.DefaultFile()
	cfg.Version = 2
	cfg.AuthProfiles = map[string]string{metadata.Name: m.ID}
	if err := config.Save(p.ConfigPath, cfg); err != nil {
		t.Fatal(err)
	}
	return p, cfg
}

func request() connection.CredentialRequest {
	return connection.CredentialRequest{SessionID: "test", SubjectID: "test", TTL: time.Minute, Spec: connection.CredentialSpec{Provider: "keyring", Issuance: connection.IssuanceStatic, Ref: "envvault://github/work"}}
}

func TestManagedProviderRejectsUnsupportedIssuanceAndBlankIdentity(t *testing.T) {
	p, _ := setup(t, `{"token":"contract-canary"}`, authstate.Metadata{Name: "github/work", Provider: "generic", Format: "json", TokenField: "/token"})
	for _, field := range []string{"issuance", "session", "subject"} {
		r := request()
		switch field {
		case "issuance":
			r.Spec.Issuance, r.Spec.MaxTTL = connection.IssuanceDynamic, time.Hour
		case "session":
			r.SessionID = " "
		case "subject":
			r.SubjectID = "\t"
		}
		if lease, err := p.Acquire(context.Background(), r); err == nil || lease != nil {
			t.Fatalf("accepted unsupported credential request: %s", field)
		}
	}
}

func TestStructuredLeaseRotatesAndRevokesWithoutCachingValues(t *testing.T) {
	p, cfg := setup(t, `{"token":"first-canary"}`, authstate.Metadata{Name: "github/work", Provider: "generic", Format: "json", TokenField: "/token"})
	ctx := context.Background()
	lease, err := p.Acquire(ctx, request())
	if err != nil {
		t.Fatal(err)
	}
	read := func(expected string) {
		t.Helper()
		if err := lease.WithValue(ctx, func(value []byte) error {
			if string(value) != expected {
				t.Error("lease retained stale credential")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	read("first-canary")
	record, _ := p.Store().Read(ctx, cfg.AuthProfiles["github/work"])
	defer record.Zero()
	if _, err := p.Store().Put(ctx, record.Metadata, []byte(`{"token":"second-canary"}`)); err != nil {
		t.Fatal(err)
	}
	read("second-canary")
	delete(cfg.AuthProfiles, "github/work")
	config.Save(p.ConfigPath, cfg)
	if err := lease.WithValue(ctx, func([]byte) error { t.Fatal("revoked profile exposed a token"); return nil }); err == nil {
		t.Fatal("profile deletion did not revoke an existing lease")
	}
}

func TestConcurrentRefreshOccursOnceAndPersistsRotatedState(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	document, _ := json.Marshal(map[string]any{"tokens": map[string]any{"access": "old-canary", "refresh": "refresh-canary", "expiry": now.Add(-time.Minute).Format(time.RFC3339)}})
	p, cfg := setup(t, string(document), authstate.Metadata{Name: "github/work", Provider: "github", Format: "json", TokenField: "/tokens/access", RefreshField: "/tokens/refresh", ExpiresField: "/tokens/expiry", ClientID: "public-client"})
	p.Now = func() time.Time { return now }
	var exchanges atomic.Int32
	p.HTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://github.com/login/oauth/access_token" {
			t.Error("refresh endpoint came from untrusted state")
		}
		r.ParseForm()
		if r.Form.Get("refresh_token") != "refresh-canary" {
			t.Error("refresh reused a consumed token")
		}
		exchanges.Add(1)
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"access_token":"fresh-canary","refresh_token":"next-refresh","expires_in":3600}`))}, nil
	})}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lease, err := p.Acquire(context.Background(), request())
			if err != nil {
				t.Error(err)
				return
			}
			defer p.Revoke(context.Background(), lease)
			if err := lease.WithValue(context.Background(), func(value []byte) error {
				if string(value) != "fresh-canary" {
					t.Error("stale token after refresh")
				}
				return nil
			}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if exchanges.Load() != 1 {
		t.Fatal("concurrent readers performed multiple refresh exchanges")
	}
	record, err := p.Store().Read(context.Background(), cfg.AuthProfiles["github/work"])
	if err != nil {
		t.Fatal(err)
	}
	defer record.Zero()
	refresh, _ := authstate.Field(record.Document, "/refresh_token")
	if refresh != "next-refresh" {
		t.Fatal("rotated refresh state was not committed")
	}
}
