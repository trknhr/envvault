package authstate

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

type mockTransport func(*http.Request) (*http.Response, error)

func (f mockTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGitHubDeviceFlowAndCancellation(t *testing.T) {
	var exchanges atomic.Int32
	g := GitHub{HTTP: &http.Client{Transport: mockTransport(func(r *http.Request) (*http.Response, error) {
		body := `{"device_code":"device-secret","user_code":"TEST-CODE","verification_uri":"https://github.com/login/device","interval":1,"expires_in":60}`
		if r.URL.Path == "/login/oauth/access_token" {
			exchanges.Add(1)
			r.ParseForm()
			if r.Form.Get("device_code") != "device-secret" {
				t.Error("device code was not exchanged")
			}
			body = `{"access_token":"device-canary","refresh_token":"refresh-canary","expires_in":3600}`
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}}
	device, err := g.Begin(context.Background(), "public-client", []string{"read:user"})
	if err != nil {
		t.Fatal(err)
	}
	document, err := g.Wait(context.Background(), "public-client", device)
	if err != nil {
		t.Fatal(err)
	}
	value, err := Token(document, "/access_token")
	if err != nil || string(value) != "device-canary" || exchanges.Load() != 1 {
		t.Fatal("device flow did not acquire authentication state")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := g.Wait(ctx, "public-client", device); err == nil {
		t.Fatal("cancelled device flow continued")
	}
}
