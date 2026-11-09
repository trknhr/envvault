package main

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func testAgentProxy(t *testing.T) (*agentProxy, *http.Client, string) {
	return testAgentProxyHandler(t, nil)
}

func testAgentProxyHandler(t *testing.T, handler http.Handler) (*agentProxy, *http.Client, string) {
	return testAgentProxyVaultHandler(t, handler, nil)
}

func testAgentProxyVaultHandler(t *testing.T, handler http.Handler, vault *agentVault) (*agentProxy, *http.Client, string) {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "policy.json")
	if err := writeAgentPolicy(filename, agentPolicy{HTTPSHosts: []string{"example.com"}, EnvVault: true}); err != nil {
		t.Fatal(err)
	}
	var originAddress atomic.Value
	proxy, err := startAgentProxyWithVault(filename, func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", originAddress.Load().(string))
	}, vault)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := proxy.tls.certificate("example.com")
	if err != nil {
		proxy.Close()
		t.Fatal(err)
	}
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handler != nil {
			handler.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/socket" {
			conn, buffered, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			accept := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
			fmt.Fprintf(buffered, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(accept[:]))
			buffered.Flush()
			io.Copy(conn, buffered)
			return
		}
		if r.URL.Path == "/stream" {
			_, _ = io.WriteString(w, "ready\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		_, _ = io.WriteString(w, "accepted")
	}))
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{*certificate}, MinVersion: tls.VersionTLS12}
	origin.StartTLS()
	originAddress.Store(origin.Listener.Addr().String())
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(proxy.tls.publicPEM)
	proxy.tls.transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	proxyURL, _ := url.Parse("http://" + proxy.listener.Addr().String())
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	t.Cleanup(func() { transport.CloseIdleConnections(); proxy.Close(); origin.Close() })
	return proxy, client, filename
}

func TestAgentProxyForwardsAndRevokesUpgrade(t *testing.T) {
	_, client, filename := testAgentProxy(t)
	// Client.Timeout wraps response bodies and hides the upgrade's Write method.
	// Bound this request with a context instead, preserving the duplex body.
	upgradeClient := *client
	upgradeClient.Timeout = 0
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/socket", nil)
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Sec-WebSocket-Version", "13")
	request.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	response, err := upgradeClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 101 {
		t.Fatalf("upgrade failed: %d", response.StatusCode)
	}
	stream, ok := response.Body.(io.ReadWriteCloser)
	if !ok {
		t.Fatal("upgrade is not bidirectional")
	}
	if _, err := stream.Write([]byte("test")); err != nil {
		t.Fatal(err)
	}
	var echoed [4]byte
	if _, err := io.ReadFull(stream, echoed[:]); err != nil || string(echoed[:]) != "test" {
		t.Fatalf("upgrade did not carry bytes: %v", err)
	}
	if err := writeAgentPolicy(filename, agentPolicy{}); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { io.Copy(io.Discard, stream); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("upgrade survived policy revocation")
	}
}

func TestAgentPolicyRejectsAuthorityChangesInsideTLS(t *testing.T) {
	_, client, _ := testAgentProxy(t)
	response, err := client.Get("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("allowed destination was denied")
	}
	request, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	request.Host = "other.example"
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("HTTP Host escaped the CONNECT destination")
	}
}

func TestAgentPolicyRevokesStreamsAndFailsClosed(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false: "removed-host", true: "invalid-json"}[invalid], func(t *testing.T) {
			_, client, filename := testAgentProxy(t)
			response, err := client.Get("https://example.com/stream")
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != 200 {
				t.Fatal("stream did not open")
			}
			if invalid {
				err = os.WriteFile(filename, []byte("{"), 0o600)
			} else {
				err = writeAgentPolicy(filename, agentPolicy{})
			}
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() { io.Copy(io.Discard, response.Body); close(done) }()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("existing stream survived policy revocation")
			}
			if fresh, err := client.Get("https://example.com/"); err == nil {
				fresh.Body.Close()
				if fresh.StatusCode != 403 {
					t.Fatal("revoked policy allowed a new request")
				}
			}
		})
	}
}

func TestAgentProxyRejectsPrivateAddresses(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "::1", "fc00::1", "::ffff:192.168.1.1"} {
		if agentPublicIP(netip.MustParseAddr(raw)) {
			t.Errorf("private address accepted: %s", raw)
		}
	}
	if !agentPublicIP(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("public address rejected")
	}
}
