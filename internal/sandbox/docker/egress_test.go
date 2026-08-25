package docker_test

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trknhr/envvault/internal/connection"
	"github.com/trknhr/envvault/internal/sandbox"
	sandboxdocker "github.com/trknhr/envvault/internal/sandbox/docker"
)

func TestRuntimeAttachesURLPreservingEgressWithoutUpstreamCredential(t *testing.T) {
	certificateServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer certificateServer.Close()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateServer.Certificate().Raw})
	const proxyCapability = "envvault-proxy-capability"
	const upstreamSecret = "UPSTREAM_SECRET_MUST_NOT_BE_MATERIALIZED"
	runtime := sandboxdocker.New(sandboxdocker.Options{Runner: &fakeRunner{}})

	attachment, err := runtime.AttachEgress(context.Background(), connection.EgressClientConfig{
		ProxyURL:         "http://envvault:" + proxyCapability + "@127.0.0.1:43123",
		CACertificatePEM: caPEM,
	})
	if err != nil {
		t.Fatalf("AttachEgress() error = %v", err)
	}
	if attachment.Mode != sandbox.EgressProxyEnvironment {
		t.Fatalf("Mode = %q", attachment.Mode)
	}
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if got := attachment.Environment[key]; !strings.Contains(got, proxyCapability) || strings.Contains(got, upstreamSecret) {
			t.Fatalf("%s was not the short-lived proxy capability", key)
		}
	}
	if attachment.Environment["NODE_USE_ENV_PROXY"] != "1" || attachment.Environment["NODE_EXTRA_CA_CERTS"] != "/etc/envvault-outbound/ca.pem" {
		t.Fatalf("Node proxy environment = %#v", attachment.Environment)
	}
	if len(attachment.Mounts) != 1 || len(attachment.Resources) != 1 {
		t.Fatalf("attachment mounts/resources = %d/%d", len(attachment.Mounts), len(attachment.Resources))
	}
	mount := attachment.Mounts[0]
	if mount.Target != "/etc/envvault-outbound" || !mount.ReadOnly {
		t.Fatalf("CA mount = %#v", mount)
	}
	writtenCA, err := os.ReadFile(filepath.Join(mount.Source, "ca.pem"))
	if err != nil {
		t.Fatalf("ReadFile(ca.pem) error = %v", err)
	}
	if string(writtenCA) != string(caPEM) || strings.Contains(string(writtenCA), proxyCapability) || strings.Contains(string(writtenCA), upstreamSecret) {
		t.Fatal("CA mount contained unexpected material")
	}
	if err := attachment.Resources[0].Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := os.Stat(mount.Source); !os.IsNotExist(err) {
		t.Fatalf("temporary CA directory remained after Close: %v", err)
	}
	if err := attachment.Resources[0].Close(context.Background()); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestRuntimeRejectsInvalidEgressClientConfigWithoutEchoingCapability(t *testing.T) {
	runtime := sandboxdocker.New(sandboxdocker.Options{Runner: &fakeRunner{}})
	const capability = "capability-must-not-be-logged"
	tests := []connection.EgressClientConfig{
		{ProxyURL: "http://envvault:" + capability + "@127.0.0.1:1234"},
		{ProxyURL: "https://envvault:" + capability + "@127.0.0.1:1234", CACertificatePEM: []byte("not a certificate")},
		{ProxyURL: "http://127.0.0.1:1234", CACertificatePEM: []byte("not a certificate")},
	}
	for _, config := range tests {
		_, err := runtime.AttachEgress(context.Background(), config)
		if err == nil {
			t.Fatal("AttachEgress() error = nil")
		}
		if strings.Contains(err.Error(), capability) {
			t.Fatalf("AttachEgress() error leaked proxy capability: %v", err)
		}
	}
}
