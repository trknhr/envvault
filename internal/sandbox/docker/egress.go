package docker

import (
	"context"
	"crypto/x509"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/connection"
	"github.com/trknhr/envvault/internal/sandbox"
)

const (
	outboundTrustTarget = "/etc/envvault-outbound"
	outboundCAFile      = "ca.pem"
)

// AttachEgress implements the Docker runtime side of the runtime-neutral
// egress attachment contract. This first prototype preserves destination URLs
// by configuring the standard forward-proxy environment. It does not enforce
// that applications use the proxy and therefore remains brokered, not
// brokered-enforced.
func (*Runtime) AttachEgress(ctx context.Context, config connection.EgressClientConfig) (sandbox.EgressAttachment, error) {
	if err := ctx.Err(); err != nil {
		return sandbox.EgressAttachment{}, err
	}
	if strings.TrimSpace(config.ProxyURL) == "" || len(config.CACertificatePEM) == 0 {
		return sandbox.EgressAttachment{}, clerr.New(clerr.ConfigInvalid, "Docker egress attachment requires a proxy URL and CA certificate")
	}
	proxyURL, err := url.Parse(config.ProxyURL)
	if err != nil || proxyURL.Scheme != "http" || proxyURL.Hostname() == "" || proxyURL.User == nil || proxyURL.Path != "" || proxyURL.RawQuery != "" || proxyURL.Fragment != "" {
		return sandbox.EgressAttachment{}, clerr.New(clerr.ConfigInvalid, "Docker egress attachment proxy URL is invalid")
	}
	if _, present := proxyURL.User.Password(); !present {
		return sandbox.EgressAttachment{}, clerr.New(clerr.ConfigInvalid, "Docker egress attachment proxy capability is missing")
	}
	certificatePool := x509.NewCertPool()
	if !certificatePool.AppendCertsFromPEM(config.CACertificatePEM) {
		return sandbox.EgressAttachment{}, clerr.New(clerr.ConfigInvalid, "Docker egress attachment CA certificate is invalid")
	}

	directory, err := os.MkdirTemp("", "envvault-egress-")
	if err != nil {
		return sandbox.EgressAttachment{}, clerr.Wrap(clerr.RuntimeUnavailable, "create Docker egress trust directory", err)
	}
	cleanup := &temporaryDirectory{path: directory}
	if err := os.Chmod(directory, 0o755); err != nil {
		_ = cleanup.Close(context.Background())
		return sandbox.EgressAttachment{}, clerr.Wrap(clerr.RuntimeUnavailable, "secure Docker egress trust directory", err)
	}
	certificatePath := filepath.Join(directory, outboundCAFile)
	if err := os.WriteFile(certificatePath, config.CACertificatePEM, 0o644); err != nil {
		_ = cleanup.Close(context.Background())
		return sandbox.EgressAttachment{}, clerr.Wrap(clerr.RuntimeUnavailable, "write Docker egress CA certificate", err)
	}

	containerCA := outboundTrustTarget + "/" + outboundCAFile
	environment := map[string]string{
		"HTTP_PROXY":          config.ProxyURL,
		"HTTPS_PROXY":         config.ProxyURL,
		"http_proxy":          config.ProxyURL,
		"https_proxy":         config.ProxyURL,
		"NODE_EXTRA_CA_CERTS": containerCA,
		// Supported Node releases use this switch to make fetch/undici honor
		// the proxy environment. Other clients continue to use their normal
		// HTTP_PROXY and HTTPS_PROXY behavior.
		"NODE_USE_ENV_PROXY": "1",
	}
	return sandbox.EgressAttachment{
		Environment: environment,
		Mounts: []sandbox.Mount{{
			Source:   directory,
			Target:   outboundTrustTarget,
			ReadOnly: true,
		}},
		Resources: []sandbox.Resource{cleanup},
		Mode:      sandbox.EgressProxyEnvironment,
	}, nil
}

type temporaryDirectory struct {
	mu     sync.Mutex
	path   string
	closed bool
}

func (d *temporaryDirectory) Close(context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	if d.path == "" {
		return nil
	}
	if err := os.RemoveAll(d.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return clerr.Wrap(clerr.CleanupFailed, "remove Docker egress trust directory", err)
	}
	return nil
}
