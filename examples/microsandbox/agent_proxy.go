package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/trknhr/envvault/internal/connection"
	"github.com/trknhr/envvault/internal/connection/authprovider"
	"github.com/trknhr/envvault/internal/connection/keyringprovider"
	"github.com/trknhr/envvault/internal/keyring"
)

type agentPolicy struct {
	HTTPSHosts      []string          `json:"https_hosts"`
	MaxProcesses    int               `json:"max_processes,omitempty"`
	Credentials     []agentCredential `json:"credentials,omitempty"`
	EnvVault        bool              `json:"envvault"`
	EnvVaultScope   string            `json:"envvault_scope"`
	NativeAuthHosts []string          `json:"native_auth_hosts,omitempty"`
	vaultReferences []string
	vaultRoutes     []agentCredential
}

func readAgentPolicy(filename string) (agentPolicy, error) {
	policy := agentPolicy{MaxProcesses: 512, EnvVault: true, EnvVaultScope: "profiles"}
	f, err := os.Open(filename)
	if err != nil {
		return policy, err
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil || info.Size() > 64<<10 {
		return policy, errors.New("agent policy exceeds size limit")
	}
	decoder := json.NewDecoder(io.LimitReader(f, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return agentPolicy{}, errors.New("invalid agent policy")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return agentPolicy{}, errors.New("invalid agent policy trailer")
	}
	for _, host := range policy.HTTPSHosts {
		if !validAgentHost(host) {
			return agentPolicy{}, errors.New("agent policy requires exact DNS hostnames")
		}
	}
	for _, host := range policy.NativeAuthHosts {
		if !validAgentHost(host) {
			return agentPolicy{}, errors.New("native_auth_hosts requires exact DNS hostnames")
		}
	}
	if policy.MaxProcesses < 16 || policy.MaxProcesses > 8192 {
		return agentPolicy{}, errors.New("max_processes must be between 16 and 8192")
	}
	if policy.EnvVaultScope != "network" && policy.EnvVaultScope != "profiles" {
		return agentPolicy{}, errors.New("envvault_scope must be network or profiles")
	}
	if err := validateAgentCredentials(policy.Credentials); err != nil {
		return agentPolicy{}, err
	}
	for _, binding := range policy.Credentials {
		if !policy.allows(binding.Host) {
			return agentPolicy{}, errors.New("credential host must also appear in https_hosts")
		}
	}
	return policy, nil
}

func validAgentHost(host string) bool {
	if host == "" || len(host) > 253 || host != strings.ToLower(host) || strings.Trim(host, ".") != host || net.ParseIP(host) != nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.Trim(label, "-") != label {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func (p agentPolicy) allows(host string) bool {
	for _, allowed := range p.HTTPSHosts {
		if allowed == host {
			return true
		}
	}
	return false
}

func (p agentPolicy) allowsNativeAuth(host string) bool {
	for _, allowed := range p.NativeAuthHosts {
		if allowed == host {
			return true
		}
	}
	return false
}

type agentTunnel struct {
	host     string
	revision string
	client   net.Conn
}

func (t *agentTunnel) close() {
	_ = t.client.Close()
}

// agentProxy enforces the host allowlist on CONNECT and every decrypted HTTPS
// request. The CA key and EnvVault credential values stay on the host.
type agentProxy struct {
	policyPath  string
	server      *http.Server
	listener    net.Listener
	cancel      context.CancelFunc
	dial        func(context.Context, string) (net.Conn, error)
	mu          sync.Mutex
	tunnels     map[*agentTunnel]struct{}
	closed      bool
	watchDone   chan struct{}
	tls         *agentTLS
	credentials connection.CredentialProvider
	vault       *agentVault
}

func startAgentProxy(policyPath, repoDir string) (*agentProxy, error) {
	vault, err := defaultAgentVault(repoDir)
	if err != nil {
		return nil, err
	}
	return startAgentProxyWithVault(policyPath, dialAgentPublic, vault)
}

func startAgentProxyWithDial(policyPath string, dial func(context.Context, string) (net.Conn, error)) (*agentProxy, error) {
	return startAgentProxyWithVault(policyPath, dial, nil)
}

func startAgentProxyWithVault(policyPath string, dial func(context.Context, string) (net.Conn, error), vault *agentVault) (*agentProxy, error) {
	if _, err := readAgentPolicy(policyPath); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &agentProxy{policyPath: policyPath, listener: ln, cancel: cancel,
		dial: dial, tunnels: make(map[*agentTunnel]struct{}), watchDone: make(chan struct{}), vault: vault}
	if _, err := p.policy(); err != nil {
		cancel()
		ln.Close()
		return nil, err
	}
	p.credentials = keyringprovider.Provider{Store: keyring.NewOSStore()}
	if vault != nil && vault.dataDir != "" {
		p.credentials = authprovider.Provider{ConfigPath: vault.filename, DataDir: vault.dataDir, Secrets: keyring.NewOSStore()}
	}
	p.tls, err = newAgentTLS(p)
	if err != nil {
		cancel()
		ln.Close()
		return nil, err
	}
	p.server = &http.Server{Handler: p, ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() { _ = p.server.Serve(ln) }()
	go p.watch(ctx)
	return p, nil
}

func (p *agentProxy) port() int { return p.listener.Addr().(*net.TCPAddr).Port }

func (p *agentProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	policy, policyErr := p.policy()
	if r.Method != http.MethodConnect || err != nil || port != "443" || policyErr != nil || !validAgentHost(host) || !policy.allows(host) {
		http.Error(w, "destination blocked", http.StatusForbidden)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "unsupported proxy transport", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	tunnel := &agentTunnel{host: host, revision: policy.hostRevision(host), client: client}
	defer tunnel.close()
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.tunnels[tunnel] = struct{}{}
	p.mu.Unlock()
	defer func() { p.mu.Lock(); delete(p.tunnels, tunnel); p.mu.Unlock() }()
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}
	p.serveAgentTLS(tunnel, buffered, host)
}

func (p *agentProxy) watch(ctx context.Context) {
	defer close(p.watchDone)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			policy, err := p.policy()
			p.mu.Lock()
			var revoke []*agentTunnel
			for tunnel := range p.tunnels {
				if err != nil || !policy.allows(tunnel.host) || policy.hostRevision(tunnel.host) != tunnel.revision {
					revoke = append(revoke, tunnel)
				}
			}
			p.mu.Unlock()
			for _, tunnel := range revoke {
				tunnel.close()
			}
		}
	}
}

func (p *agentProxy) Close() error {
	p.cancel()
	p.mu.Lock()
	p.closed = true
	for tunnel := range p.tunnels {
		tunnel.close()
	}
	p.mu.Unlock()
	<-p.watchDone
	p.tls.transport.CloseIdleConnections()
	return p.server.Close()
}

func dialAgentPublic(ctx context.Context, authority string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		ip = ip.Unmap()
		if !agentPublicIP(ip) {
			continue
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
	}
	return nil, fmt.Errorf("no reachable public address for port %s", strconv.Quote(port))
}

func agentPublicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsGlobalUnicast() && !ip.IsPrivate() &&
		!ip.IsLoopback() && !ip.IsLinkLocalUnicast() &&
		!netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
}
