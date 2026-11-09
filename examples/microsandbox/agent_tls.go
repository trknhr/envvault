package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
)

type agentTLS struct {
	ca        *x509.Certificate
	key       *ecdsa.PrivateKey
	publicPEM []byte
	transport *http.Transport
	mu        sync.Mutex
	certs     map[string]*tls.Certificate
}

func newAgentTLS(proxy *agentProxy) (*agentTLS, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{SerialNumber: serial,
		Subject:   pkix.Name{CommonName: "EnvVault Microsandbox trial CA"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &agentTLS{ca: ca, key: key, publicPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		certs: make(map[string]*tls.Certificate),
		transport: &http.Transport{
			Proxy: nil, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 15 * time.Second,
			IdleConnTimeout: time.Minute,
			DialContext: func(ctx context.Context, _, authority string) (net.Conn, error) {
				return proxy.dial(ctx, authority)
			},
		},
	}, nil
}

func (a *agentTLS) certificate(host string) (*tls.Certificate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if cached := a.certs[host]; cached != nil {
		return cached, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{SerialNumber: serial, DNSNames: []string{host},
		Subject:   pkix.Name{CommonName: host},
		NotBefore: a.ca.NotBefore, NotAfter: a.ca.NotAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.ca, &key.PublicKey, a.key)
	if err != nil {
		return nil, err
	}
	certificate := &tls.Certificate{Certificate: [][]byte{der, a.ca.Raw}, PrivateKey: key}
	a.certs[host] = certificate
	return certificate, nil
}

type agentBufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c agentBufferedConn) Read(data []byte) (int, error) { return c.reader.Read(data) }

type agentOneConnListener struct {
	conn net.Conn
	done chan struct{}
	once sync.Once
	used bool
}

func (l *agentOneConnListener) Accept() (net.Conn, error) {
	if !l.used {
		l.used = true
		return &agentNotifyingConn{Conn: l.conn, listener: l}, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *agentOneConnListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *agentOneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

type agentNotifyingConn struct {
	net.Conn
	listener *agentOneConnListener
}

func (c *agentNotifyingConn) Close() error {
	err := c.Conn.Close()
	c.listener.Close()
	return err
}

func (p *agentProxy) serveAgentTLS(tunnel *agentTunnel, buffered *bufio.ReadWriter, host string) {
	certificate, err := p.tls.certificate(host)
	if err != nil {
		return
	}
	conn := tls.Server(agentBufferedConn{Conn: tunnel.client, reader: buffered.Reader}, &tls.Config{
		MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if strings.ToLower(strings.TrimSuffix(hello.ServerName, ".")) != host {
				return nil, errors.New("TLS hostname differs from proxy destination")
			}
			return certificate, nil
		},
	})
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	err = conn.HandshakeContext(ctx)
	cancel()
	if err != nil {
		return
	}
	upstream := &url.URL{Scheme: "https", Host: host}
	forward := &httputil.ReverseProxy{
		Transport: agentCredentialTransport{proxy: p}, FlushInterval: -1,
		Rewrite:  func(request *httputil.ProxyRequest) { request.SetURL(upstream); request.Out.Host = host },
		ErrorLog: log.New(io.Discard, "", 0),
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authority := strings.ToLower(strings.TrimSuffix(r.Host, ":443"))
		policy, err := p.policy()
		if err != nil || !policy.allows(host) || authority != host || r.Method == http.MethodConnect || r.URL.IsAbs() {
			http.Error(w, "destination blocked", http.StatusForbidden)
			return
		}
		forward.ServeHTTP(w, r)
	})
	listener := &agentOneConnListener{conn: conn, done: make(chan struct{})}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 64 << 10,
		ErrorLog: log.New(io.Discard, "", 0)}
	defer server.Close()
	_ = server.Serve(listener)
}
