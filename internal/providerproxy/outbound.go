package providerproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/connection"
	"github.com/trknhr/envvault/internal/connection/compatprofile"
	"github.com/trknhr/envvault/internal/connection/keyringprovider"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/projectbinding"
)

// OutboundBroker is a runtime-independent, URL-preserving HTTP egress broker.
// A runtime delivers its proxy URL and public CA certificate to a workload;
// upstream credentials remain in this process and are injected only when the
// request carries the route's late-bound credential reference and matches its
// destination, method, and path policies.
type OutboundBroker struct {
	HTTP          *http.Client
	Now           func() time.Time
	ListenAddress string
	AdvertiseHost string
}

func (b OutboundBroker) Start(ctx context.Context, request connection.EgressBrokerStartRequest) (connection.EgressLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(request.Routes) == 0 {
		return nil, clerr.New(clerr.ConfigInvalid, "outbound broker requires at least one route")
	}
	if request.Credentials == nil {
		return nil, clerr.New(clerr.KeyringUnavailable, "outbound broker credential provider unavailable")
	}

	now := b.now()
	routes := make([]outboundRoute, 0, len(request.Routes))
	credentialLeases := make([]connection.CredentialLease, 0, len(request.Routes))
	credentialReferences := make([]string, 0, len(request.Routes))
	seenCredentialReferences := make(map[string]struct{}, len(request.Routes))
	cleanupCredentials := func() {
		for i := len(credentialLeases) - 1; i >= 0; i-- {
			_ = request.Credentials.Revoke(context.Background(), credentialLeases[i])
		}
		for i := range routes {
			zero(routes[i].credential)
		}
	}

	expiresAt := request.Routes[0].Grant.ExpiresAt
	seenPolicies := make(map[string]struct{}, len(request.Routes))
	seenDestinations := make(map[string]struct{}, len(request.Routes))
	connectSchemes := make(map[string]connection.HTTPScheme, len(request.Routes))
	for _, candidate := range request.Routes {
		if err := validateEgressRoute(candidate, now); err != nil {
			cleanupCredentials()
			return nil, err
		}
		if _, exists := seenPolicies[candidate.Policy.Name]; exists {
			cleanupCredentials()
			return nil, clerr.New(clerr.ConfigInvalid, "outbound broker policy names must be unique")
		}
		seenPolicies[candidate.Policy.Name] = struct{}{}
		routeKey := outboundRouteKey(candidate.Policy)
		if _, exists := seenDestinations[routeKey]; exists {
			cleanupCredentials()
			return nil, clerr.New(clerr.ConfigInvalid, "outbound broker routes must not have the same destination and base path")
		}
		seenDestinations[routeKey] = struct{}{}
		connectKey := outboundConnectKey(candidate.Policy.Destination)
		if existing, exists := connectSchemes[connectKey]; exists && existing != candidate.Policy.Protocol.HTTP.Scheme {
			cleanupCredentials()
			return nil, clerr.New(clerr.ConfigInvalid, "outbound broker cannot mix http and https routes on the same destination")
		}
		connectSchemes[connectKey] = candidate.Policy.Protocol.HTTP.Scheme
		if candidate.Grant.ExpiresAt.Before(expiresAt) {
			expiresAt = candidate.Grant.ExpiresAt
		}
		credentialReference := candidate.Policy.Authentication.Credential.Ref
		if _, exists := seenCredentialReferences[credentialReference]; !exists {
			seenCredentialReferences[credentialReference] = struct{}{}
			credentialReferences = append(credentialReferences, credentialReference)
		}

		credentialLease, err := request.Credentials.Acquire(ctx, connection.CredentialRequest{
			SessionID: candidate.Grant.SessionID,
			SubjectID: candidate.Grant.SubjectID,
			Spec:      candidate.Policy.Authentication.Credential,
			TTL:       candidate.Grant.ExpiresAt.Sub(now),
		})
		if err != nil {
			cleanupCredentials()
			return nil, err
		}
		credentialLeases = append(credentialLeases, credentialLease)
		var value []byte
		if err := credentialLease.WithValue(ctx, func(raw []byte) error {
			value = append([]byte(nil), raw...)
			return nil
		}); err != nil {
			cleanupCredentials()
			return nil, err
		}
		routes = append(routes, outboundRoute{policy: candidate.Policy, grant: candidate.Grant, credential: value})
	}

	server, err := startOutboundProxy(ctx, outboundProxyOptions{
		routes:        routes,
		expiresAt:     expiresAt,
		httpClient:    b.HTTP,
		now:           b.Now,
		listenAddress: b.ListenAddress,
		advertiseHost: b.AdvertiseHost,
	})
	if err != nil {
		cleanupCredentials()
		return nil, err
	}
	return &outboundBrokerLease{
		server:               server,
		credentials:          request.Credentials,
		leases:               credentialLeases,
		expiresAt:            expiresAt,
		credentialReferences: credentialReferences,
	}, nil
}

func (b OutboundBroker) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

func validateEgressRoute(route connection.EgressRoute, now time.Time) error {
	adapter := HTTPAdapter{}
	if err := adapter.Validate(route.Policy); err != nil {
		return err
	}
	if err := route.Grant.Validate(); err != nil {
		return err
	}
	if route.Grant.PolicyName != route.Policy.Name || route.Grant.Protocol != route.Policy.Protocol.Type || route.Grant.Destination != route.Policy.Destination {
		return clerr.New(clerr.ConfigInvalid, "connection grant does not match outbound policy")
	}
	if route.Grant.Expired(now) {
		return clerr.New(clerr.IssueFailed, "connection grant expired")
	}
	return nil
}

type outboundBrokerLease struct {
	mu                   sync.Mutex
	server               *outboundProxyServer
	credentials          connection.CredentialProvider
	leases               []connection.CredentialLease
	expiresAt            time.Time
	credentialReferences []string
	closed               bool
}

func (l *outboundBrokerLease) Endpoint() connection.Endpoint {
	if l.server == nil {
		return connection.Endpoint{}
	}
	return connection.Endpoint{Network: "tcp", Address: l.server.advertisedAddress}
}

func (l *outboundBrokerLease) ClientConfig() connection.EgressClientConfig {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.server == nil {
		return connection.EgressClientConfig{}
	}
	return connection.EgressClientConfig{
		ProxyURL:             l.server.proxyURL(),
		CACertificatePEM:     append([]byte(nil), l.server.caPEM...),
		CredentialReferences: append([]string(nil), l.credentialReferences...),
	}
}

func (l *outboundBrokerLease) ExpiresAt() time.Time { return l.expiresAt }

func (*outboundBrokerLease) String() string   { return "outbound broker lease [REDACTED]" }
func (*outboundBrokerLease) GoString() string { return "outbound broker lease [REDACTED]" }

func (l *outboundBrokerLease) Close(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if ctx == nil {
		ctx = context.Background()
	}
	var errs []error
	if l.server != nil {
		if err := l.server.Close(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	for i := len(l.leases) - 1; i >= 0; i-- {
		if err := l.credentials.Revoke(ctx, l.leases[i]); err != nil {
			errs = append(errs, err)
		}
	}
	l.leases = nil
	l.credentialReferences = nil
	return errors.Join(errs...)
}

// OutboundResolver translates stored provider-proxy profiles into one broker
// lease. It exposes only non-secret credential references to support late
// binding; credential values remain in the trusted broker.
type OutboundResolver struct {
	Profiles      ProfileResolver
	Secrets       keyring.Store
	Credentials   connection.CredentialProvider
	Broker        connection.EgressBroker
	HTTP          *http.Client
	Now           func() time.Time
	ListenAddress string
	AdvertiseHost string
}

func (r OutboundResolver) Open(ctx context.Context, names []string, identity projectbinding.Identity, subjectID string) (connection.EgressLease, error) {
	if len(names) == 0 {
		return nil, clerr.New(clerr.ConfigInvalid, "at least one outbound profile is required")
	}
	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	sessionID, err := newMetadataID("egress_")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(subjectID) == "" {
		subjectID = "sandbox-outbound"
	}
	seen := make(map[string]struct{}, len(names))
	routes := make([]connection.EgressRoute, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, clerr.New(clerr.ConfigInvalid, "outbound profile name is required")
		}
		if _, exists := seen[name]; exists {
			return nil, clerr.New(clerr.ConfigInvalid, "outbound profile names must be unique")
		}
		seen[name] = struct{}{}
		if r.Profiles == nil {
			return nil, clerr.New(clerr.ProfileNotFound, name)
		}
		stored, err := r.Profiles.Profile(name)
		if err != nil {
			return nil, err
		}
		if err := projectbinding.Check(stored.ProjectBinding, identity); err != nil {
			return nil, err
		}
		policy, err := compatprofile.FromProviderProxyProfile(stored)
		if err != nil {
			return nil, err
		}
		grantID, err := newMetadataID("grant_")
		if err != nil {
			return nil, err
		}
		maxConnections := policy.Limits.MaxConnections
		if maxConnections == 0 {
			maxConnections = int(^uint(0) >> 1)
		}
		routes = append(routes, connection.EgressRoute{
			Policy: policy,
			Grant: connection.Grant{
				ID:             grantID,
				SessionID:      sessionID,
				SubjectID:      subjectID,
				PolicyName:     policy.Name,
				PolicyRevision: "legacy-profile-v1",
				Protocol:       policy.Protocol.Type,
				Destination:    policy.Destination,
				IssuedAt:       now,
				ExpiresAt:      now.Add(policy.Limits.SessionTTL),
				MaxConnections: maxConnections,
				MaxBytes:       policy.Limits.MaxBytes,
			},
		})
	}
	credentials := r.Credentials
	if credentials == nil {
		credentials = keyringprovider.Provider{Store: r.Secrets, Now: r.Now}
	}
	broker := r.Broker
	if broker == nil {
		broker = OutboundBroker{HTTP: r.HTTP, Now: r.Now, ListenAddress: r.ListenAddress, AdvertiseHost: r.AdvertiseHost}
	}
	return broker.Start(ctx, connection.EgressBrokerStartRequest{Routes: routes, Credentials: credentials})
}

type outboundRoute struct {
	policy     connection.Policy
	grant      connection.Grant
	credential []byte
}

func outboundRouteKey(policy connection.Policy) string {
	httpPolicy := policy.Protocol.HTTP
	return strings.Join([]string{
		string(httpPolicy.Scheme),
		strings.ToLower(strings.TrimSuffix(policy.Destination.Host, ".")),
		strconv.Itoa(int(policy.Destination.Port)),
		path.Clean(httpPolicy.BasePath),
	}, "\x00")
}

func outboundConnectKey(destination connection.Destination) string {
	return strings.ToLower(strings.TrimSuffix(destination.Host, ".")) + "\x00" + strconv.Itoa(int(destination.Port))
}

type outboundProxyOptions struct {
	routes        []outboundRoute
	expiresAt     time.Time
	httpClient    *http.Client
	now           func() time.Time
	listenAddress string
	advertiseHost string
}

type outboundProxyServer struct {
	routes              []outboundRoute
	expiresAt           time.Time
	client              *http.Client
	publicClient        *http.Client
	publicTransport     *http.Transport
	now                 func() time.Time
	token               []byte
	caCertificate       *x509.Certificate
	caKey               *ecdsa.PrivateKey
	caPEM               []byte
	server              *http.Server
	listener            net.Listener
	advertisedAddress   string
	mu                  sync.Mutex
	leafCertificates    map[string]tls.Certificate
	hijackedConnections map[net.Conn]struct{}
	closed              bool
}

func startOutboundProxy(ctx context.Context, options outboundProxyOptions) (*outboundProxyServer, error) {
	listenAddress := strings.TrimSpace(options.listenAddress)
	if listenAddress == "" {
		listenAddress = "127.0.0.1:0"
	}
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return nil, clerr.Wrap(clerr.RuntimeUnavailable, "start outbound proxy listener", err)
	}
	token, err := newLocalToken()
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	now := time.Now()
	if options.now != nil {
		now = options.now()
	}
	caCertificate, caKey, caPEM, err := newCertificateAuthority(now, options.expiresAt)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	client := options.httpClient
	if client == nil {
		client = &http.Client{Transport: cloneDefaultTransport()}
	}
	clientCopy := *client
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	publicTransport := cloneDefaultTransport()
	publicTransport.Proxy = nil
	publicTransport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, rawPort, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		portValue, err := strconv.ParseUint(rawPort, 10, 16)
		if err != nil || portValue == 0 {
			return nil, errors.New("outbound port rejected")
		}
		resolved, err := publicDialAddress(ctx, host, uint16(portValue))
		if err != nil {
			return nil, err
		}
		return (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, network, resolved)
	}
	advertisedAddress, err := advertiseAddress(listener.Addr().String(), options.advertiseHost)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	s := &outboundProxyServer{
		routes:              options.routes,
		expiresAt:           options.expiresAt,
		client:              &clientCopy,
		publicClient:        &http.Client{Transport: publicTransport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		publicTransport:     publicTransport,
		now:                 options.now,
		token:               []byte(token),
		caCertificate:       caCertificate,
		caKey:               caKey,
		caPEM:               caPEM,
		listener:            listener,
		advertisedAddress:   advertisedAddress,
		leafCertificates:    make(map[string]tls.Certificate),
		hijackedConnections: make(map[net.Conn]struct{}),
	}
	s.server = &http.Server{Handler: s, ReadHeaderTimeout: 15 * time.Second}
	go func() { _ = s.server.Serve(listener) }()
	return s, nil
}

func (s *outboundProxyServer) proxyURL() string {
	u := url.URL{Scheme: "http", Host: s.advertisedAddress, User: url.UserPassword("envvault", string(s.token))}
	return u.String()
}

func (s *outboundProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.expired() {
		proxyAuthenticationRequired(w, "outbound proxy capability expired")
		return
	}
	if !s.proxyAuthorized(r) {
		proxyAuthenticationRequired(w, "outbound proxy capability rejected")
		return
	}
	if r.Method == http.MethodConnect {
		s.serveConnect(w, r)
		return
	}
	s.serveForwardHTTP(w, r)
}

func (s *outboundProxyServer) proxyAuthorized(r *http.Request) bool {
	raw := strings.TrimSpace(r.Header.Get("Proxy-Authorization"))
	parts := strings.SplitN(raw, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Basic") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	user, password, ok := strings.Cut(string(decoded), ":")
	if !ok || user != "envvault" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return subtle.ConstantTimeCompare([]byte(password), s.token) == 1
}

func (s *outboundProxyServer) expired() bool {
	now := time.Now()
	if s.now != nil {
		now = s.now()
	}
	return s.expiresAt.IsZero() || !now.Before(s.expiresAt)
}

func proxyAuthenticationRequired(w http.ResponseWriter, message string) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="envvault"`)
	http.Error(w, message, http.StatusProxyAuthRequired)
}

func (s *outboundProxyServer) serveConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := splitDestination(r.Host, 443)
	if err != nil {
		http.Error(w, "outbound destination rejected", http.StatusBadRequest)
		return
	}
	if s.hasHTTPSDestination(host, port) {
		s.interceptTLSConnect(w, host, port)
		return
	}
	if s.hasDestination(connection.HTTPSchemeHTTP, host, port) {
		s.interceptHTTPConnect(w, host, port)
		return
	}
	s.tunnelConnect(w, r.Context(), host, port)
}

func (s *outboundProxyServer) hasHTTPSDestination(host string, port uint16) bool {
	for _, route := range s.routes {
		if route.policy.Protocol.HTTP.Scheme == connection.HTTPSchemeHTTPS && sameDestination(route.policy.Destination, host, port) {
			return true
		}
	}
	return false
}

func (s *outboundProxyServer) interceptTLSConnect(w http.ResponseWriter, host string, port uint16) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "outbound proxy connection unsupported", http.StatusInternalServerError)
		return
	}
	clientConnection, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	if buffered.Reader.Buffered() != 0 {
		_ = clientConnection.Close()
		return
	}
	certificate, err := s.leafCertificate(host)
	if err != nil {
		_ = clientConnection.Close()
		return
	}
	if _, err := io.WriteString(clientConnection, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = clientConnection.Close()
		return
	}
	tlsConnection := tls.Server(clientConnection, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	})
	if err := tlsConnection.Handshake(); err != nil {
		_ = tlsConnection.Close()
		return
	}
	s.serveHijackedHTTP(tlsConnection, connection.HTTPSchemeHTTPS, host, port)
}

func (s *outboundProxyServer) interceptHTTPConnect(w http.ResponseWriter, host string, port uint16) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "outbound proxy connection unsupported", http.StatusInternalServerError)
		return
	}
	clientConnection, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	if buffered.Reader.Buffered() != 0 {
		_ = clientConnection.Close()
		return
	}
	if _, err := io.WriteString(clientConnection, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = clientConnection.Close()
		return
	}
	s.serveHijackedHTTP(clientConnection, connection.HTTPSchemeHTTP, host, port)
}

func (s *outboundProxyServer) serveHijackedHTTP(clientConnection net.Conn, scheme connection.HTTPScheme, host string, port uint16) {
	var listener *singleConnectionListener
	trackedConnection := &callbackConnection{Conn: clientConnection}
	listener = newSingleConnectionListener(trackedConnection)
	trackedConnection.onClose = func() {
		_ = listener.Close()
		s.untrackConnection(trackedConnection)
	}
	s.trackConnection(trackedConnection)
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		s.serveIntercepted(response, request, scheme, host, port)
	})
	go func() {
		_ = http.Serve(listener, handler)
		_ = listener.Close()
	}()
}

func (s *outboundProxyServer) serveIntercepted(w http.ResponseWriter, r *http.Request, scheme connection.HTTPScheme, host string, port uint16) {
	if s.expired() {
		http.Error(w, "outbound proxy capability expired", http.StatusUnauthorized)
		return
	}
	route, relativePath, ok := s.routeForRequest(scheme, host, port, r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !routeMethodAllowed(route, r.Method) {
		http.Error(w, "method not allowed", http.StatusForbidden)
		return
	}
	if !routePathAllowed(route, relativePath) {
		http.Error(w, "path not allowed", http.StatusForbidden)
		return
	}
	s.forwardInjected(w, r, route)
}

func (s *outboundProxyServer) serveForwardHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL == nil || r.URL.Host == "" {
		http.Error(w, "absolute outbound URL required", http.StatusBadRequest)
		return
	}
	scheme := connection.HTTPScheme(strings.ToLower(r.URL.Scheme))
	defaultPort := uint16(80)
	switch scheme {
	case connection.HTTPSchemeHTTP:
	case connection.HTTPSchemeHTTPS:
		defaultPort = 443
	default:
		http.Error(w, "outbound scheme rejected", http.StatusForbidden)
		return
	}
	host, port, err := splitDestination(r.URL.Host, defaultPort)
	if err != nil {
		http.Error(w, "outbound destination rejected", http.StatusBadRequest)
		return
	}
	if route, relativePath, ok := s.routeForRequest(scheme, host, port, r.URL.Path); ok {
		if !routeMethodAllowed(route, r.Method) || !routePathAllowed(route, relativePath) {
			http.Error(w, "outbound request not allowed", http.StatusForbidden)
			return
		}
		s.forwardInjected(w, r, route)
		return
	}
	if s.hasDestination(scheme, host, port) {
		http.Error(w, "outbound request not allowed", http.StatusForbidden)
		return
	}
	s.forwardPublicHTTP(w, r)
}

func (s *outboundProxyServer) hasDestination(scheme connection.HTTPScheme, host string, port uint16) bool {
	for _, route := range s.routes {
		if route.policy.Protocol.HTTP.Scheme == scheme && sameDestination(route.policy.Destination, host, port) {
			return true
		}
	}
	return false
}

func (s *outboundProxyServer) routeForRequest(scheme connection.HTTPScheme, host string, port uint16, requestPath string) (*outboundRoute, string, bool) {
	type match struct {
		index        int
		relativePath string
		baseLength   int
	}
	matches := make([]match, 0, len(s.routes))
	for i := range s.routes {
		route := &s.routes[i]
		if route.policy.Protocol.HTTP.Scheme != scheme || !sameDestination(route.policy.Destination, host, port) {
			continue
		}
		relative, ok := stripBasePath(route.policy.Protocol.HTTP.BasePath, requestPath)
		if ok {
			matches = append(matches, match{index: i, relativePath: relative, baseLength: len(route.policy.Protocol.HTTP.BasePath)})
		}
	}
	if len(matches) == 0 {
		return nil, "", false
	}
	sort.SliceStable(matches, func(i, j int) bool { return matches[i].baseLength > matches[j].baseLength })
	selected := matches[0]
	return &s.routes[selected.index], selected.relativePath, true
}

func stripBasePath(basePath, requestPath string) (string, bool) {
	base := path.Clean("/" + strings.TrimPrefix(basePath, "/"))
	request := path.Clean("/" + strings.TrimPrefix(requestPath, "/"))
	if base == "/" {
		return request, true
	}
	if request == base {
		return "/", true
	}
	if strings.HasPrefix(request, base+"/") {
		return strings.TrimPrefix(request, base), true
	}
	return "", false
}

func routeMethodAllowed(route *outboundRoute, method string) bool {
	for _, allowed := range route.policy.Protocol.HTTP.AllowedMethods {
		if method == allowed {
			return true
		}
	}
	return false
}

func routePathAllowed(route *outboundRoute, requestPath string) bool {
	clean := path.Clean("/" + strings.TrimPrefix(requestPath, "/"))
	for _, allowed := range route.policy.Protocol.HTTP.AllowedPaths {
		if clean == path.Clean(allowed) {
			return true
		}
	}
	return false
}

func (s *outboundProxyServer) forwardInjected(w http.ResponseWriter, r *http.Request, route *outboundRoute) {
	if r.URL.RawPath != "" || !safeOutboundRequestPath(r.URL.Path) {
		http.Error(w, "outbound path rejected", http.StatusBadRequest)
		return
	}
	httpPolicy := route.policy.Protocol.HTTP
	if !routeCredentialReferenceAllowed(r, route) {
		http.Error(w, "outbound credential reference rejected", http.StatusUnauthorized)
		return
	}
	target := url.URL{
		Scheme:   string(httpPolicy.Scheme),
		Host:     destinationAddress(route.policy.Destination),
		Path:     path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/")),
		RawQuery: r.URL.RawQuery,
	}
	request, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), r.Body)
	if err != nil {
		http.Error(w, "outbound request failed", http.StatusBadGateway)
		return
	}
	copyOutboundHeaders(request.Header, r.Header)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		http.Error(w, "outbound proxy closed", http.StatusServiceUnavailable)
		return
	}
	credential := append([]byte(nil), route.credential...)
	s.mu.Unlock()
	defer zero(credential)
	request.Header.Set(httpPolicy.Auth.Header, "Bearer "+string(credential))
	request.Host = ""
	response, err := s.client.Do(request)
	if err != nil {
		http.Error(w, "provider request failed", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	copyOutboundHeaders(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

func routeCredentialReferenceAllowed(request *http.Request, route *outboundRoute) bool {
	httpPolicy := route.policy.Protocol.HTTP
	parts := strings.Fields(request.Header.Get(httpPolicy.Auth.Header))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return false
	}
	expected := route.policy.Authentication.Credential.Ref
	return len(parts[1]) == len(expected) && subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expected)) == 1
}

func safeOutboundRequestPath(requestPath string) bool {
	if requestPath == "" || !strings.HasPrefix(requestPath, "/") || strings.ContainsRune(requestPath, '\\') {
		return false
	}
	for _, segment := range strings.Split(requestPath, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func (s *outboundProxyServer) tunnelConnect(w http.ResponseWriter, ctx context.Context, host string, port uint16) {
	address, err := publicDialAddress(ctx, host, port)
	if err != nil {
		http.Error(w, "outbound destination rejected", http.StatusForbidden)
		return
	}
	upstream, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		http.Error(w, "outbound connection failed", http.StatusBadGateway)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(w, "outbound proxy connection unsupported", http.StatusInternalServerError)
		return
	}
	client, _, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	s.trackConnection(client)
	s.trackConnection(upstream)
	go func() {
		done := make(chan struct{}, 2)
		copyConnection := func(dst, src net.Conn) {
			_, _ = io.Copy(dst, src)
			done <- struct{}{}
		}
		go copyConnection(upstream, client)
		go copyConnection(client, upstream)
		<-done
		_ = client.Close()
		_ = upstream.Close()
		s.untrackConnection(client)
		s.untrackConnection(upstream)
	}()
}

func (s *outboundProxyServer) forwardPublicHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Scheme != "http" && r.URL.Scheme != "https" {
		http.Error(w, "outbound scheme rejected", http.StatusForbidden)
		return
	}
	request := r.Clone(r.Context())
	request.RequestURI = ""
	request.Header = make(http.Header)
	copyOutboundHeaders(request.Header, r.Header)
	response, err := s.publicClient.Do(request)
	if err != nil {
		http.Error(w, "outbound request failed", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	copyOutboundHeaders(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

func (s *outboundProxyServer) leafCertificate(host string) (tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.caCertificate == nil || s.caKey == nil {
		return tls.Certificate{}, errors.New("outbound proxy closed")
	}
	if existing, ok := s.leafCertificates[host]; ok {
		return existing, nil
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	if s.now != nil {
		now = s.now()
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     s.expiresAt,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, s.caCertificate, &privateKey.PublicKey, s.caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		return tls.Certificate{}, err
	}
	s.leafCertificates[host] = certificate
	return certificate, nil
}

func newCertificateAuthority(now, expiresAt time.Time) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	if expiresAt.IsZero() || !expiresAt.After(now) {
		return nil, nil, nil, clerr.New(clerr.IssueFailed, "outbound proxy lifetime is invalid")
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, clerr.Wrap(clerr.IssueFailed, "generate outbound proxy CA key", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "EnvVault ephemeral outbound CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              expiresAt,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, nil, clerr.Wrap(clerr.IssueFailed, "create outbound proxy CA certificate", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, clerr.Wrap(clerr.IssueFailed, "parse outbound proxy CA certificate", err)
	}
	return certificate, privateKey, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, clerr.Wrap(clerr.IssueFailed, "generate certificate serial", err)
	}
	return serial, nil
}

func splitDestination(raw string, defaultPort uint16) (string, uint16, error) {
	host := raw
	port := defaultPort
	if parsedHost, parsedPort, err := net.SplitHostPort(raw); err == nil {
		host = parsedHost
		value, err := strconv.ParseUint(parsedPort, 10, 16)
		if err != nil || value == 0 {
			return "", 0, errors.New("invalid destination port")
		}
		port = uint16(value)
	} else if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]")
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || strings.ContainsAny(host, " /\\?#@\t\r\n") {
		return "", 0, errors.New("invalid destination host")
	}
	return host, port, nil
}

func sameDestination(destination connection.Destination, host string, port uint16) bool {
	return strings.EqualFold(strings.TrimSuffix(destination.Host, "."), strings.TrimSuffix(host, ".")) && destination.Port == port
}

func destinationAddress(destination connection.Destination) string {
	return net.JoinHostPort(destination.Host, strconv.Itoa(int(destination.Port)))
}

func advertiseAddress(listenerAddress, host string) (string, error) {
	if strings.TrimSpace(host) == "" {
		return listenerAddress, nil
	}
	_, port, err := net.SplitHostPort(listenerAddress)
	if err != nil || port == "" || strings.ContainsAny(host, " /\\?#@\t\r\n") {
		return "", clerr.New(clerr.ConfigInvalid, "outbound proxy advertised host is invalid")
	}
	return net.JoinHostPort(host, port), nil
}

func publicDialAddress(ctx context.Context, host string, port uint16) (string, error) {
	var addresses []net.IP
	if parsed := net.ParseIP(host); parsed != nil {
		addresses = []net.IP{parsed}
	} else {
		resolved, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return "", err
		}
		for _, address := range resolved {
			addresses = append(addresses, address.IP)
		}
	}
	for _, address := range addresses {
		if publicIP(address) {
			return net.JoinHostPort(address.String(), strconv.Itoa(int(port))), nil
		}
	}
	return "", errors.New("destination does not resolve to a public address")
}

func publicIP(ip net.IP) bool {
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsUnspecified()
}

func cloneDefaultTransport() *http.Transport {
	if transport, ok := http.DefaultTransport.(*http.Transport); ok {
		clone := transport.Clone()
		clone.Proxy = nil
		return clone
	}
	return &http.Transport{Proxy: nil}
}

func copyOutboundHeaders(destination, source http.Header) {
	blocked := map[string]struct{}{
		"Connection":          {},
		"Keep-Alive":          {},
		"Proxy-Authenticate":  {},
		"Proxy-Authorization": {},
		"Proxy-Connection":    {},
		"Te":                  {},
		"Trailer":             {},
		"Transfer-Encoding":   {},
		"Upgrade":             {},
	}
	for _, connectionHeader := range source.Values("Connection") {
		for _, name := range strings.Split(connectionHeader, ",") {
			if name = http.CanonicalHeaderKey(strings.TrimSpace(name)); name != "" {
				blocked[name] = struct{}{}
			}
		}
	}
	for key, values := range source {
		if _, skip := blocked[http.CanonicalHeaderKey(key)]; skip {
			continue
		}
		for _, value := range values {
			destination.Add(key, value)
		}
	}
}

func (s *outboundProxyServer) trackConnection(connection net.Conn) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = connection.Close()
		return
	}
	s.hijackedConnections[connection] = struct{}{}
	s.mu.Unlock()
}

func (s *outboundProxyServer) untrackConnection(connection net.Conn) {
	s.mu.Lock()
	delete(s.hijackedConnections, connection)
	s.mu.Unlock()
}

func (s *outboundProxyServer) Close(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	connections := make([]net.Conn, 0, len(s.hijackedConnections))
	for connection := range s.hijackedConnections {
		connections = append(connections, connection)
	}
	s.hijackedConnections = nil
	zero(s.token)
	s.token = nil
	for i := range s.routes {
		zero(s.routes[i].credential)
		s.routes[i].credential = nil
	}
	s.caKey = nil
	s.leafCertificates = nil
	s.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
	if s.publicTransport != nil {
		s.publicTransport.CloseIdleConnections()
	}
	if s.server == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.server.Shutdown(ctx); err != nil {
		_ = s.server.Close()
		return err
	}
	return nil
}

type singleConnectionListener struct {
	mu         sync.Mutex
	connection net.Conn
	address    net.Addr
	closed     chan struct{}
	closeOnce  sync.Once
}

func newSingleConnectionListener(connection net.Conn) *singleConnectionListener {
	return &singleConnectionListener{
		connection: connection,
		address:    connection.LocalAddr(),
		closed:     make(chan struct{}),
	}
}

func (l *singleConnectionListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.connection != nil {
		connection := l.connection
		l.connection = nil
		l.mu.Unlock()
		return connection, nil
	}
	l.mu.Unlock()
	<-l.closed
	return nil, net.ErrClosed
}

func (l *singleConnectionListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *singleConnectionListener) Addr() net.Addr {
	if l.address != nil {
		return l.address
	}
	return staticAddress("envvault-outbound")
}

type callbackConnection struct {
	net.Conn
	once    sync.Once
	onClose func()
}

func (c *callbackConnection) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
	})
	return err
}

type staticAddress string

func (a staticAddress) Network() string { return "tcp" }
func (a staticAddress) String() string  { return string(a) }

var _ connection.EgressBroker = OutboundBroker{}
