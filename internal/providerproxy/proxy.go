package providerproxy

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/connection"
	"github.com/trknhr/envvault/internal/connection/compatprofile"
	"github.com/trknhr/envvault/internal/connection/keyringprovider"
	"github.com/trknhr/envvault/internal/envref"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/profile"
	"github.com/trknhr/envvault/internal/projectbinding"
)

type ProfileResolver interface {
	Profile(name string) (profile.Profile, error)
}

type EnvResolver struct {
	Profiles      ProfileResolver
	Secrets       keyring.Store
	Credentials   connection.CredentialProvider
	Adapter       connection.ProtocolAdapter
	HTTP          *http.Client
	Now           func() time.Time
	SubjectID     string
	ListenAddress string
	AdvertiseHost string

	mu            sync.Mutex
	leases        map[string]*Lease
	adapterLeases []connection.AdapterLease
}

// ResolveProxy opens or reuses the provider-proxy lease for name. The returned
// value contains only sandbox-deliverable connection metadata: a gateway URL,
// a short-lived capability, and its expiry. It never contains the upstream
// credential.
func (r *EnvResolver) ResolveProxy(ctx context.Context, name string, identity projectbinding.Identity) (Lease, error) {
	lease, err := r.ensureLease(ctx, name, identity)
	if err != nil {
		return Lease{}, err
	}
	return *lease, nil
}

func (r *EnvResolver) ResolveReference(ctx context.Context, ref envref.Reference, identity projectbinding.Identity) (string, error) {
	switch ref.Part {
	case envref.PartBaseURL, envref.PartToken:
		lease, err := r.ensureLease(ctx, ref.Profile, identity)
		if err != nil {
			return "", err
		}
		if ref.Part == envref.PartBaseURL {
			return lease.BaseURL, nil
		}
		return lease.Token, nil
	case envref.PartDefault:
		secret, err := r.secret(ctx, ref.Profile)
		if err != nil {
			return "", err
		}
		defer zero(secret)
		return string(secret), nil
	default:
		return "", clerr.New(clerr.ReferenceInvalid, "unknown reference part")
	}
}

func (r *EnvResolver) Close(ctx context.Context) error {
	r.mu.Lock()
	adapterLeases := append([]connection.AdapterLease(nil), r.adapterLeases...)
	r.adapterLeases = nil
	r.leases = nil
	r.mu.Unlock()

	var err error
	for i := len(adapterLeases) - 1; i >= 0; i-- {
		if closeErr := adapterLeases[i].Close(ctx); closeErr != nil && err == nil {
			err = closeErr
		}
	}
	return err
}

func (r *EnvResolver) ensureLease(ctx context.Context, name string, identity projectbinding.Identity) (*Lease, error) {
	r.mu.Lock()
	if r.leases == nil {
		r.leases = map[string]*Lease{}
	}
	if lease := r.leases[name]; lease != nil {
		r.mu.Unlock()
		return lease, nil
	}
	r.mu.Unlock()

	p, err := r.profile(name)
	if err != nil {
		return nil, err
	}
	if p.Kind != profile.KindProviderProxy {
		return nil, clerr.New(clerr.ProfileKindMismatch, name)
	}
	if err := projectbinding.Check(p.ProjectBinding, identity); err != nil {
		return nil, err
	}
	policy, err := compatprofile.FromProviderProxyProfile(p)
	if err != nil {
		return nil, err
	}
	now := r.now()
	expiresAt := now.Add(policy.Limits.SessionTTL)
	grantID, err := newMetadataID("grant_")
	if err != nil {
		return nil, err
	}
	sessionID, err := newMetadataID("session_")
	if err != nil {
		return nil, err
	}
	maxConnections := policy.Limits.MaxConnections
	if maxConnections == 0 {
		maxConnections = math.MaxInt
	}
	grant := connection.Grant{
		ID:             grantID,
		SessionID:      sessionID,
		SubjectID:      r.subjectID(),
		PolicyName:     policy.Name,
		PolicyRevision: "legacy-profile-v1",
		Protocol:       policy.Protocol.Type,
		Destination:    policy.Destination,
		IssuedAt:       now,
		ExpiresAt:      expiresAt,
		MaxConnections: maxConnections,
		MaxBytes:       policy.Limits.MaxBytes,
	}
	adapter := r.Adapter
	if adapter == nil {
		adapter = HTTPAdapter{
			HTTP:          r.HTTP,
			Now:           r.Now,
			ListenAddress: r.ListenAddress,
		}
	}
	credentials := r.Credentials
	if credentials == nil {
		credentials = keyringprovider.Provider{Store: r.Secrets, Now: r.Now}
	}
	adapterLease, err := adapter.Start(ctx, connection.AdapterStartRequest{
		Policy:      policy,
		Grant:       grant,
		Credentials: credentials,
	})
	if err != nil {
		return nil, err
	}
	httpLease, ok := adapterLease.(interface {
		BaseURL() string
		Token() string
	})
	if !ok {
		_ = adapterLease.Close(context.Background())
		return nil, clerr.New(clerr.RuntimeIncompatible, "http adapter lease does not expose client connection metadata")
	}
	baseURL, err := advertiseBaseURL(httpLease.BaseURL(), r.AdvertiseHost)
	if err != nil {
		_ = adapterLease.Close(context.Background())
		return nil, err
	}

	lease := &Lease{
		Profile:   name,
		BaseURL:   baseURL,
		Token:     httpLease.Token(),
		ExpiresAt: adapterLease.ExpiresAt(),
	}

	r.mu.Lock()
	if existing := r.leases[name]; existing != nil {
		r.mu.Unlock()
		_ = adapterLease.Close(context.Background())
		return existing, nil
	}
	r.leases[name] = lease
	r.adapterLeases = append(r.adapterLeases, adapterLease)
	r.mu.Unlock()
	return lease, nil
}

func (r *EnvResolver) subjectID() string {
	if subject := strings.TrimSpace(r.SubjectID); subject != "" {
		return subject
	}
	return "compat-local-process"
}

func (r *EnvResolver) profile(name string) (profile.Profile, error) {
	if r.Profiles == nil {
		return profile.Profile{}, clerr.New(clerr.ProfileNotFound, name)
	}
	return r.Profiles.Profile(name)
}

func (r *EnvResolver) secret(ctx context.Context, name string) ([]byte, error) {
	if r.Secrets == nil {
		return nil, clerr.New(clerr.KeyringUnavailable, "OS credential store unavailable")
	}
	return r.Secrets.Get(ctx, keyring.CredentialValue(name))
}

func (r *EnvResolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

type Lease struct {
	Profile   string
	BaseURL   string
	Token     string
	ExpiresAt time.Time
}

func (Lease) String() string {
	return "provider proxy lease [REDACTED]"
}

func (Lease) GoString() string {
	return "provider proxy lease [REDACTED]"
}

type ServerOptions struct {
	Profile       profile.Profile
	APIKey        string
	APIKeyBytes   []byte
	Token         string
	Expires       time.Time
	HTTP          *http.Client
	Now           func() time.Time
	ListenAddress string
}

type Server struct {
	profile  profile.Profile
	apiKey   []byte
	token    []byte
	expires  time.Time
	client   *http.Client
	now      func() time.Time
	server   *http.Server
	listener net.Listener
	addr     string
	closeMu  sync.Mutex
	valueMu  sync.RWMutex
	closed   bool
}

func Start(ctx context.Context, options ServerOptions) (*Server, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if options.Profile.Kind != profile.KindProviderProxy {
		return nil, clerr.New(clerr.ProfileKindMismatch, options.Profile.Name)
	}
	apiKey := append([]byte(nil), options.APIKeyBytes...)
	if len(apiKey) == 0 {
		apiKey = []byte(options.APIKey)
	}
	if len(apiKey) == 0 {
		return nil, clerr.New(clerr.KeyringUnavailable, "provider api key missing")
	}
	if options.Token == "" {
		zero(apiKey)
		return nil, clerr.New(clerr.IssueFailed, "local proxy token missing")
	}
	listenAddress := options.ListenAddress
	if listenAddress == "" {
		listenAddress = "127.0.0.1:0"
	}
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		zero(apiKey)
		return nil, clerr.Wrap(clerr.RuntimeUnavailable, "start provider proxy listener", err)
	}

	s := &Server{
		profile:  options.Profile,
		apiKey:   apiKey,
		token:    []byte(options.Token),
		expires:  options.Expires,
		client:   options.HTTP,
		now:      options.Now,
		listener: listener,
		addr:     listener.Addr().String(),
	}
	if s.client == nil {
		s.client = http.DefaultClient
	}
	s.server = &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		err := s.server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			// Errors are returned to clients while running; startup succeeded after Listen.
		}
	}()
	return s, nil
}

func (s *Server) BaseURL() string {
	return "http://" + s.addr + "/" + strings.Trim(s.profile.Name, "/")
}

func (s *Server) Close(ctx context.Context) error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.server == nil || s.closed {
		return nil
	}
	shutdownCtx := ctx
	if shutdownCtx == nil {
		shutdownCtx = context.Background()
	}
	err := s.server.Shutdown(shutdownCtx)
	if err != nil {
		_ = s.server.Close()
	}
	// Shutdown only closes listeners already registered by Serve. Start returns
	// before that goroutine necessarily runs, so retain and close our listener
	// as well to guarantee the gateway is unreachable when Close returns.
	if s.listener != nil {
		if closeErr := s.listener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			err = errors.Join(err, closeErr)
		}
	}
	s.valueMu.Lock()
	zero(s.apiKey)
	zero(s.token)
	s.apiKey = nil
	s.token = nil
	s.valueMu.Unlock()
	s.closed = true
	return err
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.expired() {
		http.Error(w, "proxy token expired", http.StatusUnauthorized)
		return
	}
	if !s.authorized(r) {
		http.Error(w, "proxy token rejected", http.StatusUnauthorized)
		return
	}
	proxyPath, ok := s.proxyPath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !s.methodAllowed(r.Method) {
		http.Error(w, "method not allowed", http.StatusForbidden)
		return
	}
	if !s.pathAllowed(proxyPath) {
		http.Error(w, "path not allowed", http.StatusForbidden)
		return
	}
	s.forward(w, r, proxyPath)
}

func (s *Server) authorized(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return false
	}
	got := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	s.valueMu.RLock()
	defer s.valueMu.RUnlock()
	return subtle.ConstantTimeCompare([]byte(got), s.token) == 1
}

func (s *Server) expired() bool {
	if s.expires.IsZero() {
		return false
	}
	return !s.nowTime().Before(s.expires)
}

func (s *Server) nowTime() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *Server) proxyPath(rawPath string) (string, bool) {
	prefix := "/" + strings.Trim(s.profile.Name, "/")
	if rawPath == prefix {
		return "/", true
	}
	if strings.HasPrefix(rawPath, prefix+"/") {
		return strings.TrimPrefix(rawPath, prefix), true
	}
	return "", false
}

func (s *Server) methodAllowed(method string) bool {
	for _, allowed := range s.profile.AllowedMethods {
		if method == allowed {
			return true
		}
	}
	return false
}

func (s *Server) pathAllowed(requestPath string) bool {
	clean := path.Clean("/" + strings.TrimPrefix(requestPath, "/"))
	for _, allowed := range s.profile.AllowedPaths {
		if clean == path.Clean(allowed) {
			return true
		}
	}
	return false
}

func (s *Server) forward(w http.ResponseWriter, r *http.Request, proxyPath string) {
	target, err := s.targetURL(proxyPath, r.URL.RawQuery)
	if err != nil {
		http.Error(w, "target rejected", http.StatusBadGateway)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target, r.Body)
	if err != nil {
		http.Error(w, "proxy request failed", http.StatusBadGateway)
		return
	}
	copyHeaders(req.Header, r.Header)
	s.valueMu.RLock()
	apiKey := string(s.apiKey)
	s.valueMu.RUnlock()
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Host = ""

	resp, err := s.client.Do(req)
	if err != nil {
		http.Error(w, "provider request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (s *Server) targetURL(proxyPath, rawQuery string) (string, error) {
	base, err := url.Parse(s.profile.TargetURL)
	if err != nil {
		return "", err
	}
	joined := strings.TrimRight(base.Path, "/") + "/" + strings.TrimLeft(proxyPath, "/")
	if proxyPath == "/" {
		joined = strings.TrimRight(base.Path, "/") + "/"
	}
	base.Path = path.Clean(joined)
	if strings.HasSuffix(joined, "/") && !strings.HasSuffix(base.Path, "/") {
		base.Path += "/"
	}
	base.RawQuery = rawQuery
	return base.String(), nil
}

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		if isBlockedHeader(key) {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func isBlockedHeader(key string) bool {
	switch strings.ToLower(key) {
	case "authorization",
		"connection",
		"host",
		"keep-alive",
		"proxy-authenticate",
		"proxy-authorization",
		"te",
		"trailer",
		"transfer-encoding",
		"upgrade":
		return true
	default:
		return false
	}
}

func newLocalToken() (string, error) {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", clerr.Wrap(clerr.IssueFailed, "generate local proxy token", err)
	}
	return "envvault-local-" + hex.EncodeToString(raw[:]), nil
}

func newMetadataID(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", clerr.Wrap(clerr.IssueFailed, "generate connection metadata id", err)
	}
	return prefix + hex.EncodeToString(raw[:]), nil
}

func advertiseBaseURL(baseURL, host string) (string, error) {
	if strings.TrimSpace(host) == "" {
		return baseURL, nil
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Port() == "" {
		return "", clerr.New(clerr.RuntimeIncompatible, "http adapter returned an invalid base url")
	}
	if strings.ContainsAny(host, " /\\?#@\t\r\n") {
		return "", clerr.New(clerr.ConfigInvalid, "advertised gateway host is invalid")
	}
	u.Host = net.JoinHostPort(host, u.Port())
	return u.String(), nil
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
