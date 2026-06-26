package providerproxy

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/envref"
	"github.com/trknhr/envvault/internal/issuer"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/process"
	"github.com/trknhr/envvault/internal/profile"
	"github.com/trknhr/envvault/internal/projectbinding"
)

type ProfileResolver interface {
	Profile(name string) (profile.Profile, error)
}

type EnvResolver struct {
	Profiles ProfileResolver
	Secrets  keyring.Store
	Issuer   issuer.Issuer
	HTTP     *http.Client
	Now      func() time.Time

	mu      sync.Mutex
	leases  map[string]*Lease
	servers []*Server
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
		return r.issueProcessToken(ctx, ref.Profile, identity)
	default:
		return "", clerr.New(clerr.ReferenceInvalid, "unknown reference part")
	}
}

func (r *EnvResolver) Close(ctx context.Context) error {
	r.mu.Lock()
	servers := append([]*Server(nil), r.servers...)
	r.servers = nil
	r.leases = nil
	r.mu.Unlock()

	var err error
	for _, server := range servers {
		if closeErr := server.Close(ctx); closeErr != nil && err == nil {
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
	secret, err := r.secret(ctx, name)
	if err != nil {
		return nil, err
	}
	defer zero(secret)

	token, err := newLocalToken()
	if err != nil {
		return nil, err
	}
	server, err := Start(ctx, ServerOptions{
		Profile: p,
		APIKey:  string(secret),
		Token:   token,
		HTTP:    r.HTTP,
		Now:     r.Now,
		Expires: r.now().Add(p.LocalTokenTTL),
	})
	if err != nil {
		return nil, err
	}

	lease := &Lease{
		Profile:   name,
		BaseURL:   server.BaseURL(),
		Token:     token,
		ExpiresAt: r.now().Add(p.LocalTokenTTL),
	}

	r.mu.Lock()
	if existing := r.leases[name]; existing != nil {
		r.mu.Unlock()
		_ = server.Close(context.Background())
		return existing, nil
	}
	r.leases[name] = lease
	r.servers = append(r.servers, server)
	r.mu.Unlock()
	return lease, nil
}

func (r *EnvResolver) issueProcessToken(ctx context.Context, name string, identity projectbinding.Identity) (string, error) {
	p, err := r.profile(name)
	if err != nil {
		return "", err
	}
	if p.Kind != profile.KindProcess {
		return "", clerr.New(clerr.ProfileKindMismatch, name)
	}
	if r.Issuer == nil {
		return "", clerr.New(clerr.IssueFailed, "process token issuer is unavailable")
	}
	if err := projectbinding.Check(p.ProjectBinding, identity); err != nil {
		return "", err
	}
	claims, err := process.ProcessClaims(p, identity)
	if err != nil {
		return "", err
	}
	credential, err := r.Issuer.Issue(ctx, issuer.Grant{
		Profile:  p.Name,
		Resource: p.Resource,
		Scopes:   append([]string(nil), p.Scopes...),
		TTL:      p.TokenTTL,
		Claims:   claims,
	})
	if err != nil {
		return "", err
	}
	return credential.AccessToken, nil
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
	return r.Secrets.Get(ctx, keyring.ProviderAPIKey(name))
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

type ServerOptions struct {
	Profile profile.Profile
	APIKey  string
	Token   string
	Expires time.Time
	HTTP    *http.Client
	Now     func() time.Time
}

type Server struct {
	profile profile.Profile
	apiKey  string
	token   string
	expires time.Time
	client  *http.Client
	now     func() time.Time
	server  *http.Server
	addr    string
}

func Start(ctx context.Context, options ServerOptions) (*Server, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if options.Profile.Kind != profile.KindProviderProxy {
		return nil, clerr.New(clerr.ProfileKindMismatch, options.Profile.Name)
	}
	if options.APIKey == "" {
		return nil, clerr.New(clerr.KeyringUnavailable, "provider api key missing")
	}
	if options.Token == "" {
		return nil, clerr.New(clerr.IssueFailed, "local proxy token missing")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, clerr.Wrap(clerr.RuntimeUnavailable, "start provider proxy listener", err)
	}

	s := &Server{
		profile: options.Profile,
		apiKey:  options.APIKey,
		token:   options.Token,
		expires: options.Expires,
		client:  options.HTTP,
		now:     options.Now,
		addr:    listener.Addr().String(),
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
	if s.server == nil {
		return nil
	}
	shutdownCtx := ctx
	if shutdownCtx == nil {
		shutdownCtx = context.Background()
	}
	return s.server.Shutdown(shutdownCtx)
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
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1
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
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
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

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
