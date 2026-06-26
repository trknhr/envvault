package profile

import (
	"errors"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
)

type Kind string

const (
	KindProcess        Kind = "process"
	KindBrowserSession Kind = "browser-session"
	KindProviderProxy  Kind = "provider-proxy"
	KindInject         Kind = "inject"
)

type ProjectBindingMode string

const (
	ProjectBindingNone             ProjectBindingMode = "none"
	ProjectBindingPathHash         ProjectBindingMode = "path-hash"
	ProjectBindingGitRemoteAndRoot ProjectBindingMode = "git-remote-and-root"
)

type ProjectBinding struct {
	Mode      ProjectBindingMode
	PathHash  string
	GitRoot   string
	GitRemote string
}

type Profile struct {
	Name     string
	Kind     Kind
	Resource string
	Scopes   []string
	Claims   map[string]string

	ProjectBinding ProjectBinding

	TokenTTL    time.Duration
	MaxTokenTTL time.Duration

	BootstrapTokenTTL time.Duration
	LoginCodeTTL      time.Duration
	WebSessionTTL     time.Duration
	ExchangeURL       string
	CompleteURL       string
	PostLoginURL      string
	AllowedHosts      []string

	CredentialName string
	AuthMode       string
	Provider       string
	TargetURL      string
	AllowedPaths   []string
	AllowedMethods []string
	LocalTokenTTL  time.Duration
}

var errInvalidURL = errors.New("invalid url")

func (p Profile) Validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return configInvalid("profile name is required")
	}
	if err := p.ProjectBinding.validate(); err != nil {
		return err
	}

	switch p.Kind {
	case KindProcess:
		if err := p.validateTokenProfile(); err != nil {
			return err
		}
		return p.validateProcess()
	case KindBrowserSession:
		if err := p.validateTokenProfile(); err != nil {
			return err
		}
		return p.validateBrowserSession()
	case KindProviderProxy:
		return p.validateProviderProxy()
	case KindInject:
		return p.validateInject()
	default:
		return configInvalid("unknown profile kind")
	}
}

func (p Profile) validateTokenProfile() error {
	if err := validateResourceURL(p.Resource); err != nil {
		return err
	}
	if len(p.Scopes) == 0 {
		return configInvalid("at least one scope is required")
	}
	if err := validateClaims(p.Claims); err != nil {
		return err
	}
	return nil
}

func (b ProjectBinding) validate() error {
	switch b.Mode {
	case "", ProjectBindingNone, ProjectBindingPathHash, ProjectBindingGitRemoteAndRoot:
		return nil
	default:
		return configInvalid("unknown project binding mode")
	}
}

func validateClaims(claims map[string]string) error {
	for claim := range claims {
		name := strings.ToLower(strings.TrimSpace(claim))
		if name == "" {
			return configInvalid("claim name is required")
		}
		if reservedJWTClaims[name] {
			return configInvalid("reserved jwt claim is not allowed in profile claims")
		}
		if strings.HasPrefix(name, "envvault_") {
			return configInvalid("envvault claim namespace is reserved")
		}
	}
	return nil
}

var reservedJWTClaims = map[string]bool{
	"iss": true,
	"sub": true,
	"aud": true,
	"exp": true,
	"nbf": true,
	"iat": true,
	"jti": true,
}

func (p Profile) validateProcess() error {
	if p.TokenTTL <= 0 {
		return configInvalid("token ttl must be positive")
	}
	if p.MaxTokenTTL <= 0 {
		return configInvalid("max token ttl must be positive")
	}
	if p.TokenTTL > p.MaxTokenTTL {
		return configInvalid("token ttl exceeds max token ttl")
	}
	return nil
}

func (p Profile) validateBrowserSession() error {
	if p.BootstrapTokenTTL <= 0 {
		return configInvalid("bootstrap token ttl must be positive")
	}
	if p.BootstrapTokenTTL > time.Minute {
		return configInvalid("bootstrap token ttl exceeds 60 seconds")
	}
	if p.LoginCodeTTL <= 0 {
		return configInvalid("login code ttl must be positive")
	}
	if p.LoginCodeTTL > 30*time.Second {
		return configInvalid("login code ttl exceeds 30 seconds")
	}
	if p.WebSessionTTL <= 0 {
		return configInvalid("web session ttl must be positive")
	}
	if len(p.AllowedHosts) == 0 {
		return configInvalid("allowed hosts are required")
	}

	if err := validateHTTPSOrLocalhostURL(p.ExchangeURL, "exchange url"); err != nil {
		return err
	}
	if err := validateHTTPSOrLocalhostURL(p.CompleteURL, "complete url"); err != nil {
		return err
	}
	if err := validateHTTPSOrLocalhostURL(p.PostLoginURL, "post-login url"); err != nil {
		return err
	}
	return nil
}

func (p Profile) validateProviderProxy() error {
	switch strings.TrimSpace(p.Provider) {
	case "", "generic", "openai-compatible":
	default:
		return configInvalid("provider must be generic or openai-compatible")
	}
	switch strings.TrimSpace(p.AuthMode) {
	case "", "bearer":
	default:
		return configInvalid("auth mode must be bearer")
	}
	if strings.TrimSpace(p.CredentialName) == "" {
		return configInvalid("credential is required")
	}
	if err := validateHTTPSOrLocalhostURL(p.TargetURL, "target url"); err != nil {
		return err
	}
	if len(p.AllowedPaths) == 0 {
		return configInvalid("allowed paths are required")
	}
	for _, path := range p.AllowedPaths {
		if err := validateProxyPath(path); err != nil {
			return err
		}
	}
	if len(p.AllowedMethods) == 0 {
		return configInvalid("allowed methods are required")
	}
	for _, method := range p.AllowedMethods {
		if err := validateProxyMethod(method); err != nil {
			return err
		}
	}
	if p.LocalTokenTTL <= 0 {
		return configInvalid("local token ttl must be positive")
	}
	return nil
}

func (p Profile) validateInject() error {
	if strings.TrimSpace(p.CredentialName) == "" {
		return configInvalid("credential is required")
	}
	return nil
}

func ClampTTL(requested, defaultTTL, maxTTL time.Duration) time.Duration {
	effective := requested
	if effective <= 0 {
		effective = defaultTTL
	}
	if maxTTL > 0 && effective > maxTTL {
		return maxTTL
	}
	return effective
}

func (p Profile) AllowsScopes(requested []string) bool {
	allowed := make(map[string]struct{}, len(p.Scopes))
	for _, scope := range p.Scopes {
		allowed[scope] = struct{}{}
	}
	for _, scope := range requested {
		if _, ok := allowed[scope]; !ok {
			return false
		}
	}
	return true
}

func (p Profile) ValidateLaunchURL(rawURL string) error {
	launch, err := parseAbsoluteURL(rawURL)
	if err != nil {
		return browserURLRejected("launch url is invalid")
	}
	complete, err := parseAbsoluteURL(p.CompleteURL)
	if err != nil {
		return browserURLRejected("complete url is invalid")
	}

	if launch.User != nil {
		return browserURLRejected("launch url userinfo is not allowed")
	}
	if launch.Fragment != "" {
		return browserURLRejected("launch url fragment is not allowed")
	}
	if launch.Scheme != complete.Scheme || !strings.EqualFold(launch.Host, complete.Host) || launch.EscapedPath() != complete.EscapedPath() {
		return browserURLRejected("launch url does not match profile complete url")
	}
	if !isHTTPSOrLocalhostHTTP(launch) {
		return browserURLRejected("launch url must use https or localhost http")
	}
	if !p.hostAllowed(launch) {
		return browserURLRejected("launch url host is not allowed")
	}
	return nil
}

func (p Profile) hostAllowed(u *url.URL) bool {
	host := strings.ToLower(u.Host)
	hostname := strings.ToLower(u.Hostname())
	for _, allowed := range p.AllowedHosts {
		allowed = strings.ToLower(strings.TrimSpace(allowed))
		if allowed == "" {
			continue
		}
		if allowed == host || allowed == hostname {
			return true
		}
	}
	return false
}

func validateResourceURL(raw string) error {
	u, err := parseAbsoluteURL(raw)
	if err != nil {
		return configInvalid("resource url is invalid")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return configInvalid("resource url must use http or https")
	}
	return nil
}

func validateHTTPSOrLocalhostURL(raw, name string) error {
	u, err := parseAbsoluteURL(raw)
	if err != nil {
		return configInvalid(name + " is invalid")
	}
	if !isHTTPSOrLocalhostHTTP(u) {
		return configInvalid(name + " must use https or localhost http")
	}
	return nil
}

func parseAbsoluteURL(raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errInvalidURL
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, errInvalidURL
	}
	return u, nil
}

func validateProxyPath(path string) error {
	if path == "" || !strings.HasPrefix(path, "/") {
		return configInvalid("allowed path must start with /")
	}
	if strings.ContainsAny(path, "?#\\") {
		return configInvalid("allowed path must not include query, fragment, or backslash")
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return configInvalid("allowed path traversal segment is not allowed")
		}
	}
	return nil
}

func validateProxyMethod(method string) error {
	trimmed := strings.TrimSpace(method)
	if trimmed == "" || trimmed != strings.ToUpper(trimmed) {
		return configInvalid("allowed method must be uppercase")
	}
	for _, r := range trimmed {
		if r < 'A' || r > 'Z' {
			return configInvalid("allowed method must contain only letters")
		}
	}
	return nil
}

func isHTTPSOrLocalhostHTTP(u *url.URL) bool {
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func configInvalid(message string) error {
	return clerr.New(clerr.ConfigInvalid, message)
}

func browserURLRejected(message string) error {
	return clerr.New(clerr.BrowserURLRejected, message)
}
