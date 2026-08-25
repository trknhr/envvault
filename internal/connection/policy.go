package connection

import (
	"net"
	"strings"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
)

// Policy describes a repository-safe connection authorization. It contains
// references to credentials, never credential values.
type Policy struct {
	Name           string
	Destination    Destination
	Protocol       ProtocolSpec
	Authentication Authentication
	Limits         Limits
	Audit          AuditPolicy
}

func (p Policy) Validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return configInvalid("connection policy name is required")
	}
	if err := p.Destination.Validate(); err != nil {
		return err
	}
	if err := p.Protocol.Validate(p.Destination); err != nil {
		return err
	}
	if err := p.Authentication.Validate(p.Protocol.Type); err != nil {
		return err
	}
	if err := p.Limits.Validate(); err != nil {
		return err
	}
	return p.Audit.Validate()
}

type Destination struct {
	Host string
	Port uint16
}

func (d Destination) Validate() error {
	host := strings.TrimSpace(d.Host)
	if host == "" {
		return configInvalid("destination host is required")
	}
	if !validHost(host) {
		return configInvalid("destination host must be a hostname or IP address")
	}
	if d.Port == 0 {
		return configInvalid("destination port is required")
	}
	return nil
}

type ProtocolType string

const (
	ProtocolHTTP     ProtocolType = "http"
	ProtocolPostgres ProtocolType = "postgres"
	ProtocolMySQL    ProtocolType = "mysql"
	ProtocolRedis    ProtocolType = "redis"
	ProtocolSSH      ProtocolType = "ssh"
	ProtocolTCP      ProtocolType = "tcp"
)

func (p ProtocolType) valid() bool {
	switch p {
	case ProtocolHTTP, ProtocolPostgres, ProtocolMySQL, ProtocolRedis, ProtocolSSH, ProtocolTCP:
		return true
	default:
		return false
	}
}

// ProtocolSpec is a discriminated union. Exactly one protocol policy must be
// present, and it must match Type.
type ProtocolSpec struct {
	Type     ProtocolType
	HTTP     *HTTPPolicy
	Postgres *PostgresPolicy
	MySQL    *MySQLPolicy
	Redis    *RedisPolicy
	SSH      *SSHPolicy
	TCP      *TCPPolicy
}

func (p ProtocolSpec) Validate(destination Destination) error {
	if !p.Type.valid() {
		return configInvalid("unknown connection protocol")
	}
	if p.policyCount() != 1 {
		return configInvalid("exactly one protocol policy is required")
	}

	switch p.Type {
	case ProtocolHTTP:
		if p.HTTP == nil {
			return configInvalid("protocol type does not match protocol policy")
		}
		return p.HTTP.Validate(destination)
	case ProtocolPostgres:
		if p.Postgres == nil {
			return configInvalid("protocol type does not match protocol policy")
		}
		return p.Postgres.Validate()
	case ProtocolMySQL:
		if p.MySQL == nil {
			return configInvalid("protocol type does not match protocol policy")
		}
	case ProtocolRedis:
		if p.Redis == nil {
			return configInvalid("protocol type does not match protocol policy")
		}
	case ProtocolSSH:
		if p.SSH == nil {
			return configInvalid("protocol type does not match protocol policy")
		}
	case ProtocolTCP:
		if p.TCP == nil {
			return configInvalid("protocol type does not match protocol policy")
		}
	}
	return nil
}

func (p ProtocolSpec) policyCount() int {
	count := 0
	for _, present := range []bool{
		p.HTTP != nil,
		p.Postgres != nil,
		p.MySQL != nil,
		p.Redis != nil,
		p.SSH != nil,
		p.TCP != nil,
	} {
		if present {
			count++
		}
	}
	return count
}

type HTTPScheme string

const (
	HTTPSchemeHTTP  HTTPScheme = "http"
	HTTPSchemeHTTPS HTTPScheme = "https"
)

type HTTPAuthType string

const (
	HTTPAuthBearer HTTPAuthType = "bearer"
)

// HTTPProviderStrategy identifies provider-specific HTTP behavior without
// coupling credential acquisition to an API vendor.
type HTTPProviderStrategy string

const (
	HTTPProviderGeneric          HTTPProviderStrategy = "generic"
	HTTPProviderOpenAICompatible HTTPProviderStrategy = "openai-compatible"
)

type HTTPPolicy struct {
	Scheme           HTTPScheme
	BasePath         string
	ProviderStrategy HTTPProviderStrategy
	Auth             HTTPAuthPolicy
	AllowedMethods   []string
	AllowedPaths     []string
}

type HTTPAuthPolicy struct {
	Type   HTTPAuthType
	Header string
}

func (p HTTPPolicy) Validate(destination Destination) error {
	switch p.Scheme {
	case HTTPSchemeHTTPS:
	case HTTPSchemeHTTP:
		if !isLoopbackHost(destination.Host) {
			return configInvalid("http connections are allowed only for loopback destinations")
		}
	default:
		return configInvalid("http scheme must be http or https")
	}
	if !validHTTPPath(p.BasePath) {
		return configInvalid("http base path must be absolute and traversal-free")
	}
	switch p.ProviderStrategy {
	case HTTPProviderGeneric, HTTPProviderOpenAICompatible:
	default:
		return configInvalid("unknown http provider strategy")
	}

	if p.Auth.Type != HTTPAuthBearer {
		return configInvalid("http authentication type must be bearer")
	}
	if !validHTTPHeaderName(p.Auth.Header) || blockedInjectionHeader(p.Auth.Header) {
		return configInvalid("http authentication header is invalid")
	}
	if len(p.AllowedMethods) == 0 {
		return configInvalid("at least one http method is required")
	}
	for _, method := range p.AllowedMethods {
		if !validHTTPMethod(method) {
			return configInvalid("http methods must contain only uppercase letters")
		}
	}
	if len(p.AllowedPaths) == 0 {
		return configInvalid("at least one http path is required")
	}
	for _, path := range p.AllowedPaths {
		if !validHTTPPath(path) {
			return configInvalid("http paths must be absolute and traversal-free")
		}
	}
	return nil
}

type TLSMode string

const (
	TLSVerifyFull TLSMode = "verify-full"
)

type TLSPolicy struct {
	Mode       TLSMode
	ServerName string
}

func (p TLSPolicy) Validate() error {
	if p.Mode != TLSVerifyFull {
		return configInvalid("tls mode must be verify-full")
	}
	if !validHost(strings.TrimSpace(p.ServerName)) {
		return configInvalid("tls server name must be a hostname or IP address")
	}
	return nil
}

type PostgresPolicy struct {
	Database string
	TLS      TLSPolicy
}

func (p PostgresPolicy) Validate() error {
	if strings.TrimSpace(p.Database) == "" {
		return configInvalid("postgres database is required")
	}
	return p.TLS.Validate()
}

// The remaining protocol policies intentionally reserve typed extension
// points. Their fields and validation will be defined in protocol-specific
// RFCs before an adapter is implemented.
type MySQLPolicy struct{}

type RedisPolicy struct{}

type SSHPolicy struct{}

type TCPPolicy struct{}

type DeliveryMode string

const (
	DeliveryProxy       DeliveryMode = "proxy"
	DeliveryMaterialize DeliveryMode = "materialize"
)

type IssuanceMode string

const (
	IssuanceStatic  IssuanceMode = "static"
	IssuanceDynamic IssuanceMode = "dynamic"
)

type Authentication struct {
	Delivery   DeliveryMode
	Credential CredentialSpec
}

func (a Authentication) Validate(protocol ProtocolType) error {
	switch a.Delivery {
	case DeliveryProxy, DeliveryMaterialize:
	default:
		return configInvalid("unknown credential delivery mode")
	}
	if protocol == ProtocolTCP && a.Delivery == DeliveryProxy {
		return configInvalid("tcp proxy delivery requires a protocol-specific authentication strategy")
	}
	return a.Credential.Validate()
}

type CredentialSpec struct {
	Provider string
	Ref      string
	Issuance IssuanceMode
	MaxTTL   time.Duration
}

func (c CredentialSpec) Validate() error {
	if strings.TrimSpace(c.Provider) == "" {
		return configInvalid("credential provider is required")
	}
	if strings.TrimSpace(c.Ref) == "" {
		return configInvalid("credential reference is required")
	}
	switch c.Issuance {
	case IssuanceStatic:
		if c.MaxTTL < 0 {
			return configInvalid("credential max ttl must not be negative")
		}
	case IssuanceDynamic:
		if c.MaxTTL <= 0 {
			return configInvalid("dynamic credentials require a positive max ttl")
		}
	default:
		return configInvalid("unknown credential issuance mode")
	}
	return nil
}

type Limits struct {
	SessionTTL  time.Duration
	IdleTimeout time.Duration
	// MaxConnections is zero when a compatibility source has no equivalent
	// limit. Grant issuance must resolve zero to an explicit positive limit.
	MaxConnections int
	// MaxBytes is zero when no byte limit is specified.
	MaxBytes int64
}

func (l Limits) Validate() error {
	if l.SessionTTL <= 0 {
		return configInvalid("session ttl must be positive")
	}
	if l.IdleTimeout < 0 {
		return configInvalid("idle timeout must not be negative")
	}
	if l.IdleTimeout > l.SessionTTL {
		return configInvalid("idle timeout must not exceed session ttl")
	}
	if l.MaxConnections < 0 {
		return configInvalid("max connections must not be negative")
	}
	if l.MaxBytes < 0 {
		return configInvalid("max bytes must not be negative")
	}
	return nil
}

type AuditPolicy struct {
	Connections bool
	Payloads    bool
}

func (a AuditPolicy) Validate() error {
	if a.Payloads {
		return configInvalid("connection payload auditing is not supported")
	}
	return nil
}

func validHost(host string) bool {
	if host == "" || strings.ContainsAny(host, " /\\?#@\t\r\n") || strings.Contains(host, "://") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) > 253 {
		return false
	}
	trimmed := strings.TrimSuffix(host, ".")
	if trimmed == "" {
		return false
	}
	for _, label := range strings.Split(trimmed, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validHTTPMethod(method string) bool {
	if method == "" || method != strings.ToUpper(method) {
		return false
	}
	for _, r := range method {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}

func validHTTPPath(path string) bool {
	if path == "" || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#\\") {
		return false
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func validHTTPHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		switch r {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

func blockedInjectionHeader(name string) bool {
	switch strings.ToLower(name) {
	case "connection", "content-length", "host", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

func configInvalid(message string) error {
	return clerr.New(clerr.ConfigInvalid, message)
}
