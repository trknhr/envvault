package connection_test

import (
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/connection"
)

func TestPolicyValidateAcceptsHTTPProxy(t *testing.T) {
	policy := validHTTPPolicy()

	if err := policy.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestPolicyValidateAcceptsPostgresProxy(t *testing.T) {
	policy := validPostgresPolicy()

	if err := policy.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestProtocolSpecValidateAcceptsEachTypedArm(t *testing.T) {
	destination := connection.Destination{Host: "service.internal", Port: 443}
	tests := []struct {
		name string
		spec connection.ProtocolSpec
	}{
		{
			name: "http",
			spec: validHTTPPolicy().Protocol,
		},
		{
			name: "postgres",
			spec: validPostgresPolicy().Protocol,
		},
		{
			name: "mysql",
			spec: connection.ProtocolSpec{Type: connection.ProtocolMySQL, MySQL: &connection.MySQLPolicy{}},
		},
		{
			name: "redis",
			spec: connection.ProtocolSpec{Type: connection.ProtocolRedis, Redis: &connection.RedisPolicy{}},
		},
		{
			name: "ssh",
			spec: connection.ProtocolSpec{Type: connection.ProtocolSSH, SSH: &connection.SSHPolicy{}},
		},
		{
			name: "tcp",
			spec: connection.ProtocolSpec{Type: connection.ProtocolTCP, TCP: &connection.TCPPolicy{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.spec.Validate(destination); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestProtocolSpecValidateRejectsInvalidUnion(t *testing.T) {
	tests := []struct {
		name string
		spec connection.ProtocolSpec
	}{
		{
			name: "unknown protocol",
			spec: connection.ProtocolSpec{Type: connection.ProtocolType("smtp"), TCP: &connection.TCPPolicy{}},
		},
		{
			name: "missing policy",
			spec: connection.ProtocolSpec{Type: connection.ProtocolHTTP},
		},
		{
			name: "multiple policies",
			spec: connection.ProtocolSpec{
				Type: connection.ProtocolHTTP,
				HTTP: &connection.HTTPPolicy{},
				TCP:  &connection.TCPPolicy{},
			},
		},
		{
			name: "type mismatch",
			spec: connection.ProtocolSpec{Type: connection.ProtocolHTTP, TCP: &connection.TCPPolicy{}},
		},
		{
			name: "invalid postgres policy",
			spec: connection.ProtocolSpec{
				Type: connection.ProtocolPostgres,
				Postgres: &connection.PostgresPolicy{
					Database: "application",
					TLS:      connection.TLSPolicy{Mode: connection.TLSVerifyFull},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.spec.Validate(connection.Destination{Host: "service.internal", Port: 443})
			assertConfigInvalid(t, err)
		})
	}
}

func TestAuthenticationValidateKeepsDeliveryAndIssuanceIndependent(t *testing.T) {
	tests := []struct {
		name     string
		protocol connection.ProtocolType
		auth     connection.Authentication
	}{
		{
			name:     "proxy static",
			protocol: connection.ProtocolHTTP,
			auth:     validAuthentication(connection.DeliveryProxy, connection.IssuanceStatic, 0),
		},
		{
			name:     "proxy dynamic",
			protocol: connection.ProtocolPostgres,
			auth:     validAuthentication(connection.DeliveryProxy, connection.IssuanceDynamic, 15*time.Minute),
		},
		{
			name:     "materialize static",
			protocol: connection.ProtocolTCP,
			auth:     validAuthentication(connection.DeliveryMaterialize, connection.IssuanceStatic, 0),
		},
		{
			name:     "materialize dynamic",
			protocol: connection.ProtocolTCP,
			auth:     validAuthentication(connection.DeliveryMaterialize, connection.IssuanceDynamic, 15*time.Minute),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.auth.Validate(tt.protocol); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestAuthenticationValidateRejectsInvalidCombinations(t *testing.T) {
	tests := []struct {
		name     string
		protocol connection.ProtocolType
		auth     connection.Authentication
	}{
		{
			name:     "unknown delivery",
			protocol: connection.ProtocolHTTP,
			auth:     validAuthentication(connection.DeliveryMode("copy"), connection.IssuanceStatic, 0),
		},
		{
			name:     "unknown issuance",
			protocol: connection.ProtocolHTTP,
			auth:     validAuthentication(connection.DeliveryProxy, connection.IssuanceMode("rotated"), 0),
		},
		{
			name:     "missing provider",
			protocol: connection.ProtocolHTTP,
			auth: func() connection.Authentication {
				auth := validAuthentication(connection.DeliveryProxy, connection.IssuanceStatic, 0)
				auth.Credential.Provider = ""
				return auth
			}(),
		},
		{
			name:     "missing reference",
			protocol: connection.ProtocolHTTP,
			auth: func() connection.Authentication {
				auth := validAuthentication(connection.DeliveryProxy, connection.IssuanceStatic, 0)
				auth.Credential.Ref = ""
				return auth
			}(),
		},
		{
			name:     "dynamic without ttl",
			protocol: connection.ProtocolPostgres,
			auth:     validAuthentication(connection.DeliveryProxy, connection.IssuanceDynamic, 0),
		},
		{
			name:     "static negative ttl",
			protocol: connection.ProtocolHTTP,
			auth:     validAuthentication(connection.DeliveryProxy, connection.IssuanceStatic, -time.Second),
		},
		{
			name:     "generic tcp proxy",
			protocol: connection.ProtocolTCP,
			auth:     validAuthentication(connection.DeliveryProxy, connection.IssuanceStatic, 0),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertConfigInvalid(t, tt.auth.Validate(tt.protocol))
		})
	}
}

func TestPolicyValidateRejectsInvalidPolicyFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*connection.Policy)
	}{
		{name: "missing name", mutate: func(p *connection.Policy) { p.Name = "" }},
		{name: "host contains scheme", mutate: func(p *connection.Policy) { p.Destination.Host = "https://api.openai.com" }},
		{name: "missing port", mutate: func(p *connection.Policy) { p.Destination.Port = 0 }},
		{name: "plaintext remote http", mutate: func(p *connection.Policy) { p.Protocol.HTTP.Scheme = connection.HTTPSchemeHTTP }},
		{name: "blocked auth header", mutate: func(p *connection.Policy) { p.Protocol.HTTP.Auth.Header = "Proxy-Authorization" }},
		{name: "missing base path", mutate: func(p *connection.Policy) { p.Protocol.HTTP.BasePath = "" }},
		{name: "base path traversal", mutate: func(p *connection.Policy) { p.Protocol.HTTP.BasePath = "/v1/../admin" }},
		{name: "unknown provider strategy", mutate: func(p *connection.Policy) {
			p.Protocol.HTTP.ProviderStrategy = connection.HTTPProviderStrategy("unknown")
		}},
		{name: "lowercase method", mutate: func(p *connection.Policy) { p.Protocol.HTTP.AllowedMethods = []string{"post"} }},
		{name: "path traversal", mutate: func(p *connection.Policy) { p.Protocol.HTTP.AllowedPaths = []string{"/v1/../admin"} }},
		{name: "missing session ttl", mutate: func(p *connection.Policy) { p.Limits.SessionTTL = 0 }},
		{name: "idle exceeds session", mutate: func(p *connection.Policy) { p.Limits.IdleTimeout = time.Hour }},
		{name: "negative connection limit", mutate: func(p *connection.Policy) { p.Limits.MaxConnections = -1 }},
		{name: "negative byte limit", mutate: func(p *connection.Policy) { p.Limits.MaxBytes = -1 }},
		{name: "payload audit", mutate: func(p *connection.Policy) { p.Audit.Payloads = true }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := validHTTPPolicy()
			tt.mutate(&policy)
			assertConfigInvalid(t, policy.Validate())
		})
	}
}

func validHTTPPolicy() connection.Policy {
	return connection.Policy{
		Name:        "openai/dev",
		Destination: connection.Destination{Host: "api.openai.com", Port: 443},
		Protocol: connection.ProtocolSpec{
			Type: connection.ProtocolHTTP,
			HTTP: &connection.HTTPPolicy{
				Scheme:           connection.HTTPSchemeHTTPS,
				BasePath:         "/",
				ProviderStrategy: connection.HTTPProviderOpenAICompatible,
				Auth: connection.HTTPAuthPolicy{
					Type:   connection.HTTPAuthBearer,
					Header: "Authorization",
				},
				AllowedMethods: []string{"POST"},
				AllowedPaths:   []string{"/v1/responses"},
			},
		},
		Authentication: validAuthentication(connection.DeliveryProxy, connection.IssuanceStatic, 0),
		Limits: connection.Limits{
			SessionTTL:     30 * time.Minute,
			IdleTimeout:    5 * time.Minute,
			MaxConnections: 8,
			MaxBytes:       100 << 20,
		},
		Audit: connection.AuditPolicy{Connections: true},
	}
}

func validPostgresPolicy() connection.Policy {
	return connection.Policy{
		Name:        "postgres/dev",
		Destination: connection.Destination{Host: "db.internal", Port: 5432},
		Protocol: connection.ProtocolSpec{
			Type: connection.ProtocolPostgres,
			Postgres: &connection.PostgresPolicy{
				Database: "application",
				TLS: connection.TLSPolicy{
					Mode:       connection.TLSVerifyFull,
					ServerName: "db.internal",
				},
			},
		},
		Authentication: validAuthentication(connection.DeliveryProxy, connection.IssuanceStatic, 0),
		Limits: connection.Limits{
			SessionTTL:     30 * time.Minute,
			IdleTimeout:    5 * time.Minute,
			MaxConnections: 4,
			MaxBytes:       1 << 30,
		},
		Audit: connection.AuditPolicy{Connections: true},
	}
}

func validAuthentication(delivery connection.DeliveryMode, issuance connection.IssuanceMode, maxTTL time.Duration) connection.Authentication {
	return connection.Authentication{
		Delivery: delivery,
		Credential: connection.CredentialSpec{
			Provider: "keyring",
			Ref:      "envvault://credential/dev",
			Issuance: issuance,
			MaxTTL:   maxTTL,
		},
	}
}

func assertConfigInvalid(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("error = nil, want config error")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.ConfigInvalid {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.ConfigInvalid)
	}
}
