package connection

import (
	"context"
	"time"
)

type SecurityLevel string

const (
	SecurityMaterializedStatic SecurityLevel = "materialized-static"
	SecurityMaterializedLeased SecurityLevel = "materialized-leased"
	SecurityBrokered           SecurityLevel = "brokered"
	SecurityBrokeredEnforced   SecurityLevel = "brokered-enforced"
)

type EgressPolicy struct {
	Destinations []Destination
}

type EgressEnforcer interface {
	Attach(ctx context.Context, sandboxID string, policy EgressPolicy) error
	Detach(ctx context.Context, sandboxID string) error
	Level() SecurityLevel
}

// EgressRoute binds one validated policy to the non-secret grant metadata used
// for an outbound broker session. Credential material is acquired separately
// through EgressBrokerStartRequest.Credentials.
type EgressRoute struct {
	Policy Policy
	Grant  Grant
}

type EgressBrokerStartRequest struct {
	Routes      []EgressRoute
	Credentials CredentialProvider
}

// EgressClientConfig contains only values that may be delivered to an
// untrusted sandbox. ProxyURL may contain a short-lived capability and must be
// redacted from logs. CACertificatePEM is public certificate material; the CA
// private key remains in the trusted broker. CredentialReferences are
// non-secret handles that the broker accepts for late-bound authentication.
type EgressClientConfig struct {
	ProxyURL             string
	CACertificatePEM     []byte
	CredentialReferences []string
}

func (EgressClientConfig) String() string {
	return "egress client config [REDACTED]"
}

func (EgressClientConfig) GoString() string {
	return "egress client config [REDACTED]"
}

type EgressBroker interface {
	Start(ctx context.Context, request EgressBrokerStartRequest) (EgressLease, error)
}

type EgressLease interface {
	Endpoint() Endpoint
	ClientConfig() EgressClientConfig
	ExpiresAt() time.Time
	Close(ctx context.Context) error
}
