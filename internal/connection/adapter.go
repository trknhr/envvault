package connection

import (
	"context"
	"time"
)

type Endpoint struct {
	Network string
	Address string
}

type AdapterStartRequest struct {
	Policy      Policy
	Grant       Grant
	Credentials CredentialProvider
}

type ProtocolAdapter interface {
	Protocol() ProtocolType
	Validate(policy Policy) error
	Start(ctx context.Context, request AdapterStartRequest) (AdapterLease, error)
}

type AdapterLease interface {
	Endpoint() Endpoint
	ExpiresAt() time.Time
	Close(ctx context.Context) error
}
