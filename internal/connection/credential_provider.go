package connection

import (
	"context"
	"time"
)

type CredentialRequest struct {
	SessionID string
	SubjectID string
	Spec      CredentialSpec
	TTL       time.Duration
}

// CredentialLease deliberately exposes credential material only through a
// callback. Implementations must not serialize it or include it in String or
// error output, and should clear owned buffers when the callback returns.
type CredentialLease interface {
	ID() string
	ExpiresAt() time.Time
	WithValue(ctx context.Context, use func([]byte) error) error
}

type CredentialProvider interface {
	Acquire(ctx context.Context, request CredentialRequest) (CredentialLease, error)
	Revoke(ctx context.Context, lease CredentialLease) error
}
