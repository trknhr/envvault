package issuer

import (
	"context"
	"time"
)

type Grant struct {
	Profile  string
	Resource string
	Scopes   []string
	TTL      time.Duration
	Claims   map[string]any
}

type Credential struct {
	AccessToken string
	TokenType   string
	ExpiresAt   time.Time
	Scopes      []string
}

type Issuer interface {
	Issue(ctx context.Context, grant Grant) (Credential, error)
}
