package connection

import (
	"strings"
	"time"
)

// Grant is the non-secret metadata for a short-lived connection capability.
// The opaque capability value is intentionally managed outside this model.
type Grant struct {
	ID             string
	SessionID      string
	SubjectID      string
	PolicyName     string
	PolicyRevision string
	Protocol       ProtocolType
	Destination    Destination
	IssuedAt       time.Time
	ExpiresAt      time.Time
	MaxConnections int
	MaxBytes       int64
}

func (g Grant) Validate() error {
	if strings.TrimSpace(g.ID) == "" {
		return configInvalid("connection grant id is required")
	}
	if strings.TrimSpace(g.SessionID) == "" {
		return configInvalid("connection grant session id is required")
	}
	if strings.TrimSpace(g.SubjectID) == "" {
		return configInvalid("connection grant subject id is required")
	}
	if strings.TrimSpace(g.PolicyName) == "" {
		return configInvalid("connection grant policy name is required")
	}
	if strings.TrimSpace(g.PolicyRevision) == "" {
		return configInvalid("connection grant policy revision is required")
	}
	if !g.Protocol.valid() {
		return configInvalid("connection grant protocol is invalid")
	}
	if err := g.Destination.Validate(); err != nil {
		return err
	}
	if g.IssuedAt.IsZero() || g.ExpiresAt.IsZero() || !g.ExpiresAt.After(g.IssuedAt) {
		return configInvalid("connection grant lifetime is invalid")
	}
	if g.MaxConnections <= 0 {
		return configInvalid("connection grant max connections must be positive")
	}
	if g.MaxBytes < 0 {
		return configInvalid("connection grant max bytes must not be negative")
	}
	return nil
}

func (g Grant) Expired(now time.Time) bool {
	return g.ExpiresAt.IsZero() || !now.Before(g.ExpiresAt)
}
