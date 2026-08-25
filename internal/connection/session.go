package connection

import (
	"strings"
	"time"
)

// Session tracks non-secret runtime state for one sandbox connection session.
type Session struct {
	ID                string
	SandboxID         string
	PolicyName        string
	StartedAt         time.Time
	ExpiresAt         time.Time
	ActiveConnections int
	BytesIn           int64
	BytesOut          int64
	Revoked           bool
}

func (s Session) Validate() error {
	if strings.TrimSpace(s.ID) == "" {
		return configInvalid("connection session id is required")
	}
	if strings.TrimSpace(s.SandboxID) == "" {
		return configInvalid("connection session sandbox id is required")
	}
	if strings.TrimSpace(s.PolicyName) == "" {
		return configInvalid("connection session policy name is required")
	}
	if s.StartedAt.IsZero() || s.ExpiresAt.IsZero() || !s.ExpiresAt.After(s.StartedAt) {
		return configInvalid("connection session lifetime is invalid")
	}
	if s.ActiveConnections < 0 {
		return configInvalid("active connection count must not be negative")
	}
	if s.BytesIn < 0 || s.BytesOut < 0 {
		return configInvalid("connection byte counts must not be negative")
	}
	return nil
}

func (s Session) Expired(now time.Time) bool {
	return s.ExpiresAt.IsZero() || !now.Before(s.ExpiresAt)
}

func (s Session) Active(now time.Time) bool {
	return !s.Revoked && !s.Expired(now)
}
