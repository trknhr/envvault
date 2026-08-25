package connection_test

import (
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/connection"
)

func TestSessionValidateAndActivity(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	session := validSession(now)

	if err := session.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !session.Active(now.Add(29 * time.Minute)) {
		t.Fatal("Active() = false before expiry")
	}
	if session.Active(session.ExpiresAt) {
		t.Fatal("Active() = true at expiry")
	}

	session.Revoked = true
	if session.Active(now) {
		t.Fatal("Active() = true after revocation")
	}
}

func TestSessionValidateRejectsInvalidState(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*connection.Session)
	}{
		{name: "missing id", mutate: func(s *connection.Session) { s.ID = "" }},
		{name: "missing sandbox", mutate: func(s *connection.Session) { s.SandboxID = "" }},
		{name: "missing policy", mutate: func(s *connection.Session) { s.PolicyName = "" }},
		{name: "invalid lifetime", mutate: func(s *connection.Session) { s.ExpiresAt = s.StartedAt }},
		{name: "negative connections", mutate: func(s *connection.Session) { s.ActiveConnections = -1 }},
		{name: "negative bytes in", mutate: func(s *connection.Session) { s.BytesIn = -1 }},
		{name: "negative bytes out", mutate: func(s *connection.Session) { s.BytesOut = -1 }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := validSession(now)
			tt.mutate(&session)
			assertConfigInvalid(t, session.Validate())
		})
	}
}

func validSession(now time.Time) connection.Session {
	return connection.Session{
		ID:                "session-1",
		SandboxID:         "sandbox-1",
		PolicyName:        "openai/dev",
		StartedAt:         now,
		ExpiresAt:         now.Add(30 * time.Minute),
		ActiveConnections: 1,
		BytesIn:           1024,
		BytesOut:          2048,
	}
}
