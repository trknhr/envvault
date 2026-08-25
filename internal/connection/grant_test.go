package connection_test

import (
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/connection"
)

func TestGrantValidateAndExpiry(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	grant := validGrant(now)

	if err := grant.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if grant.Expired(now.Add(29 * time.Minute)) {
		t.Fatal("Expired() = true before expiry")
	}
	if !grant.Expired(grant.ExpiresAt) {
		t.Fatal("Expired() = false at expiry")
	}
}

func TestGrantValidateRejectsInvalidMetadata(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*connection.Grant)
	}{
		{name: "missing id", mutate: func(g *connection.Grant) { g.ID = "" }},
		{name: "missing session", mutate: func(g *connection.Grant) { g.SessionID = "" }},
		{name: "missing subject", mutate: func(g *connection.Grant) { g.SubjectID = "" }},
		{name: "missing policy", mutate: func(g *connection.Grant) { g.PolicyName = "" }},
		{name: "missing revision", mutate: func(g *connection.Grant) { g.PolicyRevision = "" }},
		{name: "unknown protocol", mutate: func(g *connection.Grant) { g.Protocol = connection.ProtocolType("smtp") }},
		{name: "invalid lifetime", mutate: func(g *connection.Grant) { g.ExpiresAt = g.IssuedAt }},
		{name: "invalid connections", mutate: func(g *connection.Grant) { g.MaxConnections = 0 }},
		{name: "invalid bytes", mutate: func(g *connection.Grant) { g.MaxBytes = -1 }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grant := validGrant(now)
			tt.mutate(&grant)
			assertConfigInvalid(t, grant.Validate())
		})
	}
}

func validGrant(now time.Time) connection.Grant {
	return connection.Grant{
		ID:             "grant-1",
		SessionID:      "session-1",
		SubjectID:      "sandbox-1",
		PolicyName:     "openai/dev",
		PolicyRevision: "revision-1",
		Protocol:       connection.ProtocolHTTP,
		Destination:    connection.Destination{Host: "api.openai.com", Port: 443},
		IssuedAt:       now,
		ExpiresAt:      now.Add(30 * time.Minute),
		MaxConnections: 8,
		MaxBytes:       100 << 20,
	}
}
