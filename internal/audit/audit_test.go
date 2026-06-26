package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/audit"
)

func TestFileRecorderAppendsMetadataOnlyJSONLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit", "events.jsonl")
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	recorder := audit.FileRecorder{
		Path: path,
		Now:  func() time.Time { return now },
	}

	err := recorder.Record(context.Background(), audit.Event{
		Event:      audit.EventCredentialIssued,
		Profile:    "backend-a/dev",
		Kind:       "process",
		Resource:   "https://api.dev.example.com",
		Scopes:     []string{"repository:read"},
		TTLSeconds: 600,
		SessionID:  "hex:session",
		ProjectID:  "sha256:project",
		Result:     audit.ResultSuccess,
	})
	if err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if bytes.Contains(raw, []byte("leased-jwt")) || bytes.Contains(raw, []byte("parent-secret")) {
		t.Fatalf("audit record contains secret material: %s", raw)
	}
	if bytes.Count(raw, []byte("\n")) != 1 {
		t.Fatalf("audit record newline count = %d, want 1", bytes.Count(raw, []byte("\n")))
	}

	var got map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(raw), &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got["time"] != "2026-06-22T12:00:00Z" {
		t.Fatalf("time = %v", got["time"])
	}
	if got["event"] != "credential_issued" {
		t.Fatalf("event = %v", got["event"])
	}
	if got["profile"] != "backend-a/dev" {
		t.Fatalf("profile = %v", got["profile"])
	}
	if got["ttl_seconds"] != float64(600) {
		t.Fatalf("ttl_seconds = %v", got["ttl_seconds"])
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}
}
