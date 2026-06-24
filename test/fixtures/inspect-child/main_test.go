package main

import (
	"encoding/json"
	"testing"
	"time"
)

func TestBuildSnapshotIncludesEnvironmentProcessMetadataAndPorts(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)

	snapshot := buildSnapshot(inspectInput{
		Args:    []string{"arg1", "arg2"},
		Environ: []string{"TOKEN=leased-jwt", "PLAIN=value", "TOKEN=latest-token", "IGNORED"},
		Ports:   []string{"127.0.0.1:12345", "127.0.0.1:54321"},
		Now:     func() time.Time { return now },
		PID:     100,
		PPID:    50,
		CheckPort: func(address string) (bool, string) {
			if address == "127.0.0.1:12345" {
				return true, ""
			}
			return false, "connection refused"
		},
	})

	if got, want := snapshot.Args, []string{"arg1", "arg2"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("Args = %#v, want %#v", got, want)
	}
	if snapshot.Env["TOKEN"] != "latest-token" {
		t.Fatalf("Env[TOKEN] = %q, want latest-token", snapshot.Env["TOKEN"])
	}
	if _, ok := snapshot.Env["IGNORED"]; ok {
		t.Fatalf("Env contains malformed assignment: %#v", snapshot.Env)
	}
	if snapshot.PID != 100 || snapshot.PPID != 50 {
		t.Fatalf("PID/PPID = %d/%d, want 100/50", snapshot.PID, snapshot.PPID)
	}
	if snapshot.StartedAt != "2026-06-22T12:00:00Z" {
		t.Fatalf("StartedAt = %q", snapshot.StartedAt)
	}
	if !snapshot.Ports["127.0.0.1:12345"].Reachable {
		t.Fatalf("port 12345 = %#v, want reachable", snapshot.Ports["127.0.0.1:12345"])
	}
	if got := snapshot.Ports["127.0.0.1:54321"]; got.Reachable || got.Error == "" {
		t.Fatalf("port 54321 = %#v, want unreachable with error", got)
	}
}

func TestSnapshotJSONUsesStableFieldNames(t *testing.T) {
	body, err := json.Marshal(buildSnapshot(inspectInput{
		Args:    []string{"child"},
		Environ: []string{"TOKEN=leased-jwt"},
		Now:     func() time.Time { return time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC) },
		PID:     10,
		PPID:    9,
	}))
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	got := string(body)
	for _, want := range []string{`"args":["child"]`, `"env":{"TOKEN":"leased-jwt"}`, `"pid":10`, `"ppid":9`, `"started_at":"2026-06-22T12:00:00Z"`, `"ports":{}`} {
		if !contains(got, want) {
			t.Fatalf("json = %s, want %s", got, want)
		}
	}
}

func contains(text, want string) bool {
	return len(want) == 0 || (len(text) >= len(want) && index(text, want) >= 0)
}

func index(text, want string) int {
	for i := 0; i+len(want) <= len(text); i++ {
		if text[i:i+len(want)] == want {
			return i
		}
	}
	return -1
}
