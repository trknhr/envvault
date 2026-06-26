package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunCapturesLaunchURLAsJSONLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "launches.jsonl")
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)

	code := run(runInput{
		Args:      []string{"https://admin.dev.example.com/auth/envvault/complete?code=opaque-code"},
		Environ:   []string{captureEnv + "=" + path},
		Now:       func() time.Time { return now },
		Stdout:    discardWriter{},
		Stderr:    discardWriter{},
		ProcessID: 123,
	})

	if code != 0 {
		t.Fatalf("run() code = %d, want 0", code)
	}
	records := readRecords(t, path)
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	if records[0].URL != "https://admin.dev.example.com/auth/envvault/complete?code=opaque-code" {
		t.Fatalf("URL = %q", records[0].URL)
	}
	if records[0].OpenedAt != "2026-06-22T12:00:00Z" {
		t.Fatalf("OpenedAt = %q", records[0].OpenedAt)
	}
	if records[0].PID != 123 {
		t.Fatalf("PID = %d, want 123", records[0].PID)
	}
}

func TestRunAppendsLaunchRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "launches.jsonl")

	for _, rawURL := range []string{"https://admin.dev.example.com/one?code=first", "https://admin.dev.example.com/two?code=second"} {
		code := run(runInput{
			Args:    []string{rawURL},
			Environ: []string{captureEnv + "=" + path},
			Now:     func() time.Time { return time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC) },
			Stdout:  discardWriter{},
			Stderr:  discardWriter{},
		})
		if code != 0 {
			t.Fatalf("run(%q) code = %d, want 0", rawURL, code)
		}
	}

	records := readRecords(t, path)
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2", len(records))
	}
	if records[0].URL == records[1].URL {
		t.Fatalf("records did not append distinct URLs: %#v", records)
	}
}

func TestRunRejectsMissingCapturePath(t *testing.T) {
	code := run(runInput{
		Args:   []string{"https://admin.dev.example.com/auth/envvault/complete?code=opaque-code"},
		Stdout: discardWriter{},
		Stderr: discardWriter{},
	})

	if code != 2 {
		t.Fatalf("run() code = %d, want 2", code)
	}
}

func TestRunRejectsInvalidArguments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "launches.jsonl")

	for _, args := range [][]string{nil, {"https://one.example/", "https://two.example/"}} {
		code := run(runInput{
			Args:    args,
			Environ: []string{captureEnv + "=" + path},
			Stdout:  discardWriter{},
			Stderr:  discardWriter{},
		})
		if code != 2 {
			t.Fatalf("run(%#v) code = %d, want 2", args, code)
		}
	}
}

func readRecords(t *testing.T, path string) []launchRecord {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	lines := splitLines(string(raw))
	records := make([]launchRecord, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		var record launchRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("json.Unmarshal(%q) error = %v", line, err)
		}
		records = append(records, record)
	}
	return records
}

func splitLines(raw string) []string {
	var lines []string
	start := 0
	for i := range raw {
		if raw[i] == '\n' {
			lines = append(lines, raw[start:i])
			start = i + 1
		}
	}
	if start < len(raw) {
		lines = append(lines, raw[start:])
	}
	return lines
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) {
	return len(p), nil
}
