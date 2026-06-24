package main

import "testing"

func TestParseCodeAcceptsConfiguredExitCode(t *testing.T) {
	code, err := parseCode([]string{"--code", "42"})
	if err != nil {
		t.Fatalf("parseCode() error = %v", err)
	}
	if code != 42 {
		t.Fatalf("code = %d, want 42", code)
	}
}

func TestParseCodeRejectsOutOfRangeExitCode(t *testing.T) {
	_, err := parseCode([]string{"--code", "126"})
	if err == nil {
		t.Fatal("parseCode() error = nil, want out-of-range error")
	}
}
