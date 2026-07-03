package cli

import "testing"

func TestVersionOutputIncludesShortCommit(t *testing.T) {
	originalVersion := version
	originalCommit := commit
	t.Cleanup(func() {
		version = originalVersion
		commit = originalCommit
	})

	version = "v1.2.3"
	commit = "abcdef1234567890"

	if got, want := versionOutput(), "envvault v1.2.3 (abcdef123456)\n"; got != want {
		t.Fatalf("versionOutput() = %q, want %q", got, want)
	}
}

func TestVersionOutputUsesDevFallback(t *testing.T) {
	originalVersion := version
	originalCommit := commit
	t.Cleanup(func() {
		version = originalVersion
		commit = originalCommit
	})

	version = ""
	commit = ""

	if got, want := versionOutput(), "envvault dev\n"; got != want {
		t.Fatalf("versionOutput() = %q, want %q", got, want)
	}
}
