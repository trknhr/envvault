# EnvVault Core Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first testable Go foundation for the EnvVault Local MVP: strict reference parsing, profile policy validation, launch URL policy checks, and a minimal CLI shell.

**Architecture:** Keep pure policy code independent from Talos, keyring, and process execution so the security invariants can be tested without external services. Later work will wire these packages into managed Talos runtime, OS keyring adapters, `exec`, `open`, and acceptance tests.

**Tech Stack:** Go 1.22+, standard library first, `go test ./...` for verification.

---

## File Structure

- `go.mod`: Go module declaration.
- `cmd/envvault/main.go`: Minimal CLI entrypoint and command dispatch placeholder.
- `internal/clerr`: Typed EnvVault error codes.
- `internal/envref`: Strict parser for `envvault://<profile>` references.
- `internal/profile`: Profile kinds, TTL policy, scope validation, and browser URL allowlist checks.
- `docs/implementation-spec.md`: User-provided Local MVP specification copied into the repo.

## Task 1: Project Scaffold

**Files:**
- Create: `go.mod`
- Create: `cmd/envvault/main.go`

- [ ] **Step 1: Create module**

Run: `go mod init github.com/trknhr/envvault`
Expected: `go.mod` is created.

- [ ] **Step 2: Add minimal entrypoint**

Create `cmd/envvault/main.go` with:

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "envvault: command required")
		os.Exit(2)
	}
	fmt.Fprintf(os.Stderr, "envvault: command %q is not implemented yet\n", os.Args[1])
	os.Exit(2)
}
```

- [ ] **Step 3: Verify scaffold**

Run: `go test ./...`
Expected: packages build successfully.

## Task 2: Error Codes

**Files:**
- Create: `internal/clerr/error.go`
- Test: `internal/clerr/error_test.go`

- [ ] **Step 1: Write failing test**

```go
func TestErrorFormatsCodeWithoutSecretDetail(t *testing.T) {
	err := clerr.New(clerr.ReferenceInvalid, "query and fragment are not allowed")
	if got, want := err.Error(), "ENVVAULT_REFERENCE_INVALID: query and fragment are not allowed"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}
```

- [ ] **Step 2: Run red test**

Run: `go test ./internal/clerr`
Expected: FAIL because package does not exist.

- [ ] **Step 3: Implement typed error**

Define `Code`, constants for the spec's error codes used by this slice, and `Error` with `Code`, `Message`, and `Unwrap`.

- [ ] **Step 4: Run green test**

Run: `go test ./internal/clerr`
Expected: PASS.

## Task 3: Env Reference Parser

**Files:**
- Create: `internal/envref/ref.go`
- Test: `internal/envref/ref_test.go`

- [ ] **Step 1: Write failing tests**

Test valid references, non-reference values, partial template strings, queries/fragments, empty segments, `..`, and percent-encoded separators.

- [ ] **Step 2: Run red test**

Run: `go test ./internal/envref`
Expected: FAIL because package does not exist.

- [ ] **Step 3: Implement parser**

Expose:

```go
type Reference struct {
	Raw     string
	Profile string
}

func ParseValue(value string) (Reference, bool, error)
```

Rules: only values whose whole string starts with `envvault://` are references; query and fragment are rejected; profile path must be normalized and must not include empty segments, `.`, `..`, `%2f`, `%2F`, `%5c`, or `%5C`.

- [ ] **Step 4: Run green test**

Run: `go test ./internal/envref`
Expected: PASS.

## Task 4: Profile Policy

**Files:**
- Create: `internal/profile/profile.go`
- Test: `internal/profile/profile_test.go`

- [ ] **Step 1: Write failing tests**

Test process and browser-session profile validation, TTL clamping against maximums, scope subset checks, and browser launch URL acceptance/rejection.

- [ ] **Step 2: Run red test**

Run: `go test ./internal/profile`
Expected: FAIL because package does not exist.

- [ ] **Step 3: Implement policy types**

Expose `Kind`, `Profile`, `ClampTTL`, `Validate`, `AllowsScopes`, and `ValidateLaunchURL`.

- [ ] **Step 4: Run green test**

Run: `go test ./internal/profile`
Expected: PASS.

## Task 5: Whole-Repo Verification

**Files:**
- Modify only if build errors expose missing imports or package names.

- [ ] **Step 1: Run package tests**

Run: `go test ./...`
Expected: PASS.

- [ ] **Step 2: Inspect status**

Run: `git status --short`
Expected: new scaffold, docs, tests, and implementation files are visible; no generated secret material exists.

## Deferred Gaps Against Full Spec

- Managed Talos download, checksum verification, migration, and on-demand lifecycle are not in this slice.
- OS Credential Store adapters are not in this slice.
- `init`, `profile add`, `token`, `exec`, `open`, `jwks`, `doctor`, and `reset` behavior is not in this slice.
- Acceptance tests, sample backends, browser session middleware, and release packaging are not in this slice.
