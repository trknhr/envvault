package envref_test

import (
	"testing"

	"github.com/trknhr/credlease/internal/clerr"
	"github.com/trknhr/credlease/internal/envref"
)

func TestParseValueReturnsReferenceForWholeCredleaseURI(t *testing.T) {
	ref, ok, err := envref.ParseValue("credlease://backend-a/dev")
	if err != nil {
		t.Fatalf("ParseValue() error = %v", err)
	}
	if !ok {
		t.Fatal("ParseValue() ok = false, want true")
	}
	if ref.Raw != "credlease://backend-a/dev" {
		t.Fatalf("Raw = %q", ref.Raw)
	}
	if ref.Profile != "backend-a/dev" {
		t.Fatalf("Profile = %q, want backend-a/dev", ref.Profile)
	}
}

func TestParseValueIgnoresNonReferenceAndTemplateValues(t *testing.T) {
	tests := []string{
		"",
		"plain-secret",
		"Bearer credlease://backend-a/dev",
		"${credlease://backend-a/dev}",
		"https://example.com/credlease://backend-a/dev",
	}

	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			_, ok, err := envref.ParseValue(tt)
			if err != nil {
				t.Fatalf("ParseValue() error = %v", err)
			}
			if ok {
				t.Fatal("ParseValue() ok = true, want false")
			}
		})
	}
}

func TestParseValueRejectsInvalidReferences(t *testing.T) {
	tests := []string{
		"credlease://",
		"credlease://backend-a/dev?scope=admin",
		"credlease://backend-a/dev#frag",
		"credlease://backend-a//dev",
		"credlease://backend-a/./dev",
		"credlease://backend-a/../dev",
		"credlease://backend-a/dev/..",
		"credlease://backend-a/%2Fdev",
		"credlease://backend-a/%2fdev",
		"credlease://backend-a/%5Cdev",
		"credlease://backend-a/%5cdev",
	}

	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			_, ok, err := envref.ParseValue(tt)
			if err == nil {
				t.Fatal("ParseValue() error = nil, want error")
			}
			if !ok {
				t.Fatal("ParseValue() ok = false, want true for malformed references")
			}
			if code, _ := clerr.CodeOf(err); code != clerr.ReferenceInvalid {
				t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.ReferenceInvalid)
			}
		})
	}
}
