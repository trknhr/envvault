package envref_test

import (
	"strings"
	"testing"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/envref"
)

func TestParseValueReturnsReferenceForWholeEnvVaultURI(t *testing.T) {
	ref, ok, err := envref.ParseValue("envvault://backend-a/dev")
	if err != nil {
		t.Fatalf("ParseValue() error = %v", err)
	}
	if !ok {
		t.Fatal("ParseValue() ok = false, want true")
	}
	if ref.Raw != "envvault://backend-a/dev" {
		t.Fatalf("Raw = %q", ref.Raw)
	}
	if ref.Profile != "backend-a/dev" {
		t.Fatalf("Profile = %q, want backend-a/dev", ref.Profile)
	}
	if ref.Part != envref.PartDefault {
		t.Fatalf("Part = %q, want default", ref.Part)
	}
}

func TestParseValueReturnsProxyReferenceParts(t *testing.T) {
	tests := []struct {
		value   string
		profile string
		part    envref.Part
	}{
		{value: "envvault://openai/dev/base-url", profile: "openai/dev", part: envref.PartBaseURL},
		{value: "envvault://openai/dev/token", profile: "openai/dev", part: envref.PartToken},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			ref, ok, err := envref.ParseValue(tt.value)
			if err != nil {
				t.Fatalf("ParseValue() error = %v", err)
			}
			if !ok {
				t.Fatal("ParseValue() ok = false, want true")
			}
			if ref.Profile != tt.profile {
				t.Fatalf("Profile = %q, want %q", ref.Profile, tt.profile)
			}
			if ref.Part != tt.part {
				t.Fatalf("Part = %q, want %q", ref.Part, tt.part)
			}
		})
	}
}

func TestParseValueRejectsValueSuffix(t *testing.T) {
	_, ok, err := envref.ParseValue("envvault://database/dev/value")
	if err == nil {
		t.Fatal("ParseValue() error = nil, want error")
	}
	if !ok {
		t.Fatal("ParseValue() ok = false, want true for malformed references")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.ReferenceInvalid {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.ReferenceInvalid)
	}
	if !strings.Contains(err.Error(), "envvault://<credential>") {
		t.Fatalf("error = %q, want direct credential guidance", err.Error())
	}
}

func TestParseValueIgnoresNonReferenceAndTemplateValues(t *testing.T) {
	tests := []string{
		"",
		"plain-secret",
		"Bearer envvault://backend-a/dev",
		"${envvault://backend-a/dev}",
		"https://example.com/envvault://backend-a/dev",
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
		"envvault://",
		"envvault://backend-a/dev?scope=admin",
		"envvault://backend-a/dev#frag",
		"envvault://backend-a//dev",
		"envvault://backend-a/./dev",
		"envvault://backend-a/../dev",
		"envvault://backend-a/dev/..",
		"envvault://backend-a/%2Fdev",
		"envvault://backend-a/%2fdev",
		"envvault://backend-a/%5Cdev",
		"envvault://backend-a/%5cdev",
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
