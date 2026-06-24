package profile_test

import (
	"testing"
	"time"

	"github.com/trknhr/credlease/internal/clerr"
	"github.com/trknhr/credlease/internal/profile"
)

func TestValidateAcceptsProcessProfile(t *testing.T) {
	p := profile.Profile{
		Name:        "backend-a/dev",
		Kind:        profile.KindProcess,
		Resource:    "https://api.dev.example.com",
		Scopes:      []string{"repository:read", "issue:read"},
		TokenTTL:    10 * time.Minute,
		MaxTokenTTL: 30 * time.Minute,
	}

	if err := p.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsInvalidProfiles(t *testing.T) {
	tests := []struct {
		name string
		p    profile.Profile
	}{
		{
			name: "unknown kind",
			p: profile.Profile{
				Name: "backend-a/dev",
				Kind: profile.Kind("remote"),
			},
		},
		{
			name: "ttl exceeds max",
			p: profile.Profile{
				Name:        "backend-a/dev",
				Kind:        profile.KindProcess,
				Resource:    "https://api.dev.example.com",
				Scopes:      []string{"repository:read"},
				TokenTTL:    time.Hour,
				MaxTokenTTL: 30 * time.Minute,
			},
		},
		{
			name: "browser missing exchange url",
			p: profile.Profile{
				Name:              "admin-web/dev",
				Kind:              profile.KindBrowserSession,
				Resource:          "https://admin.dev.example.com",
				Scopes:            []string{"browser:session:create"},
				BootstrapTokenTTL: 60 * time.Second,
				LoginCodeTTL:      30 * time.Second,
				WebSessionTTL:     30 * time.Minute,
				CompleteURL:       "https://admin.dev.example.com/auth/credlease/complete",
				PostLoginURL:      "https://admin.dev.example.com/",
				AllowedHosts:      []string{"admin.dev.example.com"},
			},
		},
		{
			name: "unknown project binding mode",
			p: profile.Profile{
				Name:        "backend-a/dev",
				Kind:        profile.KindProcess,
				Resource:    "https://api.dev.example.com",
				Scopes:      []string{"repository:read"},
				TokenTTL:    10 * time.Minute,
				MaxTokenTTL: 30 * time.Minute,
				ProjectBinding: profile.ProjectBinding{
					Mode: profile.ProjectBindingMode("repo-file"),
				},
			},
		},
		{
			name: "reserved jwt claim",
			p: profile.Profile{
				Name:        "backend-a/dev",
				Kind:        profile.KindProcess,
				Resource:    "https://api.dev.example.com",
				Scopes:      []string{"repository:read"},
				Claims:      map[string]string{"exp": "2026-06-22T12:00:00Z"},
				TokenTTL:    10 * time.Minute,
				MaxTokenTTL: 30 * time.Minute,
			},
		},
		{
			name: "credlease owned claim",
			p: profile.Profile{
				Name:        "backend-a/dev",
				Kind:        profile.KindProcess,
				Resource:    "https://api.dev.example.com",
				Scopes:      []string{"repository:read"},
				Claims:      map[string]string{"credlease_resource": "https://evil.example.com"},
				TokenTTL:    10 * time.Minute,
				MaxTokenTTL: 30 * time.Minute,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.p.Validate()
			if err == nil {
				t.Fatal("Validate() error = nil, want error")
			}
			if code, _ := clerr.CodeOf(err); code != clerr.ConfigInvalid {
				t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.ConfigInvalid)
			}
		})
	}
}

func TestClampTTLAppliesDefaultAndMaximum(t *testing.T) {
	tests := []struct {
		name      string
		requested time.Duration
		want      time.Duration
	}{
		{name: "zero uses default", requested: 0, want: 10 * time.Minute},
		{name: "shorter request accepted", requested: 5 * time.Minute, want: 5 * time.Minute},
		{name: "longer request clamped", requested: time.Hour, want: 30 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := profile.ClampTTL(tt.requested, 10*time.Minute, 30*time.Minute); got != tt.want {
				t.Fatalf("ClampTTL() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestAllowsScopesRequiresSubset(t *testing.T) {
	p := profile.Profile{Scopes: []string{"repository:read", "issue:read"}}

	if !p.AllowsScopes([]string{"issue:read"}) {
		t.Fatal("AllowsScopes(read) = false, want true")
	}
	if p.AllowsScopes([]string{"issue:write"}) {
		t.Fatal("AllowsScopes(write) = true, want false")
	}
}

func TestValidateLaunchURLAcceptsProfileCompleteURLWithCode(t *testing.T) {
	p := browserProfile()

	err := p.ValidateLaunchURL("https://admin.dev.example.com/auth/credlease/complete?code=opaque")
	if err != nil {
		t.Fatalf("ValidateLaunchURL() error = %v", err)
	}
}

func TestValidateLaunchURLAllowsLocalhostHTTP(t *testing.T) {
	p := browserProfile()
	p.CompleteURL = "http://localhost:8080/auth/credlease/complete"
	p.AllowedHosts = []string{"localhost"}

	err := p.ValidateLaunchURL("http://localhost:8080/auth/credlease/complete?code=opaque")
	if err != nil {
		t.Fatalf("ValidateLaunchURL() error = %v", err)
	}
}

func TestValidateLaunchURLRejectsUnsafeURL(t *testing.T) {
	tests := []string{
		"http://admin.dev.example.com/auth/credlease/complete?code=opaque",
		"https://evil.example/auth/credlease/complete?code=opaque",
		"https://admin.dev.example.com/other?code=opaque",
		"https://user:pass@admin.dev.example.com/auth/credlease/complete?code=opaque",
	}
	p := browserProfile()

	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			err := p.ValidateLaunchURL(tt)
			if err == nil {
				t.Fatal("ValidateLaunchURL() error = nil, want error")
			}
			if code, _ := clerr.CodeOf(err); code != clerr.BrowserURLRejected {
				t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.BrowserURLRejected)
			}
		})
	}
}

func browserProfile() profile.Profile {
	return profile.Profile{
		Name:              "admin-web/dev",
		Kind:              profile.KindBrowserSession,
		Resource:          "https://admin.dev.example.com",
		Scopes:            []string{"browser:session:create"},
		BootstrapTokenTTL: 60 * time.Second,
		LoginCodeTTL:      30 * time.Second,
		WebSessionTTL:     30 * time.Minute,
		ExchangeURL:       "https://admin.dev.example.com/auth/credlease/browser-sessions",
		CompleteURL:       "https://admin.dev.example.com/auth/credlease/complete",
		PostLoginURL:      "https://admin.dev.example.com/",
		AllowedHosts:      []string{"admin.dev.example.com"},
	}
}
