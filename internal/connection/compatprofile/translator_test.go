package compatprofile_test

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/connection"
	"github.com/trknhr/envvault/internal/connection/compatprofile"
	"github.com/trknhr/envvault/internal/profile"
)

func TestFromProviderProxyProfileMapsHTTPPolicy(t *testing.T) {
	p := validProviderProxyProfile()
	p.TargetURL = "https://api.openai.com:8443/v1"
	p.AllowedPaths = []string{"/chat/completions", "/responses"}
	p.AllowedMethods = []string{"POST", "GET"}

	got, err := compatprofile.FromProviderProxyProfile(p)
	if err != nil {
		t.Fatalf("FromProviderProxyProfile() error = %v", err)
	}
	want := connection.Policy{
		Name:        "openai/dev",
		Destination: connection.Destination{Host: "api.openai.com", Port: 8443},
		Protocol: connection.ProtocolSpec{
			Type: connection.ProtocolHTTP,
			HTTP: &connection.HTTPPolicy{
				Scheme:           connection.HTTPSchemeHTTPS,
				BasePath:         "/v1",
				ProviderStrategy: connection.HTTPProviderOpenAICompatible,
				Auth: connection.HTTPAuthPolicy{
					Type:   connection.HTTPAuthBearer,
					Header: "Authorization",
				},
				AllowedMethods: []string{"POST", "GET"},
				AllowedPaths:   []string{"/chat/completions", "/responses"},
			},
		},
		Authentication: connection.Authentication{
			Delivery: connection.DeliveryProxy,
			Credential: connection.CredentialSpec{
				Provider: "keyring",
				Ref:      "envvault://openai-key/dev",
				Issuance: connection.IssuanceStatic,
			},
		},
		Limits: connection.Limits{SessionTTL: 10 * time.Minute},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("policy = %#v, want %#v", got, want)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("translated Policy.Validate() error = %v", err)
	}
}

func TestFromProviderProxyProfileAppliesLegacyDefaults(t *testing.T) {
	p := validProviderProxyProfile()
	p.Provider = ""
	p.AuthMode = ""
	p.TargetURL = "http://[::1]/"

	got, err := compatprofile.FromProviderProxyProfile(p)
	if err != nil {
		t.Fatalf("FromProviderProxyProfile() error = %v", err)
	}
	if got.Destination != (connection.Destination{Host: "::1", Port: 80}) {
		t.Fatalf("Destination = %#v", got.Destination)
	}
	if got.Protocol.HTTP.Scheme != connection.HTTPSchemeHTTP {
		t.Fatalf("Scheme = %q", got.Protocol.HTTP.Scheme)
	}
	if got.Protocol.HTTP.BasePath != "/" {
		t.Fatalf("BasePath = %q", got.Protocol.HTTP.BasePath)
	}
	if got.Protocol.HTTP.ProviderStrategy != connection.HTTPProviderGeneric {
		t.Fatalf("ProviderStrategy = %q", got.Protocol.HTTP.ProviderStrategy)
	}
	if got.Protocol.HTTP.Auth.Type != connection.HTTPAuthBearer {
		t.Fatalf("Auth.Type = %q", got.Protocol.HTTP.Auth.Type)
	}
}

func TestFromProviderProxyProfileRejectsKindMismatch(t *testing.T) {
	p := validProviderProxyProfile()
	p.Kind = profile.KindInject

	_, err := compatprofile.FromProviderProxyProfile(p)
	assertCode(t, err, clerr.ProfileKindMismatch)
}

func TestFromProviderProxyProfileRejectsLegacyValidationGaps(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*profile.Profile)
	}{
		{
			name: "target userinfo",
			mutate: func(p *profile.Profile) {
				p.TargetURL = "https://user:secret-canary@api.openai.com/v1"
			},
		},
		{
			name: "target query",
			mutate: func(p *profile.Profile) {
				p.TargetURL = "https://api.openai.com/v1?api-version=latest"
			},
		},
		{
			name: "target fragment",
			mutate: func(p *profile.Profile) {
				p.TargetURL = "https://api.openai.com/v1#fragment"
			},
		},
		{
			name: "encoded target path",
			mutate: func(p *profile.Profile) {
				p.TargetURL = "https://api.openai.com/v1%2fadmin"
			},
		},
		{
			name: "method whitespace",
			mutate: func(p *profile.Profile) {
				p.AllowedMethods = []string{" POST "}
			},
		},
		{
			name: "unrepresentable credential reference",
			mutate: func(p *profile.Profile) {
				p.CredentialName = "credential?secret-canary"
			},
		},
		{
			name: "credential reference reserved suffix",
			mutate: func(p *profile.Profile) {
				p.CredentialName = "credential/token"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validProviderProxyProfile()
			tt.mutate(&p)
			if err := p.Validate(); err != nil {
				t.Fatalf("legacy Profile.Validate() error = %v; test must exercise a validation difference", err)
			}

			_, err := compatprofile.FromProviderProxyProfile(p)
			assertCode(t, err, clerr.ConfigInvalid)
			if strings.Contains(err.Error(), "secret-canary") {
				t.Fatalf("error leaked target or credential material: %v", err)
			}
		})
	}
}

func TestFromProviderProxyProfileRejectsInvalidLegacyProfile(t *testing.T) {
	p := validProviderProxyProfile()
	p.LocalTokenTTL = 0

	_, err := compatprofile.FromProviderProxyProfile(p)
	assertCode(t, err, clerr.ConfigInvalid)
}

func TestFromProviderProxyProfileDoesNotAliasProfileSlices(t *testing.T) {
	p := validProviderProxyProfile()
	originalMethods := append([]string(nil), p.AllowedMethods...)
	originalPaths := append([]string(nil), p.AllowedPaths...)

	policy, err := compatprofile.FromProviderProxyProfile(p)
	if err != nil {
		t.Fatalf("FromProviderProxyProfile() error = %v", err)
	}
	policy.Protocol.HTTP.AllowedMethods[0] = "GET"
	policy.Protocol.HTTP.AllowedPaths[0] = "/mutated"
	if !reflect.DeepEqual(p.AllowedMethods, originalMethods) || !reflect.DeepEqual(p.AllowedPaths, originalPaths) {
		t.Fatalf("translation mutated source profile: %#v", p)
	}

	p.AllowedMethods[0] = "PATCH"
	p.AllowedPaths[0] = "/source-mutated"
	if policy.Protocol.HTTP.AllowedMethods[0] != "GET" || policy.Protocol.HTTP.AllowedPaths[0] != "/mutated" {
		t.Fatalf("translated policy aliases source profile slices: %#v", policy.Protocol.HTTP)
	}
}

func validProviderProxyProfile() profile.Profile {
	return profile.Profile{
		Name:           "openai/dev",
		Kind:           profile.KindProviderProxy,
		CredentialName: "openai-key/dev",
		AuthMode:       "bearer",
		Provider:       "openai-compatible",
		TargetURL:      "https://api.openai.com/v1",
		AllowedPaths:   []string{"/chat/completions"},
		AllowedMethods: []string{"POST"},
		LocalTokenTTL:  10 * time.Minute,
		ProjectBinding: profile.ProjectBinding{Mode: profile.ProjectBindingNone},
	}
}

func assertCode(t *testing.T, err error, want clerr.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want %q", want)
	}
	if got, _ := clerr.CodeOf(err); got != want {
		t.Fatalf("CodeOf(error) = %q, want %q (error: %v)", got, want, err)
	}
}
