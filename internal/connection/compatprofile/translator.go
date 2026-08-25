// Package compatprofile translates legacy profiles into connection policies.
// It does not change profile storage or activate the connection runtime.
package compatprofile

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/connection"
	"github.com/trknhr/envvault/internal/envref"
	"github.com/trknhr/envvault/internal/profile"
)

const keyringCredentialProvider = "keyring"

// FromProviderProxyProfile translates the connection semantics of an existing
// provider-proxy profile. Project binding remains on the source profile and
// callers must continue to enforce it before using the translated policy.
func FromProviderProxyProfile(p profile.Profile) (connection.Policy, error) {
	if p.Kind != profile.KindProviderProxy {
		return connection.Policy{}, clerr.New(clerr.ProfileKindMismatch, p.Name)
	}
	if err := p.Validate(); err != nil {
		return connection.Policy{}, err
	}

	strategy, err := providerStrategy(p.Provider)
	if err != nil {
		return connection.Policy{}, err
	}
	auth, err := authenticationPolicy(p.AuthMode)
	if err != nil {
		return connection.Policy{}, err
	}
	destination, scheme, basePath, err := translateTarget(p.TargetURL)
	if err != nil {
		return connection.Policy{}, err
	}
	credentialRef, err := translateCredentialRef(p.CredentialName)
	if err != nil {
		return connection.Policy{}, err
	}

	policy := connection.Policy{
		Name:        p.Name,
		Destination: destination,
		Protocol: connection.ProtocolSpec{
			Type: connection.ProtocolHTTP,
			HTTP: &connection.HTTPPolicy{
				Scheme:           scheme,
				BasePath:         basePath,
				ProviderStrategy: strategy,
				Auth:             auth,
				AllowedMethods:   append([]string(nil), p.AllowedMethods...),
				AllowedPaths:     append([]string(nil), p.AllowedPaths...),
			},
		},
		Authentication: connection.Authentication{
			Delivery: connection.DeliveryProxy,
			Credential: connection.CredentialSpec{
				Provider: keyringCredentialProvider,
				Ref:      credentialRef,
				Issuance: connection.IssuanceStatic,
			},
		},
		Limits: connection.Limits{
			SessionTTL: p.LocalTokenTTL,
		},
	}
	if err := policy.Validate(); err != nil {
		return connection.Policy{}, err
	}
	return policy, nil
}

func providerStrategy(raw string) (connection.HTTPProviderStrategy, error) {
	switch strings.TrimSpace(raw) {
	case "", string(connection.HTTPProviderGeneric):
		return connection.HTTPProviderGeneric, nil
	case string(connection.HTTPProviderOpenAICompatible):
		return connection.HTTPProviderOpenAICompatible, nil
	default:
		return "", configInvalid("provider-proxy provider is not supported by the connection model")
	}
}

func authenticationPolicy(raw string) (connection.HTTPAuthPolicy, error) {
	switch strings.TrimSpace(raw) {
	case "", string(connection.HTTPAuthBearer):
		return connection.HTTPAuthPolicy{
			Type:   connection.HTTPAuthBearer,
			Header: "Authorization",
		}, nil
	default:
		return connection.HTTPAuthPolicy{}, configInvalid("provider-proxy authentication is not supported by the connection model")
	}
}

func translateTarget(raw string) (connection.Destination, connection.HTTPScheme, string, error) {
	target, err := url.Parse(raw)
	if err != nil {
		return connection.Destination{}, "", "", configInvalid("provider-proxy target url is invalid")
	}
	if target.User != nil {
		return connection.Destination{}, "", "", configInvalid("provider-proxy target url userinfo is not supported")
	}
	if target.ForceQuery || target.RawQuery != "" {
		return connection.Destination{}, "", "", configInvalid("provider-proxy target url query is not supported")
	}
	if target.Fragment != "" || target.RawFragment != "" || strings.Contains(raw, "#") {
		return connection.Destination{}, "", "", configInvalid("provider-proxy target url fragment is not supported")
	}
	if target.RawPath != "" || strings.Contains(target.EscapedPath(), "%") {
		return connection.Destination{}, "", "", configInvalid("provider-proxy target url encoded path is not supported")
	}

	scheme := connection.HTTPScheme(target.Scheme)
	port, err := targetPort(target, scheme)
	if err != nil {
		return connection.Destination{}, "", "", err
	}
	basePath := target.Path
	if basePath == "" {
		basePath = "/"
	}
	return connection.Destination{Host: target.Hostname(), Port: port}, scheme, basePath, nil
}

func targetPort(target *url.URL, scheme connection.HTTPScheme) (uint16, error) {
	if rawPort := target.Port(); rawPort != "" {
		port, err := strconv.ParseUint(rawPort, 10, 16)
		if err != nil || port == 0 {
			return 0, configInvalid("provider-proxy target url port is invalid")
		}
		return uint16(port), nil
	}
	switch scheme {
	case connection.HTTPSchemeHTTPS:
		return 443, nil
	case connection.HTTPSchemeHTTP:
		return 80, nil
	default:
		return 0, configInvalid("provider-proxy target url scheme is not supported")
	}
}

func translateCredentialRef(name string) (string, error) {
	ref := envref.Format(name, envref.PartDefault)
	parsed, recognized, err := envref.ParseValue(ref)
	if err != nil || !recognized || parsed.Part != envref.PartDefault || parsed.Profile != name {
		return "", configInvalid("provider-proxy credential name cannot be represented as an envvault reference")
	}
	return ref, nil
}

func configInvalid(message string) error {
	return clerr.New(clerr.ConfigInvalid, message)
}
