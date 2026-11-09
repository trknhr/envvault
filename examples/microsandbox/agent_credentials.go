package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/trknhr/envvault/internal/connection"
	"github.com/trknhr/envvault/internal/envref"
)

// Every field is host-controlled, public configuration. No raw secret belongs
// in the policy. There is one credential scope per hostname.
type agentCredential struct {
	Environment string   `json:"env,omitempty"`
	Reference   string   `json:"ref"`
	Host        string   `json:"host"`
	Header      string   `json:"header,omitempty"`
	Methods     []string `json:"methods"`
	Paths       []string `json:"paths"`
	rawHeader   bool
}

func (c agentCredential) prefix() string {
	if c.rawHeader {
		return ""
	}
	return "Bearer "
}

func (c agentCredential) header() string {
	if c.Header == "" {
		return "Authorization"
	}
	return c.Header
}

// GitHub CLI uses the token scheme. Both forms carry the exact same public
// reference; the upstream request always uses the profile's Bearer strategy.
func (c agentCredential) matchesHeaderValue(value string) bool {
	return value == c.prefix()+c.Reference || !c.rawHeader && strings.EqualFold(c.header(), "Authorization") && value == "token "+c.Reference
}

func (c agentCredential) matchesReference(request *http.Request) bool {
	if connection.IsGitHTTPSRequest(request, c.Host) {
		return connection.GitHTTPSReference(request, c.Host, c.Reference, c.Methods, c.Paths)
	}
	values := request.Header.Values(c.header())
	return len(values) == 1 && c.matchesHeaderValue(values[0])
}

func validateAgentCredentials(bindings []agentCredential) error {
	hosts, environment := map[string]bool{}, map[string]string{}
	for _, binding := range bindings {
		ref, recognized, err := envref.ParseValue(binding.Reference)
		if err != nil || !recognized || ref.Part != envref.PartDefault ||
			!validAgentHost(binding.Host) || hosts[binding.Host] ||
			!validAgentCredentialEnv(binding.Environment) {
			return errors.New("invalid or duplicate EnvVault credential binding")
		}
		hosts[binding.Host] = true
		if existing, ok := environment[binding.Environment]; ok && existing != binding.Reference {
			return errors.New("credential environment variable has conflicting references")
		}
		environment[binding.Environment] = binding.Reference
		httpPolicy := connection.HTTPPolicy{
			Scheme: connection.HTTPSchemeHTTPS, BasePath: "/", ProviderStrategy: connection.HTTPProviderGeneric,
			Auth:           connection.HTTPAuthPolicy{Type: connection.HTTPAuthBearer, Header: binding.header()},
			AllowedMethods: binding.Methods, AllowedPaths: binding.Paths,
		}
		if err := httpPolicy.Validate(connection.Destination{Host: binding.Host, Port: 443}); err != nil {
			return errors.New("invalid credential method, path, or authentication header policy")
		}
		for _, allowedPath := range binding.Paths {
			if !safeAgentCredentialPath(allowedPath) || strings.Contains(allowedPath, "*") {
				return errors.New("credential paths must be exact, clean absolute paths")
			}
		}
	}
	return nil
}

func validAgentCredentialEnv(name string) bool {
	if name == "" || name[0] < 'A' || name[0] > 'Z' {
		return false
	}
	for _, c := range name {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	switch name {
	case "HOME", "PATH", "USER", "SHELL", "CODEX_HOME", "GOPATH", "GOCACHE", "GOTOOLCHAIN", "GIT_CONFIG_SYSTEM", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR", "CODEX_CA_CERTIFICATE", "NODE_EXTRA_CA_CERTS", "ENVVAULT_CREDENTIALS_FILE", "LD_PRELOAD", "LD_LIBRARY_PATH", "NODE_OPTIONS", "BASH_ENV", "ENV", "PYTHONPATH":
		return false
	}
	return true
}

func safeAgentCredentialPath(value string) bool {
	return strings.HasPrefix(value, "/") && path.Clean(value) == value && !strings.ContainsAny(value, "%?#\\")
}

func (p agentPolicy) binding(host string) *agentCredential {
	for i := range p.Credentials {
		if p.Credentials[i].Host == host {
			return &p.Credentials[i]
		}
	}
	return nil
}

func (p agentPolicy) hostRevision(host string) string {
	data, _ := json.Marshal(struct {
		Explicit   *agentCredential
		Automatic  []agentCredential
		References []string
		Scope      string
		NativeAuth bool
	}{p.binding(host), p.routes(host), p.vaultReferences, p.EnvVaultScope, p.allowsNativeAuth(host)})
	return string(data)
}

type agentCredentialTransport struct{ proxy *agentProxy }

func agentDeniedResponse(request *http.Request, code int, message string) *http.Response {
	return &http.Response{StatusCode: code, Header: http.Header{"Content-Type": {"text/plain"}},
		Body: io.NopCloser(strings.NewReader(message + "\n")), Request: request}
}

func (t agentCredentialTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	policy, err := t.proxy.policy()
	if err != nil || !policy.allows(request.URL.Hostname()) {
		return agentDeniedResponse(request, 403, "destination blocked"), nil
	}
	// Native auth is a separate, explicit host permission. It never resolves an
	// EnvVault handle; reference-bearing requests still require their saved rules.
	if policy.allowsNativeAuth(request.URL.Hostname()) && !agentRequestHasReference(request) {
		return t.proxy.tls.transport.RoundTrip(request)
	}
	binding := policy.binding(request.URL.Hostname())
	if binding == nil {
		if policy.EnvVaultScope == "network" {
			var err error
			binding, err = policy.networkBinding(request)
			if err != nil {
				return agentDeniedResponse(request, 401, "credential reference is not authorized"), nil
			}
		} else {
			var protected bool
			binding, protected = policy.autoBinding(request)
			if binding == nil && protected {
				for _, candidate := range policy.routes(request.URL.Hostname()) {
					if connection.GitHTTPSAllowed(request, candidate.Host, candidate.Methods, candidate.Paths) {
						response := agentDeniedResponse(request, 401, "Git credential reference required")
						response.Header.Set("WWW-Authenticate", `Basic realm="EnvVault"`)
						return response, nil
					}
				}
				return agentDeniedResponse(request, 403, "credential scope or reference blocked"), nil
			}
		}
	}
	if binding == nil {
		if connection.HasCredentialReference(request) {
			return agentDeniedResponse(request, 401, "credential reference is not authorized"), nil
		}
		return t.proxy.tls.transport.RoundTrip(request)
	}
	if !binding.allows(request) {
		return agentDeniedResponse(request, 403, "credential scope blocked"), nil
	}
	if !binding.matchesReference(request) {
		response := agentDeniedResponse(request, 401, "credential reference is not authorized")
		if connection.IsGitHTTPSRequest(request, binding.Host) {
			response.Header.Set("WWW-Authenticate", `Basic realm="EnvVault"`)
		}
		return response, nil
	}
	for header, values := range request.Header {
		for _, value := range values {
			if strings.Contains(value, "envvault://") && (!strings.EqualFold(header, binding.header()) || !binding.matchesHeaderValue(value)) {
				return agentDeniedResponse(request, 401, "ambiguous credential references"), nil
			}
		}
	}
	if t.proxy.credentials == nil {
		return agentDeniedResponse(request, 503, "credential provider unavailable"), nil
	}
	lease, err := t.proxy.credentials.Acquire(request.Context(), connection.CredentialRequest{
		SessionID: "microsandbox-agent", SubjectID: "host-policy",
		Spec: connection.CredentialSpec{Provider: "keyring", Ref: binding.Reference, Issuance: connection.IssuanceStatic},
		TTL:  time.Minute,
	})
	if err != nil {
		return agentDeniedResponse(request, 503, "credential unavailable"), nil
	}
	defer t.proxy.credentials.Revoke(context.Background(), lease)
	var response *http.Response
	err = lease.WithValue(request.Context(), func(value []byte) error {
		if len(value) == 0 || len(value) > 16<<10 || !bytes.Equal(value, bytes.TrimSpace(value)) ||
			bytes.ContainsFunc(value, func(c rune) bool { return c < 0x20 || c == 0x7f }) {
			return errors.New("invalid header credential")
		}
		outgoing := request.Clone(request.Context())
		if connection.IsGitHTTPSRequest(request, binding.Host) {
			outgoing.SetBasicAuth("x-access-token", string(value))
		} else {
			outgoing.Header.Set(binding.header(), binding.prefix()+string(value))
		}
		// Credential byte buffers are revoked below. Go's HTTP header strings
		// remain confined to this host-side request until transport releases it.
		response, err = t.proxy.tls.transport.RoundTrip(outgoing)
		return err
	})
	if err != nil {
		return agentDeniedResponse(request, 503, "credential or upstream unavailable"), nil
	}
	return response, nil
}

func agentRequestHasReference(request *http.Request) bool {
	return connection.HasCredentialReference(request)
}

func (binding agentCredential) allows(request *http.Request) bool {
	if connection.IsGitHTTPSRequest(request, binding.Host) {
		return connection.GitHTTPSAllowed(request, binding.Host, binding.Methods, binding.Paths)
	}
	methodOK, pathOK := false, false
	for _, method := range binding.Methods {
		methodOK = methodOK || method == request.Method
	}
	for _, allowed := range binding.Paths {
		pathOK = pathOK || allowed == request.URL.Path
	}
	return methodOK && pathOK && request.URL.RawPath == "" && safeAgentCredentialPath(request.URL.Path)
}
