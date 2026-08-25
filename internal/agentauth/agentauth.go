// Package agentauth adapts known agent CLIs to brokered EnvVault provider
// profiles and isolated native authentication state.
package agentauth

import (
	"net/url"
	"path"
	"strings"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/profile"
)

type Agent string

const (
	Codex Agent = "codex"

	CodexTokenEnvironment = "ENVVAULT_CODEX_TOKEN"
	DefaultNativeProfile  = "default"
)

// NativeConfig describes the persistent state an agent needs for its own
// authentication flow. RelativePath is rooted under EnvVault's private data
// directory by the caller.
type NativeConfig struct {
	Profile       string
	RelativePath  string
	ContainerPath string
	Environment   map[string]string
}

// AgentAuthAdapter contains agent-specific command, proxy, and native-auth
// behavior. OAuth itself remains implemented by the official agent CLI.
type AgentAuthAdapter interface {
	Agent() Agent
	MatchesExecutable(executable string) bool
	TokenEnvironment() string
	SupportsProfile(candidate profile.Profile) bool
	ConfigureProxy(command []string, baseURL string) ([]string, error)
	NativeConfig(profileName string) (NativeConfig, error)
	ConfigureNative(command []string) ([]string, error)
}

var adapters = []AgentAuthAdapter{codexAdapter{}}

// Detect recognizes a directly invoked agent executable. Shell-wrapped or
// otherwise indirect invocations are intentionally not inferred.
func Detect(command []string) (Agent, bool) {
	if len(command) == 0 {
		return "", false
	}
	executable := path.Base(strings.TrimSpace(command[0]))
	for _, adapter := range adapters {
		if adapter.MatchesExecutable(executable) {
			return adapter.Agent(), true
		}
	}
	return "", false
}

func TokenEnvironment(agent Agent) string {
	if adapter, ok := adapterFor(agent); ok {
		return adapter.TokenEnvironment()
	}
	return ""
}

// SupportsProfile reports whether a provider-proxy profile exposes the
// protocol surface required by the agent adapter.
func SupportsProfile(agent Agent, candidate profile.Profile) bool {
	if adapter, ok := adapterFor(agent); ok {
		return adapter.SupportsProfile(candidate)
	}
	return false
}

// ConfigureCommand adds invocation-scoped provider settings without
// persisting upstream credentials in the sandbox.
func ConfigureCommand(agent Agent, command []string, baseURL string) ([]string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, clerr.New(clerr.ConfigInvalid, "agent gateway base url is invalid")
	}
	adapter, ok := adapterFor(agent)
	if !ok {
		return nil, clerr.New(clerr.ConfigInvalid, "unsupported agent command")
	}
	return adapter.ConfigureProxy(command, baseURL)
}

// NativeConfiguration returns an isolated native-auth state layout for an
// agent. The resulting directory may contain refresh tokens and must be
// treated as credential material.
func NativeConfiguration(agent Agent, profileName string) (NativeConfig, error) {
	adapter, ok := adapterFor(agent)
	if !ok {
		return NativeConfig{}, clerr.New(clerr.ConfigInvalid, "unsupported agent command")
	}
	return adapter.NativeConfig(profileName)
}

// ConfigureNativeCommand lets the official agent own login and refresh while
// forcing storage into its isolated mounted state directory.
func ConfigureNativeCommand(agent Agent, command []string) ([]string, error) {
	adapter, ok := adapterFor(agent)
	if !ok {
		return nil, clerr.New(clerr.ConfigInvalid, "unsupported agent command")
	}
	return adapter.ConfigureNative(command)
}

func adapterFor(agent Agent) (AgentAuthAdapter, bool) {
	for _, adapter := range adapters {
		if adapter.Agent() == agent {
			return adapter, true
		}
	}
	return nil, false
}
