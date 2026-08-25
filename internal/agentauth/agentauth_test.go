package agentauth_test

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/trknhr/envvault/internal/agentauth"
	"github.com/trknhr/envvault/internal/profile"
)

func TestDetectRecognizesDirectCodexExecutable(t *testing.T) {
	for _, command := range [][]string{
		{"codex"},
		{"/usr/local/bin/codex", "exec", "fix tests"},
		{"./codex"},
	} {
		agent, ok := agentauth.Detect(command)
		if !ok || agent != agentauth.Codex {
			t.Fatalf("Detect(%#v) = %q/%t, want codex/true", command, agent, ok)
		}
	}
}

func TestDetectDoesNotInferShellWrappedAgent(t *testing.T) {
	for _, command := range [][]string{
		nil,
		{""},
		{"my-codex"},
		{"sh", "-lc", "codex"},
	} {
		if agent, ok := agentauth.Detect(command); ok {
			t.Fatalf("Detect(%#v) = %q/true, want unrecognized", command, agent)
		}
	}
}

func TestCodexSupportsOnlyResponsesProviderProxy(t *testing.T) {
	valid := profile.Profile{
		Kind:           profile.KindProviderProxy,
		Provider:       "openai-compatible",
		AllowedMethods: []string{"POST"},
		AllowedPaths:   []string{"/responses"},
	}
	if !agentauth.SupportsProfile(agentauth.Codex, valid) {
		t.Fatal("SupportsProfile() = false for compatible Codex profile")
	}

	invalid := []profile.Profile{
		{Kind: profile.KindInject, Provider: "openai-compatible", AllowedMethods: []string{"POST"}, AllowedPaths: []string{"/responses"}},
		{Kind: profile.KindProviderProxy, Provider: "generic", AllowedMethods: []string{"POST"}, AllowedPaths: []string{"/responses"}},
		{Kind: profile.KindProviderProxy, Provider: "openai-compatible", AllowedMethods: []string{"GET"}, AllowedPaths: []string{"/responses"}},
		{Kind: profile.KindProviderProxy, Provider: "openai-compatible", AllowedMethods: []string{"POST"}, AllowedPaths: []string{"/chat/completions"}},
	}
	for _, candidate := range invalid {
		if agentauth.SupportsProfile(agentauth.Codex, candidate) {
			t.Fatalf("SupportsProfile(%#v) = true, want false", candidate)
		}
	}
}

func TestConfigureCodexCommandAddsInvocationScopedProvider(t *testing.T) {
	got, err := agentauth.ConfigureCommand(
		agentauth.Codex,
		[]string{"codex", "exec", "fix tests"},
		"http://host.docker.internal:49152/openai-codex/dev",
	)
	if err != nil {
		t.Fatalf("ConfigureCommand() error = %v", err)
	}
	want := []string{
		"codex",
		"-c", `model_provider="envvault"`,
		"-c", `model_providers.envvault.name="EnvVault"`,
		"-c", `model_providers.envvault.base_url="http://host.docker.internal:49152/openai-codex/dev"`,
		"-c", `model_providers.envvault.env_key="ENVVAULT_CODEX_TOKEN"`,
		"-c", `model_providers.envvault.wire_api="responses"`,
		"exec", "fix tests",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ConfigureCommand() = %#v, want %#v", got, want)
	}
}

func TestConfigureCodexCommandRejectsInvalidGateway(t *testing.T) {
	if _, err := agentauth.ConfigureCommand(agentauth.Codex, []string{"codex"}, "not-a-url"); err == nil {
		t.Fatal("ConfigureCommand() error = nil, want invalid gateway")
	}
}

func TestCodexNativeConfigurationUsesIsolatedFileBackedHome(t *testing.T) {
	configured, err := agentauth.NativeConfiguration(agentauth.Codex, "work")
	if err != nil {
		t.Fatalf("NativeConfiguration() error = %v", err)
	}
	if configured.Profile != "work" {
		t.Fatalf("Profile = %q, want work", configured.Profile)
	}
	if configured.RelativePath != filepath.Join("agent-auth", "codex", "work") {
		t.Fatalf("RelativePath = %q", configured.RelativePath)
	}
	if configured.ContainerPath != "/home/envvault/.codex" {
		t.Fatalf("ContainerPath = %q", configured.ContainerPath)
	}
	if configured.Environment["CODEX_HOME"] != configured.ContainerPath {
		t.Fatalf("Environment = %#v", configured.Environment)
	}

	command, err := agentauth.ConfigureNativeCommand(agentauth.Codex, []string{"codex", "login", "--device-auth"})
	if err != nil {
		t.Fatalf("ConfigureNativeCommand() error = %v", err)
	}
	want := []string{"codex", "-c", `cli_auth_credentials_store="file"`, "login", "--device-auth"}
	if !reflect.DeepEqual(command, want) {
		t.Fatalf("ConfigureNativeCommand() = %#v, want %#v", command, want)
	}
}

func TestCodexNativeConfigurationDefaultsAndValidatesProfile(t *testing.T) {
	configured, err := agentauth.NativeConfiguration(agentauth.Codex, "")
	if err != nil {
		t.Fatalf("NativeConfiguration(default) error = %v", err)
	}
	if configured.Profile != agentauth.DefaultNativeProfile {
		t.Fatalf("Profile = %q, want %q", configured.Profile, agentauth.DefaultNativeProfile)
	}

	for _, invalid := range []string{"../work", ".hidden", "work/personal", "profile with spaces"} {
		if _, err := agentauth.NativeConfiguration(agentauth.Codex, invalid); err == nil {
			t.Fatalf("NativeConfiguration(%q) error = nil", invalid)
		}
	}
}
