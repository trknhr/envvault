package agentauth

import (
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/profile"
)

const codexHomeTarget = "/home/envvault/.codex"

type codexAdapter struct{}

func (codexAdapter) Agent() Agent { return Codex }

func (codexAdapter) MatchesExecutable(executable string) bool {
	return executable == "codex"
}

func (codexAdapter) TokenEnvironment() string { return CodexTokenEnvironment }

func (codexAdapter) SupportsProfile(candidate profile.Profile) bool {
	return candidate.Kind == profile.KindProviderProxy &&
		candidate.Provider == "openai-compatible" &&
		slices.Contains(candidate.AllowedMethods, "POST") &&
		slices.Contains(candidate.AllowedPaths, "/responses")
}

func (codexAdapter) ConfigureProxy(command []string, baseURL string) ([]string, error) {
	return addCodexOverrides(command, []string{
		`model_provider="envvault"`,
		`model_providers.envvault.name="EnvVault"`,
		"model_providers.envvault.base_url=" + strconv.Quote(baseURL),
		`model_providers.envvault.env_key="` + CodexTokenEnvironment + `"`,
		`model_providers.envvault.wire_api="responses"`,
	})
}

func (codexAdapter) NativeConfig(profileName string) (NativeConfig, error) {
	normalized, err := normalizeNativeProfile(profileName)
	if err != nil {
		return NativeConfig{}, err
	}
	return NativeConfig{
		Profile:       normalized,
		RelativePath:  filepath.Join("agent-auth", string(Codex), normalized),
		ContainerPath: codexHomeTarget,
		Environment: map[string]string{
			"CODEX_HOME": codexHomeTarget,
		},
	}, nil
}

func (codexAdapter) ConfigureNative(command []string) ([]string, error) {
	return addCodexOverrides(command, []string{`cli_auth_credentials_store="file"`})
}

func addCodexOverrides(command, overrides []string) ([]string, error) {
	if len(command) == 0 || strings.TrimSpace(command[0]) == "" {
		return nil, clerr.New(clerr.ConfigInvalid, "agent command is required")
	}
	configured := make([]string, 0, len(command)+2*len(overrides))
	configured = append(configured, command[0])
	for _, override := range overrides {
		configured = append(configured, "-c", override)
	}
	configured = append(configured, command[1:]...)
	return configured, nil
}

func normalizeNativeProfile(profileName string) (string, error) {
	name := strings.TrimSpace(profileName)
	if name == "" {
		name = DefaultNativeProfile
	}
	if len(name) > 64 || name == "." || name == ".." {
		return "", invalidNativeProfile()
	}
	for index, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || (r == '.' && index > 0) {
			continue
		}
		return "", invalidNativeProfile()
	}
	return name, nil
}

func invalidNativeProfile() error {
	return clerr.New(clerr.ConfigInvalid, "agent auth profile must contain only letters, numbers, dots, dashes, or underscores")
}
