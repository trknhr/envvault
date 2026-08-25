package cli

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/trknhr/envvault/internal/agentauth"
	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/envref"
	"github.com/trknhr/envvault/internal/profile"
	"github.com/trknhr/envvault/internal/projectbinding"
	"github.com/trknhr/envvault/internal/sandbox"
)

type sandboxProfileLister interface {
	ListProfiles() ([]profile.Profile, error)
}

type sandboxAgentBinding struct {
	agent   agentauth.Agent
	mode    sandboxAgentAuthMode
	profile profile.Profile
	native  agentauth.NativeConfig
}

type sandboxAgentAuthMode string

const (
	sandboxAgentAuthBrokered sandboxAgentAuthMode = "brokered"
	sandboxAgentAuthNative   sandboxAgentAuthMode = "native"
)

func (a App) selectSandboxOutboundProfiles(
	requested []string,
	all bool,
	identity projectbinding.Identity,
) ([]string, error) {
	if all && len(requested) > 0 {
		return nil, clerr.New(clerr.ConfigInvalid, "--all and --outbound-profile cannot be used together")
	}
	if !all {
		return append([]string(nil), requested...), nil
	}

	lister, ok := a.profiles.(sandboxProfileLister)
	if !ok {
		return nil, clerr.New(clerr.ConfigInvalid, "--all requires a profile store that supports listing")
	}
	available, err := lister.ListProfiles()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(available))
	for _, candidate := range available {
		if candidate.Kind != profile.KindProviderProxy {
			continue
		}
		if err := projectbinding.Check(candidate.ProjectBinding, identity); err != nil {
			if code, ok := clerr.CodeOf(err); ok && code == clerr.ProjectNotTrusted {
				continue
			}
			return nil, err
		}
		names = append(names, candidate.Name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil, clerr.New(clerr.ConfigInvalid, "no outbound profiles are available for the current project")
	}
	return names, nil
}

func (a App) selectSandboxAgentAuth(parsed sandboxRunArgs) (*sandboxAgentBinding, error) {
	requested := strings.TrimSpace(parsed.agentAuth)
	nativeProfile := strings.TrimSpace(parsed.agentAuthProfile)
	if parsed.noAgentAuth && (requested != "" || nativeProfile != "") {
		return nil, clerr.New(clerr.ConfigInvalid, "--agent-auth and --no-agent-auth cannot be used together; --agent-auth-profile also requires agent auth")
	}
	if requested != "native" && nativeProfile != "" {
		return nil, clerr.New(clerr.ConfigInvalid, "--agent-auth-profile requires --agent-auth native")
	}

	agent, recognized := agentauth.Detect(parsed.command)
	if !recognized {
		if requested != "" {
			return nil, clerr.New(clerr.ConfigInvalid, "--agent-auth requires a recognized direct agent command")
		}
		return nil, nil
	}
	if parsed.noAgentAuth {
		return nil, nil
	}
	if requested == "native" {
		native, err := agentauth.NativeConfiguration(agent, nativeProfile)
		if err != nil {
			return nil, err
		}
		return &sandboxAgentBinding{agent: agent, mode: sandboxAgentAuthNative, native: native}, nil
	}

	if requested != "" {
		if a.profiles == nil {
			return nil, clerr.New(clerr.ProfileNotFound, requested)
		}
		selected, err := a.profiles.Profile(requested)
		if err != nil {
			return nil, err
		}
		if !agentauth.SupportsProfile(agent, selected) {
			return nil, incompatibleAgentProfile(agent, requested)
		}
		return &sandboxAgentBinding{agent: agent, mode: sandboxAgentAuthBrokered, profile: selected}, nil
	}

	lister, ok := a.profiles.(sandboxProfileLister)
	if !ok {
		return nil, noAgentProfile(agent)
	}
	available, err := lister.ListProfiles()
	if err != nil {
		return nil, err
	}
	candidates := make([]profile.Profile, 0, len(available))
	for _, candidate := range available {
		if agentauth.SupportsProfile(agent, candidate) {
			candidates = append(candidates, candidate)
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Name < candidates[j].Name
	})

	switch len(candidates) {
	case 0:
		return nil, noAgentProfile(agent)
	case 1:
		return &sandboxAgentBinding{agent: agent, mode: sandboxAgentAuthBrokered, profile: candidates[0]}, nil
	default:
		names := make([]string, 0, len(candidates))
		for _, candidate := range candidates {
			names = append(names, strconv.Quote(candidate.Name))
		}
		return nil, clerr.New(
			clerr.ConfigInvalid,
			"multiple compatible "+string(agent)+" agent auth profiles found ("+strings.Join(names, ", ")+"); select one with --agent-auth",
		)
	}
}

func (a App) attachSandboxNativeAgentAuth(
	binding sandboxAgentBinding,
	environment map[string]string,
	command []string,
) ([]string, sandbox.Mount, error) {
	for key, value := range binding.native.Environment {
		if _, exists := environment[key]; exists {
			return nil, sandbox.Mount{}, clerr.New(clerr.ConfigInvalid, key+" is reserved for native agent authentication")
		}
		environment[key] = value
	}
	configured, err := agentauth.ConfigureNativeCommand(binding.agent, command)
	if err != nil {
		return nil, sandbox.Mount{}, err
	}
	source, err := prepareNativeAgentState(a.paths.DataDir, binding.native.RelativePath)
	if err != nil {
		return nil, sandbox.Mount{}, err
	}
	return configured, sandbox.Mount{
		Source: source,
		Target: binding.native.ContainerPath,
	}, nil
}

func prepareNativeAgentState(dataDir, relativePath string) (string, error) {
	if strings.TrimSpace(dataDir) == "" {
		return "", clerr.New(clerr.ConfigInvalid, "EnvVault data directory is required for native agent authentication")
	}
	root, err := filepath.Abs(dataDir)
	if err != nil {
		return "", clerr.Wrap(clerr.ConfigInvalid, "resolve EnvVault data directory", err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", clerr.Wrap(clerr.ConfigInvalid, "create EnvVault data directory", err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", clerr.Wrap(clerr.ConfigInvalid, "resolve EnvVault data directory", err)
	}

	return secureNativeAgentStatePath(resolvedRoot, relativePath)
}

func secureNativeAgentStatePath(root, relativePath string) (string, error) {
	cleaned := filepath.Clean(relativePath)
	if cleaned == "." || filepath.IsAbs(cleaned) || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", clerr.New(clerr.ConfigInvalid, "native agent auth state path must stay under the EnvVault data directory")
	}
	current := filepath.Clean(root)
	for _, segment := range strings.Split(cleaned, string(filepath.Separator)) {
		if segment == "" || segment == "." || segment == ".." {
			return "", clerr.New(clerr.ConfigInvalid, "native agent auth state path is invalid")
		}
		current = filepath.Join(current, segment)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if mkdirErr := os.Mkdir(current, 0o700); mkdirErr != nil && !os.IsExist(mkdirErr) {
				return "", clerr.Wrap(clerr.ConfigInvalid, "create native agent auth state", mkdirErr)
			}
			info, err = os.Lstat(current)
		}
		switch {
		case err != nil:
			return "", clerr.Wrap(clerr.ConfigInvalid, "inspect native agent auth state", err)
		case info.Mode()&os.ModeSymlink != 0 || !info.IsDir():
			return "", clerr.New(clerr.ConfigInvalid, "native agent auth state must contain only directories, not symlinks")
		}
		if err := os.Chmod(current, 0o700); err != nil {
			return "", clerr.Wrap(clerr.ConfigInvalid, "secure native agent auth state", err)
		}
	}
	return current, nil
}

func attachSandboxAgentAuth(
	ctx context.Context,
	binding sandboxAgentBinding,
	identity projectbinding.Identity,
	resolver *sandboxReferenceResolver,
	environment map[string]string,
	command []string,
) ([]string, error) {
	tokenEnvironment := agentauth.TokenEnvironment(binding.agent)
	if tokenEnvironment == "" {
		return nil, clerr.New(clerr.ConfigInvalid, "recognized agent has no token environment")
	}
	if _, exists := environment[tokenEnvironment]; exists {
		return nil, clerr.New(clerr.ConfigInvalid, tokenEnvironment+" is reserved for brokered agent authentication")
	}

	baseURL, err := resolver.ResolveReference(ctx, envref.Reference{
		Raw:     envref.Format(binding.profile.Name, envref.PartBaseURL),
		Profile: binding.profile.Name,
		Part:    envref.PartBaseURL,
	}, identity)
	if err != nil {
		return nil, err
	}
	token, err := resolver.ResolveReference(ctx, envref.Reference{
		Raw:     envref.Format(binding.profile.Name, envref.PartToken),
		Profile: binding.profile.Name,
		Part:    envref.PartToken,
	}, identity)
	if err != nil {
		return nil, err
	}
	configured, err := agentauth.ConfigureCommand(binding.agent, command, baseURL)
	if err != nil {
		return nil, err
	}
	environment[tokenEnvironment] = token
	return configured, nil
}

func noAgentProfile(agent agentauth.Agent) error {
	return clerr.New(
		clerr.ConfigInvalid,
		"no compatible "+string(agent)+" agent auth profile found; add an openai-compatible provider proxy, use --agent-auth native, select a proxy with --agent-auth, or use --no-agent-auth",
	)
}

func incompatibleAgentProfile(agent agentauth.Agent, name string) error {
	return clerr.New(
		clerr.ConfigInvalid,
		"agent auth profile "+strconv.Quote(name)+" is not compatible with "+string(agent)+"; it must be an openai-compatible provider proxy allowing POST /responses",
	)
}
