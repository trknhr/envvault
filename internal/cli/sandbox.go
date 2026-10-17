package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/connection"
	"github.com/trknhr/envvault/internal/envref"
	"github.com/trknhr/envvault/internal/process"
	"github.com/trknhr/envvault/internal/projectbinding"
	"github.com/trknhr/envvault/internal/providerproxy"
	"github.com/trknhr/envvault/internal/sandbox"
)

type sandboxRunArgs struct {
	runtime                  string
	image                    string
	envFiles                 []string
	inlineEnv                []string
	publish                  []string
	interactive              bool
	tty                      bool
	agentAuth                string
	agentAuthProfile         string
	noAgentAuth              bool
	outboundProfiles         []string
	allOutboundProfiles      bool
	allowMaterializedSecrets bool
	command                  []string
}

func (a App) runSandbox(ctx context.Context, parsed sandboxRunArgs, stdout, stderr io.Writer) int {
	if err := validateSandboxRunArgs(parsed); err != nil {
		return exitError(stderr, err)
	}
	agentBinding, err := a.selectSandboxAgentAuth(parsed)
	if err != nil {
		return exitError(stderr, err)
	}
	runtime := a.sandboxRuntimes[strings.TrimSpace(parsed.runtime)]
	if runtime == nil {
		return exitError(stderr, clerr.New(clerr.RuntimeUnavailable, "sandbox runtime is not configured"))
	}
	publications, err := sandboxPublications(parsed.publish)
	if err != nil {
		return exitError(stderr, err)
	}
	workspace, err := a.sandboxWorkspace()
	if err != nil {
		return exitError(stderr, err)
	}
	if err := runtime.Check(ctx); err != nil {
		return exitError(stderr, err)
	}
	egressAttacher, err := sandboxEgressAttacher(runtime, parsed)
	if err != nil {
		return exitError(stderr, err)
	}
	identity, err := a.detectProjectIdentity(ctx)
	if err != nil {
		return exitError(stderr, err)
	}
	parsed.outboundProfiles, err = a.selectSandboxOutboundProfiles(
		parsed.outboundProfiles,
		parsed.allOutboundProfiles,
		identity,
	)
	if err != nil {
		return exitError(stderr, err)
	}
	launch, err := a.openSandboxLaunch(ctx, runtime, parsed, identity)
	defer launch.Close()
	if err != nil {
		return exitError(stderr, err)
	}
	environment, references, err := a.resolveSandboxEnvironment(ctx, parsed, identity, launch)
	if err != nil {
		return exitError(stderr, err)
	}
	sandboxCommand, mounts, err := a.applySandboxAgentAuth(ctx, agentBinding, identity, references, environment, append([]string(nil), parsed.command...))
	if err != nil {
		return exitError(stderr, err)
	}
	resources := []sandbox.Resource{launch.resolver}
	var egressMode sandbox.EgressMode
	if launch.outbound != nil {
		attachment, attachErr := egressAttacher.AttachEgress(ctx, launch.outboundConfig)
		if attachErr != nil {
			return exitError(stderr, attachErr)
		}
		if mergeErr := mergeEgressAttachment(environment, &mounts, attachment, references.gateway); mergeErr != nil {
			return exitError(stderr, errors.Join(mergeErr, closeSandboxResources(attachment.Resources)))
		}
		resources = append(resources, attachment.Resources...)
		resources = append(resources, launch.outbound)
		egressMode = attachment.Mode
	}
	level := connection.SecurityBrokered
	if references.materialized || (agentBinding != nil && agentBinding.mode == sandboxAgentAuthNative) {
		level = connection.SecurityMaterializedStatic
	}
	signals := make(chan os.Signal, 1)
	process.NotifyInterrupt(signals)
	defer signal.Stop(signals)
	stdin := a.stdin
	if parsed.interactive && stdin == nil {
		stdin = os.Stdin
	}
	result, runErr := (sandbox.Orchestrator{}).Run(ctx, sandbox.RunRequest{
		Runtime:        runtime,
		RuntimeChecked: true,
		Spec: sandbox.Spec{
			Image:            parsed.image,
			Command:          sandboxCommand,
			WorkingDirectory: "/workspace",
			Environment:      environment,
			Workspace: sandbox.WorkspaceMount{
				Source: workspace,
				Target: "/workspace",
			},
			Mounts:         mounts,
			PublishedPorts: publications,
			Resources: sandbox.ResourceLimits{
				PIDs:        256,
				MemoryBytes: 512 << 20,
				CPUs:        1,
			},
			Network:       sandbox.NetworkAttachment{Mode: sandbox.NetworkBridge},
			Gateway:       references.gateway,
			SecurityLevel: level,
			Stdin:         stdin,
			Stdout:        stdout,
			Stderr:        stderr,
			Interactive:   parsed.interactive,
			TTY:           parsed.tty,
		},
		Signals:   signals,
		Resources: resources,
		OnCreated: reportSandboxCreated(stderr, agentBinding, egressMode, parsed.outboundProfiles),
		OnStarted: reportSandboxStarted(stderr),
	})
	if runErr != nil {
		fmt.Fprintln(stderr, runErr)
		if result.ExitCode != 0 {
			return result.ExitCode
		}
		return 1
	}
	return result.ExitCode
}

func validateSandboxRunArgs(parsed sandboxRunArgs) error {
	if parsed.allOutboundProfiles && len(parsed.outboundProfiles) > 0 {
		return clerr.New(clerr.ConfigInvalid, "--all and --outbound-profile cannot be used together")
	}
	for _, assignment := range parsed.inlineEnv {
		if err := validateEnvAssignment(assignment); err != nil {
			return err
		}
	}
	return nil
}

func sandboxPublications(rawPorts []string) ([]sandbox.PortPublication, error) {
	publications := make([]sandbox.PortPublication, 0, len(rawPorts))
	for _, rawPort := range rawPorts {
		port, err := strconv.ParseUint(rawPort, 10, 16)
		if err != nil || port == 0 {
			return nil, clerr.New(clerr.ConfigInvalid, "published port must be between 1 and 65535")
		}
		publications = append(publications, sandbox.PortPublication{ContainerPort: uint16(port)})
	}
	return publications, nil
}

func sandboxEgressAttacher(runtime sandbox.Runtime, parsed sandboxRunArgs) (sandbox.EgressAttacher, error) {
	if !parsed.allOutboundProfiles && len(parsed.outboundProfiles) == 0 {
		return nil, nil
	}
	attacher, ok := runtime.(sandbox.EgressAttacher)
	if !ok {
		return nil, clerr.New(clerr.RuntimeIncompatible, "sandbox runtime does not support outbound profile attachment")
	}
	return attacher, nil
}

type sandboxLaunch struct {
	resolver       *providerproxy.EnvResolver
	outbound       connection.EgressLease
	outboundConfig connection.EgressClientConfig
}

func (s sandboxLaunch) Close() {
	if s.resolver != nil {
		defer closeQuietly(s.resolver.Close)
	}
	if s.outbound != nil {
		defer closeQuietly(s.outbound.Close)
	}
}

func (a App) openSandboxLaunch(ctx context.Context, runtime sandbox.Runtime, parsed sandboxRunArgs, identity projectbinding.Identity) (sandboxLaunch, error) {
	access := sandbox.GatewayAccess{ListenAddress: "127.0.0.1:0"}
	if accessor, ok := runtime.(sandbox.GatewayAccessor); ok {
		access = accessor.GatewayAccess()
	}
	launch := sandboxLaunch{
		resolver: &providerproxy.EnvResolver{
			Profiles:      a.profiles,
			Secrets:       a.secrets,
			ListenAddress: access.ListenAddress,
			AdvertiseHost: access.AdvertiseHost,
		},
	}
	if len(parsed.outboundProfiles) == 0 {
		return launch, nil
	}
	lease, err := (providerproxy.OutboundResolver{
		Profiles:      a.profiles,
		Secrets:       a.secrets,
		ListenAddress: access.ListenAddress,
		AdvertiseHost: access.AdvertiseHost,
	}).Open(ctx, parsed.outboundProfiles, identity, "sandbox-run")
	if err != nil {
		return launch, err
	}
	launch.outbound = lease
	launch.outboundConfig = lease.ClientConfig()
	return launch, nil
}

func (a App) resolveSandboxEnvironment(ctx context.Context, parsed sandboxRunArgs, identity projectbinding.Identity, launch sandboxLaunch) (map[string]string, *sandboxReferenceResolver, error) {
	references := &sandboxReferenceResolver{
		delegate:          launch.resolver,
		allowMaterialized: parsed.allowMaterializedSecrets,
		lateBound:         referenceSet(launch.outboundConfig.CredentialReferences),
	}
	environment, err := process.BuildEnv(ctx, process.EnvInput{
		EnvFiles:          append([]string(nil), parsed.envFiles...),
		InlineEnv:         append([]string(nil), parsed.inlineEnv...),
		ProjectIdentity:   identity,
		ReferenceResolver: references,
	}, a.profiles, a.issuer)
	if err != nil {
		return nil, nil, err
	}
	return environment, references, nil
}

func (a App) applySandboxAgentAuth(ctx context.Context, agentBinding *sandboxAgentBinding, identity projectbinding.Identity, references *sandboxReferenceResolver, environment map[string]string, command []string) ([]string, []sandbox.Mount, error) {
	if agentBinding == nil {
		return command, nil, nil
	}
	var mounts []sandbox.Mount
	var err error
	switch agentBinding.mode {
	case sandboxAgentAuthBrokered:
		command, err = attachSandboxAgentAuth(ctx, *agentBinding, identity, references, environment, command)
	case sandboxAgentAuthNative:
		var mount sandbox.Mount
		command, mount, err = a.attachSandboxNativeAgentAuth(*agentBinding, environment, command)
		mounts = append(mounts, mount)
	default:
		err = clerr.New(clerr.ConfigInvalid, "unsupported sandbox agent auth mode")
	}
	if err != nil {
		return nil, nil, err
	}
	return command, mounts, nil
}

func reportSandboxCreated(stderr io.Writer, agentBinding *sandboxAgentBinding, egressMode sandbox.EgressMode, outboundProfiles []string) func(string, connection.SecurityLevel) {
	return func(id string, securityLevel connection.SecurityLevel) {
		fmt.Fprintf(stderr, "sandbox: %s\n", id)
		fmt.Fprintf(stderr, "security: %s (experimental; direct egress is not blocked)\n", securityLevel)
		if agentBinding != nil {
			switch agentBinding.mode {
			case sandboxAgentAuthBrokered:
				fmt.Fprintf(stderr, "agent-auth: %s via %s\n", agentBinding.agent, agentBinding.profile.Name)
			case sandboxAgentAuthNative:
				fmt.Fprintf(stderr, "agent-auth: %s native (profile %s)\n", agentBinding.agent, agentBinding.native.Profile)
			}
		}
		if egressMode != "" {
			fmt.Fprintf(stderr, "outbound: %s via %s (URL-preserving prototype)\n", egressMode, strings.Join(outboundProfiles, ", "))
		}
		if securityLevel == connection.SecurityMaterializedStatic {
			fmt.Fprintln(stderr, "warning: raw credentials are available inside the sandbox")
		}
	}
}

func reportSandboxStarted(stderr io.Writer) func(string, []sandbox.PublishedPort) {
	return func(_ string, ports []sandbox.PublishedPort) {
		for _, port := range ports {
			fmt.Fprintf(stderr, "app: http://%s (container port %d)\n", port.HostAddress, port.ContainerPort)
		}
	}
}

func mergeEgressAttachment(environment map[string]string, mounts *[]sandbox.Mount, attachment sandbox.EgressAttachment, gateway connection.Endpoint) error {
	if attachment.Mode != sandbox.EgressProxyEnvironment {
		return clerr.New(clerr.RuntimeIncompatible, "sandbox runtime returned an unsupported outbound attachment mode")
	}
	for key, value := range attachment.Environment {
		if _, exists := environment[key]; exists {
			return clerr.New(clerr.ConfigInvalid, key+" is reserved when --outbound-profile is used")
		}
		environment[key] = value
	}
	existingTargets := make(map[string]struct{}, len(*mounts)+1)
	existingTargets["/workspace"] = struct{}{}
	for _, mount := range *mounts {
		existingTargets[filepath.Clean(mount.Target)] = struct{}{}
	}
	for _, mount := range attachment.Mounts {
		target := filepath.Clean(mount.Target)
		if _, exists := existingTargets[target]; exists {
			return clerr.New(clerr.ConfigInvalid, "outbound attachment mount target conflicts with another sandbox mount")
		}
		existingTargets[target] = struct{}{}
		*mounts = append(*mounts, mount)
	}
	if gateway.Network == "tcp" && gateway.Address != "" {
		addNoProxyEndpoint(environment, gateway.Address)
	}
	return nil
}

func addNoProxyEndpoint(environment map[string]string, address string) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return
	}
	entry := net.JoinHostPort(host, port)
	values := append(splitCommaList(environment["NO_PROXY"]), splitCommaList(environment["no_proxy"])...)
	unique := make([]string, 0, len(values)+1)
	seen := make(map[string]struct{}, len(values)+1)
	for _, value := range append(values, entry) {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	joined := strings.Join(unique, ",")
	environment["NO_PROXY"] = joined
	environment["no_proxy"] = joined
}

func splitCommaList(raw string) []string {
	var values []string
	for _, value := range strings.Split(raw, ",") {
		if value = strings.TrimSpace(value); value != "" {
			values = append(values, value)
		}
	}
	return values
}

func closeSandboxResources(resources []sandbox.Resource) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), resourceCleanupTimeout)
	defer cancel()
	var errs []error
	for index := len(resources) - 1; index >= 0; index-- {
		if resources[index] == nil {
			continue
		}
		if err := resources[index].Close(cleanupCtx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (a App) sandboxWorkspace() (string, error) {
	return a.absoluteInvocationDir("get sandbox workspace", "resolve sandbox workspace")
}

type sandboxReferenceResolver struct {
	delegate          process.ReferenceResolver
	allowMaterialized bool
	lateBound         map[string]struct{}
	materialized      bool
	gateway           connection.Endpoint
}

func (r *sandboxReferenceResolver) ResolveReference(ctx context.Context, ref envref.Reference, identity projectbinding.Identity) (string, error) {
	if ref.Part == envref.PartDefault {
		canonical := envref.Format(ref.Profile, ref.Part)
		if _, ok := r.lateBound[canonical]; ok {
			return canonical, nil
		}
		if !r.allowMaterialized {
			return "", clerr.New(clerr.ConfigInvalid, "direct credential references are not allowed unless attached to a matching outbound profile")
		}
		r.materialized = true
	}
	if r.delegate == nil {
		return "", clerr.New(clerr.RuntimeUnavailable, "sandbox reference resolver unavailable")
	}
	resolved, err := r.delegate.ResolveReference(ctx, ref, identity)
	if err != nil {
		return "", err
	}
	if ref.Part == envref.PartBaseURL {
		if endpoint, ok := endpointFromURL(resolved); ok {
			r.gateway = endpoint
		}
	}
	return resolved, nil
}

func referenceSet(references []string) map[string]struct{} {
	result := make(map[string]struct{}, len(references))
	for _, reference := range references {
		if reference = strings.TrimSpace(reference); reference != "" {
			result[reference] = struct{}{}
		}
	}
	return result
}

func endpointFromURL(raw string) (connection.Endpoint, bool) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" {
		return connection.Endpoint{}, false
	}
	return connection.Endpoint{Network: "tcp", Address: parsed.Host}, true
}
