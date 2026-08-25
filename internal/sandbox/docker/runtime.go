// Package docker implements the experimental Docker sandbox runtime by
// invoking the local Docker CLI. It provides brokered, not enforced, network
// isolation: the application container retains direct bridge egress.
package docker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/sandbox"
)

const (
	defaultPIDs        = 256
	defaultMemoryBytes = 512 << 20
	defaultCPUs        = 1
	homeTarget         = "/home/envvault"
)

type CommandRunner interface {
	Start(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, args ...string) (wait func() error, err error)
	Run(ctx context.Context, stdout, stderr io.Writer, args ...string) error
	Output(ctx context.Context, args ...string) ([]byte, error)
}

type Options struct {
	Binary string
	Runner CommandRunner
}

type Runtime struct {
	runner CommandRunner
}

func New(options Options) *Runtime {
	binary := strings.TrimSpace(options.Binary)
	if binary == "" {
		binary = "docker"
	}
	runner := options.Runner
	if runner == nil {
		runner = execRunner{binary: binary}
	}
	return &Runtime{runner: runner}
}

func (*Runtime) Name() string { return "docker" }

func (*Runtime) GatewayAccess() sandbox.GatewayAccess {
	return sandbox.GatewayAccess{
		ListenAddress: "0.0.0.0:0",
		AdvertiseHost: "host.docker.internal",
	}
}

func (r *Runtime) Check(ctx context.Context) error {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return clerr.New(clerr.RuntimeIncompatible, "experimental Docker sandbox supports macOS and Linux")
	}
	output, err := r.runner.Output(ctx, "version", "--format", "{{.Server.Version}}")
	if err != nil {
		return runtimeUnavailable("check Docker daemon", err)
	}
	if strings.TrimSpace(string(output)) == "" {
		return clerr.New(clerr.RuntimeUnavailable, "Docker daemon version is empty")
	}
	return nil
}

func (r *Runtime) Create(ctx context.Context, spec sandbox.Spec) (sandbox.Sandbox, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	info, err := os.Stat(spec.Workspace.Source)
	if err != nil {
		return nil, clerr.Wrap(clerr.ConfigInvalid, "inspect sandbox workspace", err)
	}
	if !info.IsDir() {
		return nil, clerr.New(clerr.ConfigInvalid, "sandbox workspace must be a directory")
	}
	if err := validateWorkspace(spec); err != nil {
		return nil, err
	}
	if err := validateMounts(spec); err != nil {
		return nil, err
	}

	sandboxID, suffix, err := newSandboxID()
	if err != nil {
		return nil, err
	}
	name := "envvault-sbx-" + suffix
	args := createArgs(spec, sandboxID, name)
	output, err := r.runner.Output(ctx, args...)
	if err != nil {
		return nil, runtimeUnavailable("create Docker sandbox", err)
	}
	containerID := strings.TrimSpace(string(output))
	if containerID == "" {
		return nil, clerr.New(clerr.RuntimeUnavailable, "Docker create returned an empty container id")
	}
	stdout := spec.Stdout
	if stdout == nil {
		stdout = io.Discard
	}
	stderr := spec.Stderr
	if stderr == nil {
		stderr = io.Discard
	}
	return &container{
		id:          sandboxID,
		containerID: containerID,
		runner:      r.runner,
		stdin:       spec.Stdin,
		stdout:      stdout,
		stderr:      stderr,
		interactive: spec.Interactive,
		tty:         spec.TTY,
		published:   append([]sandbox.PortPublication(nil), spec.PublishedPorts...),
	}, nil
}

func createArgs(spec sandbox.Spec, sandboxID, name string) []string {
	pids := spec.Resources.PIDs
	if pids == 0 {
		pids = defaultPIDs
	}
	memory := spec.Resources.MemoryBytes
	if memory == 0 {
		memory = defaultMemoryBytes
	}
	cpus := spec.Resources.CPUs
	if cpus == 0 {
		cpus = defaultCPUs
	}
	environment := make(map[string]string, len(spec.Environment)+2)
	for key, value := range spec.Environment {
		environment[key] = value
	}
	environment["HOME"] = homeTarget
	environment["ENVVAULT_SECURITY_LEVEL"] = string(spec.SecurityLevel)

	args := []string{"create"}
	if spec.Interactive {
		args = append(args, "--interactive")
	}
	if spec.TTY {
		args = append(args, "--tty")
	}
	args = append(args,
		"--name", name,
		"--hostname", sandboxID,
		"--label", "io.envvault.managed=true",
		"--label", "io.envvault.sandbox="+sandboxID,
		"--network", "bridge",
		"--add-host", "host.docker.internal:host-gateway",
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--pids-limit", strconv.Itoa(pids),
		"--memory", strconv.FormatInt(memory, 10),
		"--cpus", strconv.FormatFloat(cpus, 'f', -1, 64),
		"--init",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=67108864",
		"--tmpfs", homeTarget+":rw,noexec,nosuid,nodev,size=16777216",
		"--workdir", spec.WorkingDirectory,
	)
	mount := "type=bind,source=" + spec.Workspace.Source + ",target=" + spec.Workspace.Target
	if spec.Workspace.ReadOnly {
		mount += ",readonly"
	}
	args = append(args, "--mount", mount)
	for _, additional := range spec.Mounts {
		mount := "type=bind,source=" + additional.Source + ",target=" + additional.Target
		if additional.ReadOnly {
			mount += ",readonly"
		}
		args = append(args, "--mount", mount)
	}
	for _, publication := range spec.PublishedPorts {
		args = append(args, "--publish", "127.0.0.1::"+strconv.Itoa(int(publication.ContainerPort)))
	}
	keys := make([]string, 0, len(environment))
	for key := range environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		args = append(args, "--env", key+"="+environment[key])
	}
	args = append(args, spec.Image)
	args = append(args, spec.Command...)
	return args
}

func validateWorkspace(spec sandbox.Spec) error {
	source := filepath.Clean(spec.Workspace.Source)
	if strings.Contains(source, ",") {
		return clerr.New(clerr.ConfigInvalid, "sandbox workspace path must not contain a comma")
	}
	resolvedSource, err := filepath.EvalSymlinks(source)
	if err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "resolve sandbox workspace", err)
	}
	source = filepath.Clean(resolvedSource)
	if filepath.Dir(source) == source {
		return clerr.New(clerr.ConfigInvalid, "sandbox workspace must not be a filesystem root")
	}
	if home, err := os.UserHomeDir(); err == nil {
		resolvedHome, resolveErr := filepath.EvalSymlinks(home)
		if resolveErr == nil && source == filepath.Clean(resolvedHome) {
			return clerr.New(clerr.ConfigInvalid, "sandbox workspace must not be the host home directory")
		}
	}
	for _, socket := range dockerSocketPaths() {
		if pathInside(source, socket) {
			return clerr.New(clerr.ConfigInvalid, "sandbox workspace must not contain the Docker socket")
		}
	}
	if path.Clean(spec.Workspace.Target) != "/workspace" {
		return clerr.New(clerr.ConfigInvalid, "Docker sandbox workspace target must be /workspace")
	}
	workingDirectory := path.Clean(spec.WorkingDirectory)
	if workingDirectory != "/workspace" && !strings.HasPrefix(workingDirectory, "/workspace/") {
		return clerr.New(clerr.ConfigInvalid, "Docker sandbox working directory must be inside /workspace")
	}
	return nil
}

func validateMounts(spec sandbox.Spec) error {
	for _, mount := range spec.Mounts {
		source := filepath.Clean(mount.Source)
		if strings.Contains(source, ",") || strings.Contains(mount.Target, ",") {
			return clerr.New(clerr.ConfigInvalid, "sandbox mount paths must not contain a comma")
		}
		info, err := os.Stat(source)
		if err != nil {
			return clerr.Wrap(clerr.ConfigInvalid, "inspect sandbox mount source", err)
		}
		if !info.IsDir() {
			return clerr.New(clerr.ConfigInvalid, "sandbox mount source must be a directory")
		}
		resolvedSource, err := filepath.EvalSymlinks(source)
		if err != nil {
			return clerr.Wrap(clerr.ConfigInvalid, "resolve sandbox mount source", err)
		}
		source = filepath.Clean(resolvedSource)
		if filepath.Dir(source) == source {
			return clerr.New(clerr.ConfigInvalid, "sandbox mount source must not be a filesystem root")
		}
		if home, err := os.UserHomeDir(); err == nil {
			resolvedHome, resolveErr := filepath.EvalSymlinks(home)
			if resolveErr == nil && source == filepath.Clean(resolvedHome) {
				return clerr.New(clerr.ConfigInvalid, "sandbox mount source must not be the host home directory")
			}
		}
		for _, socket := range dockerSocketPaths() {
			if pathInside(source, socket) {
				return clerr.New(clerr.ConfigInvalid, "sandbox mount source must not contain the Docker socket")
			}
		}
	}
	return nil
}

func dockerSocketPaths() []string {
	paths := []string{"/var/run/docker.sock"}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".docker", "run", "docker.sock"))
	}
	if dockerHost := strings.TrimSpace(os.Getenv("DOCKER_HOST")); strings.HasPrefix(dockerHost, "unix://") {
		paths = append(paths, strings.TrimPrefix(dockerHost, "unix://"))
	}
	resolved := make([]string, 0, len(paths)*2)
	for _, candidate := range paths {
		resolved = append(resolved, filepath.Clean(candidate))
		if target, err := filepath.EvalSymlinks(candidate); err == nil {
			resolved = append(resolved, filepath.Clean(target))
		}
	}
	return resolved
}

func pathInside(parent, candidate string) bool {
	relative, err := filepath.Rel(parent, filepath.Clean(candidate))
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

type container struct {
	mu             sync.Mutex
	id             string
	containerID    string
	runner         CommandRunner
	stdin          io.Reader
	stdout         io.Writer
	stderr         io.Writer
	interactive    bool
	tty            bool
	published      []sandbox.PortPublication
	attachedDone   chan error
	cancelAttached context.CancelFunc
	removed        bool
}

func (c *container) ID() string { return c.id }

func (c *container) Start(ctx context.Context) error {
	if c.interactive || c.tty {
		return c.startAttached(ctx)
	}
	if err := c.runner.Run(ctx, io.Discard, io.Discard, "start", c.containerID); err != nil {
		return runtimeUnavailable("start Docker sandbox", err)
	}
	return nil
}

func (c *container) startAttached(ctx context.Context) error {
	attachedCtx, cancel := context.WithCancel(ctx)
	args := []string{"start", "--attach"}
	if c.interactive {
		args = append(args, "--interactive")
	}
	args = append(args, c.containerID)
	wait, err := c.runner.Start(attachedCtx, c.stdin, c.stdout, c.stderr, args...)
	if err != nil {
		cancel()
		return runtimeUnavailable("start attached Docker sandbox", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- wait()
	}()
	c.mu.Lock()
	c.attachedDone = done
	c.cancelAttached = cancel
	c.mu.Unlock()
	if err := c.waitUntilStarted(ctx, done); err != nil {
		cancel()
		return err
	}
	return nil
}

func (c *container) waitUntilStarted(ctx context.Context, done chan error) error {
	const pollInterval = 10 * time.Millisecond
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	finished := false
	var finishedErr error
	for {
		output, err := c.runner.Output(ctx, "inspect", "--format", "{{.State.Status}}", c.containerID)
		if err != nil {
			return runtimeUnavailable("inspect attached Docker sandbox", err)
		}
		switch strings.TrimSpace(string(output)) {
		case "running", "paused", "restarting", "exited", "dead":
			return nil
		case "created":
			if finished {
				if finishedErr != nil {
					return runtimeUnavailable("start attached Docker sandbox", finishedErr)
				}
				return clerr.New(clerr.RuntimeUnavailable, "attached Docker sandbox did not start")
			}
		default:
			return clerr.New(clerr.RuntimeUnavailable, "Docker returned an invalid sandbox state")
		}

		select {
		case finishedErr = <-done:
			done <- finishedErr
			finished = true
		case <-ticker.C:
		case <-ctx.Done():
			return runtimeUnavailable("start attached Docker sandbox", ctx.Err())
		}
	}
}

func (c *container) PublishedPorts(ctx context.Context) ([]sandbox.PublishedPort, error) {
	ports := make([]sandbox.PublishedPort, 0, len(c.published))
	for _, publication := range c.published {
		output, err := c.runner.Output(ctx, "port", c.containerID, strconv.Itoa(int(publication.ContainerPort))+"/tcp")
		if err != nil {
			return nil, runtimeUnavailable("inspect Docker published port", err)
		}
		address, err := loopbackPublishedAddress(string(output))
		if err != nil {
			return nil, err
		}
		ports = append(ports, sandbox.PublishedPort{
			ContainerPort: publication.ContainerPort,
			HostAddress:   address,
		})
	}
	return ports, nil
}

func (c *container) Wait(ctx context.Context) (sandbox.ExitResult, error) {
	c.mu.Lock()
	attachedDone := c.attachedDone
	cancelAttached := c.cancelAttached
	c.mu.Unlock()
	if attachedDone != nil {
		return c.waitAttached(ctx, attachedDone, cancelAttached)
	}

	logsDone := make(chan error, 1)
	logsCtx, cancelLogs := context.WithCancel(ctx)
	defer cancelLogs()
	go func() {
		logsDone <- c.runner.Run(logsCtx, c.stdout, c.stderr, "logs", "--follow", c.containerID)
	}()

	output, err := c.runner.Output(ctx, "wait", c.containerID)
	if err != nil {
		cancelLogs()
		<-logsDone
		return sandbox.ExitResult{}, runtimeUnavailable("wait for Docker sandbox", err)
	}
	logsErr := <-logsDone
	if logsErr != nil && ctx.Err() == nil {
		return sandbox.ExitResult{}, runtimeUnavailable("stream Docker sandbox logs", logsErr)
	}
	code, err := strconv.Atoi(strings.TrimSpace(string(output)))
	if err != nil || code < 0 || code > 255 {
		return sandbox.ExitResult{}, clerr.New(clerr.RuntimeUnavailable, "Docker wait returned an invalid exit code")
	}
	return sandbox.ExitResult{Code: code}, nil
}

func (c *container) waitAttached(ctx context.Context, done <-chan error, cancel context.CancelFunc) (sandbox.ExitResult, error) {
	if cancel != nil {
		defer cancel()
	}
	output, err := c.runner.Output(ctx, "wait", c.containerID)
	if err != nil {
		return sandbox.ExitResult{}, runtimeUnavailable("wait for attached Docker sandbox", err)
	}
	code, err := strconv.Atoi(strings.TrimSpace(string(output)))
	if err != nil || code < 0 || code > 255 {
		return sandbox.ExitResult{}, clerr.New(clerr.RuntimeUnavailable, "Docker wait returned an invalid exit code")
	}

	var attachedErr error
	select {
	case attachedErr = <-done:
	case <-ctx.Done():
		if cancel != nil {
			cancel()
		}
		return sandbox.ExitResult{}, runtimeUnavailable("wait for attached Docker output", ctx.Err())
	}
	if attachedErr != nil && !commandExitedWith(attachedErr, code) {
		return sandbox.ExitResult{}, runtimeUnavailable("stream attached Docker sandbox", attachedErr)
	}
	return sandbox.ExitResult{Code: code}, nil
}

func (c *container) Stop(ctx context.Context) error {
	if err := c.runner.Run(ctx, io.Discard, io.Discard, "stop", "--time", "2", c.containerID); err != nil {
		return clerr.Wrap(clerr.CleanupFailed, "stop Docker sandbox", redactedCommandError{err: err})
	}
	return nil
}

func (c *container) Remove(ctx context.Context) error {
	c.mu.Lock()
	if c.removed {
		c.mu.Unlock()
		return nil
	}
	cancelAttached := c.cancelAttached
	c.mu.Unlock()
	if cancelAttached != nil {
		cancelAttached()
	}
	if err := c.runner.Run(ctx, io.Discard, io.Discard, "rm", "--force", c.containerID); err != nil {
		return clerr.Wrap(clerr.CleanupFailed, "remove Docker sandbox", redactedCommandError{err: err})
	}
	c.mu.Lock()
	c.removed = true
	c.mu.Unlock()
	return nil
}

type execRunner struct {
	binary string
}

func (r execRunner) Start(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, args ...string) (func() error, error) {
	cmd := exec.CommandContext(ctx, r.binary, args...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd.Wait, nil
}

func (r execRunner) Run(ctx context.Context, stdout, stderr io.Writer, args ...string) error {
	cmd := exec.CommandContext(ctx, r.binary, args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

func (r execRunner) Output(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, r.binary, args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return stdout.Bytes(), nil
}

type redactedCommandError struct {
	err error
}

func (e redactedCommandError) Error() string {
	return "Docker command failed"
}

func (e redactedCommandError) Unwrap() error { return e.err }

func runtimeUnavailable(message string, err error) error {
	return clerr.Wrap(clerr.RuntimeUnavailable, message, redactedCommandError{err: err})
}

func commandExitedWith(err error, code int) bool {
	var exitError interface{ ExitCode() int }
	return errors.As(err, &exitError) && exitError.ExitCode() == code
}

func newSandboxID() (id, suffix string, err error) {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", "", clerr.Wrap(clerr.RuntimeUnavailable, "generate sandbox id", err)
	}
	suffix = hex.EncodeToString(raw[:])
	return "sbx_" + suffix, suffix, nil
}

func loopbackPublishedAddress(output string) (string, error) {
	for _, line := range strings.Split(output, "\n") {
		address := strings.TrimSpace(line)
		if address == "" {
			continue
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || port == "" {
			continue
		}
		return net.JoinHostPort(host, port), nil
	}
	return "", clerr.New(clerr.RuntimeUnavailable, "Docker did not report a loopback published port")
}
