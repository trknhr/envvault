package docker_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/connection"
	"github.com/trknhr/envvault/internal/sandbox"
	sandboxdocker "github.com/trknhr/envvault/internal/sandbox/docker"
)

func TestRuntimeCreatesHardenedContainerAndStreamsExit(t *testing.T) {
	runner := &fakeRunner{}
	runtime := sandboxdocker.New(sandboxdocker.Options{Runner: runner})
	var stdout, stderr bytes.Buffer
	spec := validSpec(t)
	spec.Stdout = &stdout
	spec.Stderr = &stderr

	if err := runtime.Check(context.Background()); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	instance, err := runtime.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if !strings.HasPrefix(instance.ID(), "sbx_") {
		t.Fatalf("ID() = %q", instance.ID())
	}
	if err := instance.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	exit, err := instance.Wait(context.Background())
	if err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	if exit.Code != 23 {
		t.Fatalf("exit code = %d", exit.Code)
	}
	if stdout.String() != "container stdout\n" || stderr.String() != "container stderr\n" {
		t.Fatalf("logs stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if err := instance.Remove(context.Background()); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	if err := instance.Remove(context.Background()); err != nil {
		t.Fatalf("second Remove() error = %v", err)
	}

	create := runner.findOutputCall("create")
	joined := strings.Join(create, "\x00")
	for _, required := range []string{
		"--network\x00bridge",
		"--read-only",
		"--cap-drop\x00ALL",
		"--security-opt\x00no-new-privileges",
		"--pids-limit\x00256",
		"--memory\x00536870912",
		"--cpus\x001",
		"--add-host\x00host.docker.internal:host-gateway",
		"--env\x00ENVVAULT_SECURITY_LEVEL=brokered",
		"--env\x00HOME=/home/envvault",
		"--workdir\x00/workspace",
		"example:test\x00run-tests",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("Docker create is missing required hardening option %q", required)
		}
	}
	if !strings.Contains(joined, "--env\x00API_TOKEN=envvault-local-test") {
		t.Fatal("Docker create is missing the sandbox session capability")
	}
	for _, forbidden := range []struct {
		name   string
		needle string
	}{
		{name: "upstream credential", needle: "secret-canary"},
		{name: "host home", needle: "/sensitive-home"},
		{name: "Docker socket", needle: "/var/run/docker.sock"},
		{name: "privileged mode", needle: "--privileged"},
		{name: "host network", needle: "--network\x00host"},
	} {
		if strings.Contains(joined, forbidden.needle) {
			t.Fatalf("Docker create contains forbidden %s", forbidden.name)
		}
	}
	if got := runner.countRunCall("rm"); got != 1 {
		t.Fatalf("docker rm calls = %d, want 1", got)
	}
}

func TestRuntimeCreatesInteractiveTTYAndAttachesStreams(t *testing.T) {
	runner := &fakeRunner{attachedExitCode: 23}
	runtime := sandboxdocker.New(sandboxdocker.Options{Runner: runner})
	input := strings.NewReader("interactive input\n")
	var stdout, stderr bytes.Buffer
	spec := validSpec(t)
	spec.Stdin = input
	spec.Stdout = &stdout
	spec.Stderr = &stderr
	spec.Interactive = true
	spec.TTY = true

	instance, err := runtime.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := instance.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	exit, err := instance.Wait(context.Background())
	if err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	if exit.Code != 23 {
		t.Fatalf("exit code = %d", exit.Code)
	}

	create := strings.Join(runner.findOutputCall("create"), "\x00")
	for _, required := range []string{"--interactive", "--tty"} {
		if !strings.Contains(create, required) {
			t.Fatalf("Docker create is missing %q: %q", required, create)
		}
	}
	if call := runner.findStartCall("start"); strings.Join(call, " ") != "start --attach --interactive container-test-id" {
		t.Fatalf("attached Docker start args = %#v", call)
	}
	if runner.startedStdin != input || runner.startedStdout != &stdout || runner.startedStderr != &stderr {
		t.Fatal("attached Docker start did not receive the sandbox streams")
	}
	if got := runner.countRunCall("logs"); got != 0 {
		t.Fatalf("docker logs calls = %d, want 0 for attached execution", got)
	}
	if stdout.String() != "attached stdout\n" || stderr.String() != "attached stderr\n" {
		t.Fatalf("attached stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRuntimeCreatesTrustedAdditionalDirectoryMount(t *testing.T) {
	runner := &fakeRunner{}
	runtime := sandboxdocker.New(sandboxdocker.Options{Runner: runner})
	spec := validSpec(t)
	source := t.TempDir()
	spec.Mounts = []sandbox.Mount{{
		Source: source,
		Target: "/home/envvault/.codex",
	}}

	if _, err := runtime.Create(context.Background(), spec); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	create := strings.Join(runner.findOutputCall("create"), "\x00")
	want := "--mount\x00type=bind,source=" + source + ",target=/home/envvault/.codex"
	if !strings.Contains(create, want) {
		t.Fatalf("Docker create = %q, want additional mount %q", create, want)
	}
}

func TestRuntimeRejectsUnsafeAdditionalMountSource(t *testing.T) {
	runner := &fakeRunner{}
	runtime := sandboxdocker.New(sandboxdocker.Options{Runner: runner})
	spec := validSpec(t)
	spec.Mounts = []sandbox.Mount{{Source: string(filepath.Separator), Target: "/home/envvault/.codex"}}

	if _, err := runtime.Create(context.Background(), spec); err == nil {
		t.Fatal("Create() error = nil")
	}
	if call := runner.findOutputCall("create"); call != nil {
		t.Fatalf("Docker create was called for unsafe mount: %#v", call)
	}
}

func TestRuntimeGatewayAccessUsesContainerReachableHost(t *testing.T) {
	runtime := sandboxdocker.New(sandboxdocker.Options{Runner: &fakeRunner{}})
	access := runtime.GatewayAccess()
	if access.ListenAddress != "0.0.0.0:0" || access.AdvertiseHost != "host.docker.internal" {
		t.Fatalf("GatewayAccess() = %#v", access)
	}
}

func TestRuntimeRedactsCommandFailure(t *testing.T) {
	runner := &fakeRunner{createErr: errors.New("secret-canary")}
	runtime := sandboxdocker.New(sandboxdocker.Options{Runner: runner})
	_, err := runtime.Create(context.Background(), validSpec(t))
	if err == nil {
		t.Fatal("Create() error = nil")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.RuntimeUnavailable {
		t.Fatalf("CodeOf(error) = %q", code)
	}
	if strings.Contains(err.Error(), "secret-canary") {
		t.Fatalf("Create() error leaked command failure: %v", err)
	}
}

func TestRuntimeStopUsesBoundedDockerStop(t *testing.T) {
	runner := &fakeRunner{}
	runtime := sandboxdocker.New(sandboxdocker.Options{Runner: runner})
	instance, err := runtime.Create(context.Background(), validSpec(t))
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := instance.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	call := runner.findRunCall("stop")
	if strings.Join(call, " ") != "stop --time 2 container-test-id" {
		t.Fatalf("docker stop args = %#v", call)
	}
}

func TestRuntimeReportsPublishedLoopbackPort(t *testing.T) {
	runner := &fakeRunner{}
	runtime := sandboxdocker.New(sandboxdocker.Options{Runner: runner})
	spec := validSpec(t)
	spec.PublishedPorts = []sandbox.PortPublication{{ContainerPort: 3000}}
	instance, err := runtime.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	publisher, ok := instance.(sandbox.PortPublisher)
	if !ok {
		t.Fatalf("sandbox type %T does not implement PortPublisher", instance)
	}
	ports, err := publisher.PublishedPorts(context.Background())
	if err != nil {
		t.Fatalf("PublishedPorts() error = %v", err)
	}
	if len(ports) != 1 || ports[0].ContainerPort != 3000 || ports[0].HostAddress != "127.0.0.1:49172" {
		t.Fatalf("PublishedPorts() = %#v", ports)
	}
}

func TestRuntimeRejectsWorkspaceSymlinkResolvingToFilesystemRoot(t *testing.T) {
	link := filepath.Join(t.TempDir(), "workspace-link")
	if err := os.Symlink(string(filepath.Separator), link); err != nil {
		t.Skipf("cannot create workspace symlink: %v", err)
	}
	runner := &fakeRunner{}
	runtime := sandboxdocker.New(sandboxdocker.Options{Runner: runner})
	spec := validSpec(t)
	spec.Workspace.Source = link

	if _, err := runtime.Create(context.Background(), spec); err == nil {
		t.Fatal("Create() error = nil")
	}
	if call := runner.findOutputCall("create"); call != nil {
		t.Fatalf("Docker create was called for unsafe workspace: %#v", call)
	}
}

func validSpec(t *testing.T) sandbox.Spec {
	t.Helper()
	return sandbox.Spec{
		Image:            "example:test",
		Command:          []string{"run-tests"},
		WorkingDirectory: "/workspace",
		Environment: map[string]string{
			"API_TOKEN": "envvault-local-test",
			"HOME":      "/sensitive-home",
		},
		Workspace: sandbox.WorkspaceMount{
			Source: t.TempDir(),
			Target: "/workspace",
		},
		Network:       sandbox.NetworkAttachment{Mode: sandbox.NetworkBridge},
		SecurityLevel: connection.SecurityBrokered,
		Stdout:        io.Discard,
		Stderr:        io.Discard,
	}
}

type commandCall struct {
	kind string
	args []string
}

type fakeRunner struct {
	mu               sync.Mutex
	calls            []commandCall
	createErr        error
	startErr         error
	attachedExitCode int
	startedStdin     io.Reader
	startedStdout    io.Writer
	startedStderr    io.Writer
}

func (r *fakeRunner) Start(_ context.Context, stdin io.Reader, stdout, stderr io.Writer, args ...string) (func() error, error) {
	r.record("start", args)
	r.mu.Lock()
	r.startedStdin = stdin
	r.startedStdout = stdout
	r.startedStderr = stderr
	startErr := r.startErr
	exitCode := r.attachedExitCode
	r.mu.Unlock()
	if startErr != nil {
		return nil, startErr
	}
	_, _ = io.WriteString(stdout, "attached stdout\n")
	_, _ = io.WriteString(stderr, "attached stderr\n")
	return func() error {
		if exitCode == 0 {
			return nil
		}
		return fakeExitError{code: exitCode}
	}, nil
}

func (r *fakeRunner) Run(_ context.Context, stdout, stderr io.Writer, args ...string) error {
	r.record("run", args)
	if len(args) > 0 && args[0] == "logs" {
		_, _ = io.WriteString(stdout, "container stdout\n")
		_, _ = io.WriteString(stderr, "container stderr\n")
	}
	return nil
}

func (r *fakeRunner) Output(_ context.Context, args ...string) ([]byte, error) {
	r.record("output", args)
	if len(args) == 0 {
		return nil, errors.New("missing command")
	}
	switch args[0] {
	case "version":
		return []byte("28.3.2\n"), nil
	case "create":
		if r.createErr != nil {
			return nil, r.createErr
		}
		return []byte("container-test-id\n"), nil
	case "wait":
		return []byte("23\n"), nil
	case "inspect":
		return []byte("running\n"), nil
	case "port":
		return []byte("127.0.0.1:49172\n"), nil
	default:
		return nil, errors.New("unexpected command")
	}
}

func (r *fakeRunner) record(kind string, args []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, commandCall{kind: kind, args: append([]string(nil), args...)})
}

func (r *fakeRunner) findOutputCall(command string) []string {
	return r.findCall("output", command)
}

func (r *fakeRunner) findRunCall(command string) []string {
	return r.findCall("run", command)
}

func (r *fakeRunner) findStartCall(command string) []string {
	return r.findCall("start", command)
}

func (r *fakeRunner) findCall(kind, command string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, call := range r.calls {
		if call.kind == kind && len(call.args) > 0 && call.args[0] == command {
			return append([]string(nil), call.args...)
		}
	}
	return nil
}

type fakeExitError struct {
	code int
}

func (e fakeExitError) Error() string { return "attached command exited" }

func (e fakeExitError) ExitCode() int { return e.code }

func (r *fakeRunner) countRunCall(command string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for _, call := range r.calls {
		if call.kind == "run" && len(call.args) > 0 && call.args[0] == command {
			count++
		}
	}
	return count
}
