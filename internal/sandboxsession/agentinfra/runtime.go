// Package agentinfra uses only agent-infra's versioned CLI session contract.
// It never imports npm internals or implements Docker/clipboard behavior.
package agentinfra

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/sandbox"
	"github.com/trknhr/envvault/internal/sandboxplugin"
	"github.com/trknhr/envvault/internal/sandboxsession"
)

const Protocol = "agent-infra.sandbox-session/v1"

type Runtime struct {
	Executable string
}

type preparation struct {
	Protocol    string `json:"protocol"`
	Target      string `json:"target"`
	ContainerID string `json:"container_id"`
	ProjectRoot string `json:"project_root"`
	GitRemote   string `json:"git_remote"`
	Engine      string `json:"engine"`
}

var fullID = regexp.MustCompile(`^[a-f0-9]{64}$`)

func (r Runtime) executable() string {
	if r.Executable != "" {
		return r.Executable
	}
	return "agent-infra"
}

func (r Runtime) Prepare(ctx context.Context, target sandboxsession.Target) (sandboxsession.Prepared, error) {
	if runtime.GOOS != "darwin" {
		return sandboxsession.Prepared{}, clerr.New(clerr.RuntimeIncompatible, "agent-infra sessions currently require macOS and local Docker Desktop")
	}
	prepareCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	args := []string{"sandbox", "session", "prepare", "--protocol", Protocol, "--target", target.Reference}
	if !target.Interactive {
		args = append(args, "--non-interactive")
	}
	cmd := exec.CommandContext(prepareCtx, r.executable(), args...)
	cmd.Dir, cmd.Env = target.Directory, target.ParentEnv
	var output boundedOutput
	cmd.Stdout, cmd.Stderr = &output, io.Discard
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Run(); err != nil {
		return sandboxsession.Prepared{}, clerr.New(clerr.RuntimeIncompatible,
			"cannot prepare agent-infra session: a session-capable build and a running branch sandbox are required; use --runtime-command to select the local integration build")
	}
	prepared, err := decodePreparation(output.Bytes(), target)
	if err != nil {
		return sandboxsession.Prepared{}, err
	}
	return prepared, nil
}

func decodePreparation(data []byte, target sandboxsession.Target) (sandboxsession.Prepared, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var response preparation
	err := decoder.Decode(&response)
	var extra any
	if err != nil || !errors.Is(decoder.Decode(&extra), io.EOF) || response.Protocol != Protocol || response.Target != target.Reference ||
		!fullID.MatchString(response.ContainerID) || !filepath.IsAbs(response.ProjectRoot) || response.Engine != "docker-desktop" {
		return sandboxsession.Prepared{}, clerr.New(clerr.RuntimeIncompatible, "agent-infra returned an unsupported or invalid session descriptor")
	}
	return sandboxsession.Prepared{
		ID: response.ContainerID, Target: target,
		Project: sandboxplugin.ProjectIdentity{Root: response.ProjectRoot, GitRemote: response.GitRemote},
		Gateway: sandbox.GatewayAccess{ListenAddress: "0.0.0.0:0", AdvertiseHost: "host.docker.internal"},
	}, nil
}

func executionArgs(prepared sandboxsession.Prepared, command sandboxsession.Command) []string {
	args := []string{"sandbox", "session", "exec", "--protocol", Protocol,
		"--target", prepared.Target.Reference, "--container-id", prepared.ID}
	if !prepared.Target.Interactive {
		args = append(args, "--non-interactive")
	}
	names := make([]string, 0, len(command.Environment))
	for name := range command.Environment {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		args = append(args, "--env", name)
	}
	return append(append(args, "--"), command.Args...)
}

func (r Runtime) Run(ctx context.Context, prepared sandboxsession.Prepared, command sandboxsession.Command) (int, error) {
	if err := sandboxsession.ValidateEnvironment(command.Environment); err != nil {
		return 1, err
	}
	if !fullID.MatchString(prepared.ID) || len(command.Args) == 0 {
		return 1, clerr.New(clerr.ConfigInvalid, "a pinned sandbox and child command are required")
	}
	cmd := exec.CommandContext(ctx, r.executable(), executionArgs(prepared, command)...)
	cmd.Dir = prepared.Target.Directory
	// Only the new host runtime process receives the temporary values. Names,
	// not values, appear in argv; agent-infra forwards just those names.
	cmd.Env = mergeEnvironment(prepared.Target.ParentEnv, command.Environment)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = command.Stdin, command.Stdout, command.Stderr
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	if ctx.Err() != nil {
		return 1, clerr.New(clerr.RuntimeUnavailable, "sandbox session canceled or credential lease expired")
	}
	var exited *exec.ExitError
	if errors.As(err, &exited) && exited.ExitCode() >= 0 {
		return exited.ExitCode(), nil
	}
	if err != nil {
		return 1, clerr.New(clerr.RuntimeUnavailable, "agent-infra session could not complete")
	}
	return 0, nil
}

func mergeEnvironment(parent []string, selected map[string]string) []string {
	result := make([]string, 0, len(parent)+len(selected))
	for _, assignment := range parent {
		name, _, _ := strings.Cut(assignment, "=")
		if _, replaced := selected[name]; !replaced {
			result = append(result, assignment)
		}
	}
	for name, value := range selected {
		result = append(result, name+"="+value)
	}
	return result
}

type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(data []byte) (int, error) {
	if b.Len()+len(data) > 64<<10 {
		return 0, errors.New("session descriptor exceeded 64 KiB")
	}
	return b.Buffer.Write(data)
}
