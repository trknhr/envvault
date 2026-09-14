package agentinfra

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/sandboxsession"
)

func TestSessionDescriptorValidation(t *testing.T) {
	target := sandboxsession.Target{Reference: "trial"}
	valid := preparation{Protocol: Protocol, Target: "trial", ContainerID: strings.Repeat("a", 64),
		ProjectRoot: t.TempDir(), Engine: "docker-desktop"}
	encoded, _ := json.Marshal(valid)
	got, err := decodePreparation(encoded, target)
	if err != nil || got.ID != valid.ContainerID || got.Project.Root != valid.ProjectRoot || got.Gateway.AdvertiseHost != "host.docker.internal" {
		t.Fatalf("descriptor: %#v %v", got, err)
	}
	for _, mutate := range []func(*preparation){
		func(p *preparation) { p.Protocol = "v999" },
		func(p *preparation) { p.Target = "other" },
		func(p *preparation) { p.ContainerID = "short" },
		func(p *preparation) { p.ProjectRoot = "relative" },
		func(p *preparation) { p.Engine = "remote" },
	} {
		invalid := valid
		mutate(&invalid)
		data, _ := json.Marshal(invalid)
		if _, err := decodePreparation(data, target); err == nil {
			t.Fatal("invalid descriptor accepted")
		}
	}
	for _, data := range [][]byte{[]byte("not-json"), append(encoded, []byte("\n{}")...), []byte("null")} {
		if _, err := decodePreparation(data, target); err == nil {
			t.Fatal("invalid framing accepted")
		}
	}
}

func TestSessionExecutionArgvDoesNotContainCapabilities(t *testing.T) {
	prepared := sandboxsession.Prepared{ID: strings.Repeat("a", 64), Target: sandboxsession.Target{Reference: "trial"}}
	command := sandboxsession.Command{Args: []string{"node", "--version"}, Environment: map[string]string{"APP_TOKEN": "canary", "APP_URL": "http://gateway"}}
	want := []string{"sandbox", "session", "exec", "--protocol", Protocol, "--target", "trial", "--container-id", prepared.ID,
		"--non-interactive", "--env", "APP_TOKEN", "--env", "APP_URL", "--", "node", "--version"}
	if got := executionArgs(prepared, command); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %#v", got)
	}
	merged := mergeEnvironment([]string{"PATH=/bin", "APP_TOKEN=stale"}, command.Environment)
	for _, item := range merged {
		if item == "APP_TOKEN=stale" {
			t.Fatal("stale value survived")
		}
	}
}

func TestSessionDescriptorOutputBound(t *testing.T) {
	var output boundedOutput
	if _, err := output.Write(make([]byte, 64<<10)); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Write([]byte("x")); err == nil {
		t.Fatal("descriptor output was unbounded")
	}
}

func TestSessionExecutableExitAndCancellation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix runtime executable")
	}
	dir := t.TempDir()
	executable := filepath.Join(dir, "agent-infra-fixture")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexec \"$SESSION_TEST_BINARY\" -test.run=TestSessionExecutableHelper -- \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	prepared := sandboxsession.Prepared{ID: strings.Repeat("a", 64), Target: sandboxsession.Target{
		Reference: "trial", Directory: dir, ParentEnv: append(os.Environ(), "SESSION_TEST_BINARY="+binary, "SESSION_TEST_HELPER=1"),
	}}
	var stdout, stderr bytes.Buffer
	command := sandboxsession.Command{Args: []string{"probe"}, Environment: map[string]string{"APP_TOKEN": "synthetic-capability"}, Stdout: &stdout, Stderr: &stderr}
	code, err := (Runtime{Executable: executable}).Run(context.Background(), prepared, command)
	if err != nil || code != 7 || stdout.String() != "session-probe-ok\n" || stderr.Len() != 0 {
		t.Fatalf("run: %d %v %q %q", code, err, stdout.String(), stderr.String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	command.Args = []string{"wait"}
	started := time.Now()
	if _, err := (Runtime{Executable: executable}).Run(ctx, prepared, command); err == nil || time.Since(started) > 4*time.Second {
		t.Fatalf("cancellation: %v", err)
	}
}

func TestSessionExecutableHelper(t *testing.T) {
	if os.Getenv("SESSION_TEST_HELPER") != "1" {
		return
	}
	args := os.Args
	if args[len(args)-1] == "wait" {
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	if os.Getenv("APP_TOKEN") != "synthetic-capability" || strings.Contains(strings.Join(args, " "), "synthetic-capability") {
		os.Exit(99)
	}
	fmt.Println("session-probe-ok")
	os.Exit(7)
}
