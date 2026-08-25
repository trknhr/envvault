package sandbox_test

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/connection"
	"github.com/trknhr/envvault/internal/sandbox"
)

func TestOrchestratorRunsAndCleansLifecycleInOrder(t *testing.T) {
	events := &eventLog{}
	instance := &fakeSandbox{id: "sbx-test", events: events, exit: sandbox.ExitResult{Code: 17}}
	runtime := &fakeRuntime{events: events, instance: instance}
	resource := &fakeResource{events: events}
	var createdID string

	result, err := (sandbox.Orchestrator{CleanupTimeout: time.Second}).Run(context.Background(), sandbox.RunRequest{
		Runtime:   runtime,
		Spec:      validSpec(t),
		Resources: []sandbox.Resource{resource},
		OnCreated: func(id string, level connection.SecurityLevel) {
			createdID = id
			if level != connection.SecurityBrokered {
				t.Errorf("created security level = %q", level)
			}
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.SandboxID != "sbx-test" || result.ExitCode != 17 || result.Interrupted {
		t.Fatalf("Run() result = %#v", result)
	}
	if createdID != "sbx-test" {
		t.Fatalf("OnCreated id = %q", createdID)
	}
	wantEvents(t, events, "check", "create", "start", "wait", "remove", "resource-close")
}

func TestOrchestratorPreservesStartErrorBeforeCleanupErrors(t *testing.T) {
	startErr := errors.New("start failed")
	stopErr := errors.New("stop failed")
	removeErr := errors.New("remove failed")
	resourceErr := errors.New("resource close failed")
	events := &eventLog{}
	instance := &fakeSandbox{
		id:        "sbx-test",
		events:    events,
		startErr:  startErr,
		stopErr:   stopErr,
		removeErr: removeErr,
	}
	runtime := &fakeRuntime{events: events, instance: instance}
	resource := &fakeResource{events: events, err: resourceErr}

	_, err := (sandbox.Orchestrator{CleanupTimeout: time.Second}).Run(context.Background(), sandbox.RunRequest{
		Runtime:   runtime,
		Spec:      validSpec(t),
		Resources: []sandbox.Resource{resource},
	})
	for _, want := range []error{startErr, stopErr, removeErr, resourceErr} {
		if !errors.Is(err, want) {
			t.Fatalf("Run() error = %v, want errors.Is(%v)", err, want)
		}
	}
	if !strings.HasPrefix(err.Error(), startErr.Error()) {
		t.Fatalf("Run() error = %q, want primary error first", err)
	}
	wantEvents(t, events, "check", "create", "start", "stop", "remove", "resource-close")
}

func TestOrchestratorStopsOnWaitFailure(t *testing.T) {
	waitErr := errors.New("wait failed")
	events := &eventLog{}
	instance := &fakeSandbox{id: "sbx-test", events: events, waitErr: waitErr}
	runtime := &fakeRuntime{events: events, instance: instance}

	_, err := (sandbox.Orchestrator{CleanupTimeout: time.Second}).Run(context.Background(), sandbox.RunRequest{
		Runtime: runtime,
		Spec:    validSpec(t),
	})
	if !errors.Is(err, waitErr) {
		t.Fatalf("Run() error = %v", err)
	}
	wantEvents(t, events, "check", "create", "start", "wait", "stop", "remove")
}

func TestOrchestratorStopsOnSignalAndReturnsContainerExit(t *testing.T) {
	events := &eventLog{}
	instance := &fakeSandbox{
		id:        "sbx-test",
		events:    events,
		waitUntil: make(chan struct{}),
		exit:      sandbox.ExitResult{Code: 143},
	}
	runtime := &fakeRuntime{events: events, instance: instance}
	signals := make(chan os.Signal, 1)
	signals <- os.Interrupt

	result, err := (sandbox.Orchestrator{CleanupTimeout: time.Second}).Run(context.Background(), sandbox.RunRequest{
		Runtime: runtime,
		Spec:    validSpec(t),
		Signals: signals,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.ExitCode != 143 || !result.Interrupted {
		t.Fatalf("Run() result = %#v", result)
	}
	wantEvents(t, events, "check", "create", "start", "stop", "wait", "remove")
}

func TestOrchestratorReturnsCleanupErrorWithoutReplacingExitCode(t *testing.T) {
	removeErr := errors.New("remove failed")
	events := &eventLog{}
	instance := &fakeSandbox{
		id:        "sbx-test",
		events:    events,
		exit:      sandbox.ExitResult{Code: 23},
		removeErr: removeErr,
	}
	runtime := &fakeRuntime{events: events, instance: instance}

	result, err := (sandbox.Orchestrator{CleanupTimeout: time.Second}).Run(context.Background(), sandbox.RunRequest{
		Runtime: runtime,
		Spec:    validSpec(t),
	})
	if !errors.Is(err, removeErr) {
		t.Fatalf("Run() error = %v", err)
	}
	if result.ExitCode != 23 {
		t.Fatalf("Run() exit code = %d", result.ExitCode)
	}
}

func TestOrchestratorReportsPublishedPortsAfterStart(t *testing.T) {
	events := &eventLog{}
	wantPorts := []sandbox.PublishedPort{{ContainerPort: 3000, HostAddress: "127.0.0.1:49172"}}
	instance := &fakeSandbox{
		id:        "sbx-test",
		events:    events,
		exit:      sandbox.ExitResult{Code: 0},
		published: wantPorts,
	}
	runtime := &fakeRuntime{events: events, instance: instance}
	spec := validSpec(t)
	spec.PublishedPorts = []sandbox.PortPublication{{ContainerPort: 3000}}
	var startedID string
	var startedPorts []sandbox.PublishedPort

	result, err := (sandbox.Orchestrator{CleanupTimeout: time.Second}).Run(context.Background(), sandbox.RunRequest{
		Runtime: runtime,
		Spec:    spec,
		OnStarted: func(id string, ports []sandbox.PublishedPort) {
			startedID = id
			startedPorts = ports
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if startedID != "sbx-test" || len(startedPorts) != 1 || startedPorts[0] != wantPorts[0] {
		t.Fatalf("OnStarted() = %q/%#v", startedID, startedPorts)
	}
	if len(result.PublishedPorts) != 1 || result.PublishedPorts[0] != wantPorts[0] {
		t.Fatalf("Run() published ports = %#v", result.PublishedPorts)
	}
	wantEvents(t, events, "check", "create", "start", "ports", "wait", "remove")
}

func TestSpecValidateRejectsUnsafeOrIncompleteValues(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*sandbox.Spec)
	}{
		{name: "missing image", mutate: func(s *sandbox.Spec) { s.Image = "" }},
		{name: "missing command", mutate: func(s *sandbox.Spec) { s.Command = nil }},
		{name: "relative workspace", mutate: func(s *sandbox.Spec) { s.Workspace.Source = "relative" }},
		{name: "relative workdir", mutate: func(s *sandbox.Spec) { s.WorkingDirectory = "workspace" }},
		{name: "relative mount source", mutate: func(s *sandbox.Spec) { s.Mounts = []sandbox.Mount{{Source: "relative", Target: "/state"}} }},
		{name: "root mount target", mutate: func(s *sandbox.Spec) { s.Mounts = []sandbox.Mount{{Source: t.TempDir(), Target: "/"}} }},
		{name: "workspace mount overlap", mutate: func(s *sandbox.Spec) { s.Mounts = []sandbox.Mount{{Source: t.TempDir(), Target: "/workspace/state"}} }},
		{name: "host network", mutate: func(s *sandbox.Spec) { s.Network.Mode = "host" }},
		{name: "invalid env", mutate: func(s *sandbox.Spec) { s.Environment["BAD=NAME"] = "value" }},
		{name: "incomplete gateway", mutate: func(s *sandbox.Spec) { s.Gateway.Network = "tcp" }},
		{name: "invalid security", mutate: func(s *sandbox.Spec) { s.SecurityLevel = connection.SecurityBrokeredEnforced }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := validSpec(t)
			tt.mutate(&spec)
			if err := spec.Validate(); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
}

func validSpec(t *testing.T) sandbox.Spec {
	t.Helper()
	return sandbox.Spec{
		Image:            "example:test",
		Command:          []string{"test-command"},
		WorkingDirectory: "/workspace",
		Environment:      map[string]string{"PLAIN": "value"},
		Workspace: sandbox.WorkspaceMount{
			Source: t.TempDir(),
			Target: "/workspace",
		},
		Resources:     sandbox.ResourceLimits{PIDs: 256, MemoryBytes: 512 << 20, CPUs: 1},
		Network:       sandbox.NetworkAttachment{Mode: sandbox.NetworkBridge},
		SecurityLevel: connection.SecurityBrokered,
		Stdout:        io.Discard,
		Stderr:        io.Discard,
	}
}

type fakeRuntime struct {
	events    *eventLog
	instance  *fakeSandbox
	checkErr  error
	createErr error
}

func (*fakeRuntime) Name() string { return "fake" }

func (r *fakeRuntime) Check(context.Context) error {
	r.events.add("check")
	return r.checkErr
}

func (r *fakeRuntime) Create(context.Context, sandbox.Spec) (sandbox.Sandbox, error) {
	r.events.add("create")
	return r.instance, r.createErr
}

type fakeSandbox struct {
	id         string
	events     *eventLog
	exit       sandbox.ExitResult
	startErr   error
	waitErr    error
	stopErr    error
	removeErr  error
	waitUntil  chan struct{}
	stopOnce   sync.Once
	published  []sandbox.PublishedPort
	publishErr error
}

func (s *fakeSandbox) ID() string { return s.id }

func (s *fakeSandbox) Start(context.Context) error {
	s.events.add("start")
	return s.startErr
}

func (s *fakeSandbox) PublishedPorts(context.Context) ([]sandbox.PublishedPort, error) {
	s.events.add("ports")
	return append([]sandbox.PublishedPort(nil), s.published...), s.publishErr
}

func (s *fakeSandbox) Wait(ctx context.Context) (sandbox.ExitResult, error) {
	if s.waitUntil != nil {
		select {
		case <-s.waitUntil:
		case <-ctx.Done():
			return sandbox.ExitResult{}, ctx.Err()
		}
	}
	s.events.add("wait")
	return s.exit, s.waitErr
}

func (s *fakeSandbox) Stop(context.Context) error {
	s.events.add("stop")
	s.stopOnce.Do(func() {
		if s.waitUntil != nil {
			close(s.waitUntil)
		}
	})
	return s.stopErr
}

func (s *fakeSandbox) Remove(context.Context) error {
	s.events.add("remove")
	return s.removeErr
}

type fakeResource struct {
	events *eventLog
	err    error
}

func (r *fakeResource) Close(context.Context) error {
	r.events.add("resource-close")
	return r.err
}

type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *eventLog) add(event string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
}

func (l *eventLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

func wantEvents(t *testing.T, log *eventLog, want ...string) {
	t.Helper()
	got := strings.Join(log.snapshot(), ",")
	if got != strings.Join(want, ",") {
		t.Fatalf("events = %q, want %q", got, strings.Join(want, ","))
	}
}
