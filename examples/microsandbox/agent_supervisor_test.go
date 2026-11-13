package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fixtureAgentBackend struct {
	project agentProject
	failed  chan struct{}
	closed  atomic.Int32
}

func (b *fixtureAgentBackend) descriptor(workspace, digest string) agentSession {
	return agentSession{Protocol: agentSupervisorProtocol, Workspace: workspace, Helper: digest, Sandbox: b.project.Sandbox(), Environment: map[string]string{"CODEX_HOME": "/home/agent/.codex"}}
}
func (b *fixtureAgentBackend) Done() <-chan struct{}       { return b.failed }
func (b *fixtureAgentBackend) Close(context.Context) error { b.closed.Add(1); return nil }

type fixtureAgentServer struct {
	project agentProject
	backend *fixtureAgentBackend
	cancel  context.CancelFunc
	done    chan struct{}
	err     error
}

func shortAgentState(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ev-supervisor-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func startFixtureAgentServer(t *testing.T, boot func(context.Context, *fixtureAgentBackend) (agentSupervisorBackend, error)) *fixtureAgentServer {
	t.Helper()
	p, err := newAgentProject(shortAgentState(t), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	owner, err := acquireAgentLock(p.ownerLock())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	s := &fixtureAgentServer{project: p, backend: &fixtureAgentBackend{project: p, failed: make(chan struct{})}, cancel: cancel, done: make(chan struct{})}
	go func() {
		s.err = serveAgentProject(ctx, p, "fixture-build", owner, func(ctx context.Context) (agentSupervisorBackend, error) {
			if boot != nil {
				return boot(ctx, s.backend)
			}
			return s.backend, nil
		}, 100*time.Millisecond)
		close(s.done)
	}()
	t.Cleanup(func() { cancel(); waitFixtureAgentServer(t, s) })
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(p.socket()); err == nil {
			break
		}
		select {
		case <-s.done:
			t.Fatalf("supervisor exited before listening: %v", s.err)
		case <-time.After(time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("supervisor did not listen")
		}
	}
	return s
}

func waitFixtureAgentServer(t *testing.T, s *fixtureAgentServer) {
	t.Helper()
	select {
	case <-s.done:
	case <-time.After(3 * time.Second):
		t.Fatal("supervisor did not finish cleanup")
	}
}

func fixtureAgentLease(t *testing.T, s *fixtureAgentServer, ctx context.Context) *agentLease {
	t.Helper()
	l, err := connectAgentLease(ctx, s.project, "fixture-build")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Close)
	return l
}

func TestSupervisorKeepsOtherTerminalsAliveAndClosesAfterLastLease(t *testing.T) {
	s := startFixtureAgentServer(t, nil)
	firstCtx, stopFirst := context.WithCancel(t.Context())
	defer stopFirst()
	first := fixtureAgentLease(t, s, firstCtx)
	second := fixtureAgentLease(t, s, t.Context())
	if first.session.Sandbox != second.session.Sandbox {
		t.Fatal("parallel terminals received different history storage")
	}
	stopFirst()
	select {
	case <-first.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("cancelled terminal retained its lease")
	}
	select {
	case <-second.ctx.Done():
		t.Fatal("closing one terminal stopped the other")
	case <-s.done:
		t.Fatal("supervisor stopped with a live terminal")
	case <-time.After(250 * time.Millisecond):
	}
	if s.backend.closed.Load() != 0 {
		t.Fatal("live backend was destroyed")
	}
	info, err := os.Stat(s.project.socket())
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("control socket is not private")
	}
	second.Close()
	waitFixtureAgentServer(t, s)
	if s.backend.closed.Load() != 1 {
		t.Fatal("backend cleanup did not happen exactly once")
	}
}

func TestConcurrentClientsWaitForOneColdProjectBoot(t *testing.T) {
	gate := make(chan struct{})
	var boots atomic.Int32
	s := startFixtureAgentServer(t, func(ctx context.Context, b *fixtureAgentBackend) (agentSupervisorBackend, error) {
		boots.Add(1)
		select {
		case <-gate:
			return b, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	const count = 8
	leases := make(chan *agentLease, count)
	errorsFound := make(chan error, count)
	var workers sync.WaitGroup
	for i := 0; i < count; i++ {
		workers.Go(func() {
			l, err := connectAgentLease(t.Context(), s.project, "fixture-build")
			if err != nil {
				errorsFound <- err
				return
			}
			leases <- l
		})
	}
	close(gate)
	workers.Wait()
	close(leases)
	close(errorsFound)
	for err := range errorsFound {
		t.Error(err)
	}
	seen := 0
	for l := range leases {
		t.Cleanup(l.Close)
		if l.session.Sandbox != s.project.Sandbox() || l.session.Environment["CODEX_HOME"] != "/home/agent/.codex" {
			t.Error("client did not attach to project history")
		}
		seen++
		l.Close()
	}
	if seen != count || boots.Load() != 1 {
		t.Fatal("cold parallel launches did not share exactly one boot")
	}
	waitFixtureAgentServer(t, s)
}

func TestSupervisorRejectsForeignWorkspaceAndBuildBeforeDisclosingSession(t *testing.T) {
	s := startFixtureAgentServer(t, nil)
	keepAlive := fixtureAgentLease(t, s, t.Context())
	defer keepAlive.Close()
	for _, request := range []agentSession{
		{Protocol: agentSupervisorProtocol, Workspace: "/different/workspace", Helper: "fixture-build"},
		{Protocol: agentSupervisorProtocol, Workspace: s.project.Workspace, Helper: "outdated-build"},
	} {
		conn, err := net.Dial("unix", s.project.socket())
		if err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(conn).Encode(request); err != nil {
			t.Fatal(err)
		}
		var response agentSession
		if err := json.NewDecoder(conn).Decode(&response); err != nil {
			t.Fatal(err)
		}
		conn.Close()
		if response.Error == "" || response.Sandbox != "" || response.Environment != nil {
			t.Fatal("foreign client received project state")
		}
	}
	if keepAlive.ctx.Err() != nil {
		t.Fatal("rejected client interrupted an existing terminal")
	}
}

func TestLossOfPolicySupervisionCancelsAllTerminalLeases(t *testing.T) {
	s := startFixtureAgentServer(t, nil)
	first, second := fixtureAgentLease(t, s, t.Context()), fixtureAgentLease(t, s, t.Context())
	close(s.backend.failed)
	for _, l := range []*agentLease{first, second} {
		select {
		case <-l.ctx.Done():
		case <-time.After(time.Second):
			t.Fatal("unsupervised terminal kept running")
		}
	}
	waitFixtureAgentServer(t, s)
	if s.backend.closed.Load() != 1 || s.err == nil {
		t.Fatal("failed supervision did not destroy its backend")
	}
}

func TestCancelledColdStartReleasesLeaseAndCancelsUnneededBoot(t *testing.T) {
	s := startFixtureAgentServer(t, func(ctx context.Context, b *fixtureAgentBackend) (agentSupervisorBackend, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		l, err := connectAgentLease(ctx, s.project, "fixture-build")
		if l != nil {
			l.Close()
		}
		result <- err
	}()
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled startup succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("startup ignored cancellation")
	}
	waitFixtureAgentServer(t, s)
}

func TestStartupBackendErrorsStayOutOfTerminalProtocol(t *testing.T) {
	p, err := newAgentProject(shortAgentState(t), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server, client := net.Pipe()
	defer client.Close()
	ready := make(chan struct{})
	close(ready)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		handleAgentLease(t.Context(), server, p, "fixture-build", ready, func() (agentSession, error) { return agentSession{}, errors.New("fixture-private-diagnostic") })
	}()
	if err := json.NewEncoder(client).Encode(agentSession{Protocol: agentSupervisorProtocol, Workspace: p.Workspace, Helper: "fixture-build"}); err != nil {
		t.Fatal(err)
	}
	var response agentSession
	if err := json.NewDecoder(client).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Error == "" || strings.Contains(response.Error, "fixture-private-diagnostic") || response.Environment != nil {
		t.Fatal("native diagnostics leaked through the control protocol")
	}
	client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failed handshake did not release its handler")
	}
}
