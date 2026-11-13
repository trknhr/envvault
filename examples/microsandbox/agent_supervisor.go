package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

const agentSupervisorProtocol = 1
const agentIdleGrace = 2 * time.Second

type agentSession struct {
	Protocol    int               `json:"protocol"`
	Workspace   string            `json:"workspace"`
	Helper      string            `json:"helper"`
	Sandbox     string            `json:"sandbox,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	Error       string            `json:"error,omitempty"`
}

type agentSupervisorBackend interface {
	descriptor(workspace, digest string) agentSession
	Done() <-chan struct{}
	Close(context.Context) error
}

type agentLease struct {
	session agentSession
	ctx     context.Context
	cancel  context.CancelFunc
	conn    net.Conn
}

func (l *agentLease) Close() {
	l.cancel()
	l.conn.Close()
}

func agentHelperDigest() (string, error) {
	filename, err := os.Executable()
	if err != nil {
		return "", err
	}
	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func connectAgentLease(ctx context.Context, p agentProject, digest string) (*agentLease, error) {
	startup, stop := context.WithTimeout(ctx, 10*time.Minute)
	defer stop()
	spawned := false
	for {
		if err := startup.Err(); err != nil {
			return nil, err
		}
		conn, err := (&net.Dialer{Timeout: 300 * time.Millisecond}).DialContext(startup, "unix", p.socket())
		if err == nil {
			leaseCtx, cancel := context.WithCancel(ctx)
			closeOnCancel := context.AfterFunc(leaseCtx, func() { conn.Close() })
			_ = conn.SetDeadline(time.Now().Add(10 * time.Minute))
			err = json.NewEncoder(conn).Encode(agentSession{Protocol: agentSupervisorProtocol, Workspace: p.Workspace, Helper: digest})
			var session agentSession
			if err == nil {
				err = json.NewDecoder(io.LimitReader(conn, 1<<20)).Decode(&session)
			}
			if err == nil && session.Error != "" {
				err = errors.New(session.Error)
			}
			if err == nil && (session.Protocol != agentSupervisorProtocol || session.Workspace != p.Workspace || session.Helper != digest || session.Sandbox != p.Sandbox()) {
				err = errors.New("project supervisor identity mismatch")
			}
			if err != nil {
				cancel()
				closeOnCancel()
				conn.Close()
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				// An idle supervisor may have begun shutdown just as this client
				// connected. Wait for its owner lock, then boot the same project.
				if !spawned && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
					continue
				}
				return nil, fmt.Errorf("connect project sandbox: %w (private log: %s)", err, p.logPath())
			}
			_ = conn.SetDeadline(time.Time{})
			lease := &agentLease{session: session, ctx: leaseCtx, cancel: cancel, conn: conn}
			go func() {
				var one [1]byte
				_, _ = conn.Read(one[:])
				cancel() // Loss of supervision cancels this terminal's guest exec.
				closeOnCancel()
			}()
			return lease, nil
		}
		lock, lockErr := acquireAgentLock(p.ownerLock())
		if lockErr == nil {
			if spawned {
				lock.Close()
				return nil, fmt.Errorf("project sandbox could not start; inspect its private log: %s", p.logPath())
			}
			err = spawnAgentSupervisor(p, lock)
			lock.Close() // The child holds the inherited flock until cleanup ends.
			if err != nil {
				return nil, err
			}
			spawned = true
			fmt.Println("Starting Codex sandbox...")
		} else if !errors.Is(lockErr, errAgentStateBusy) {
			return nil, lockErr
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-startup.Done():
			timer.Stop()
			return nil, startup.Err()
		case <-timer.C:
		}
	}
}

func spawnAgentSupervisor(p agentProject, lock *os.File) error {
	filename, err := os.Executable()
	if err != nil {
		return err
	}
	log, err := os.OpenFile(p.logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer log.Close()
	cmd := exec.Command(filename, "agent-serve", "--workspace", p.Workspace)
	cmd.Dir, cmd.Env = p.Workspace, os.Environ()
	cmd.Stdout, cmd.Stderr = log, log
	cmd.ExtraFiles = []*os.File{lock}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

func inheritedAgentLock(p agentProject) (*os.File, error) {
	lock := os.NewFile(3, "project supervisor lock")
	if lock == nil {
		return nil, errors.New("supervisor requires its launcher's lock")
	}
	actual, err := lock.Stat()
	expected, pathErr := os.Lstat(p.ownerLock())
	if err != nil || pathErr != nil || !expected.Mode().IsRegular() || !os.SameFile(actual, expected) {
		lock.Close()
		return nil, errors.New("supervisor received an invalid launcher lock")
	}
	syscall.CloseOnExec(3) // Native runtime subprocesses must not inherit ownership.
	if err := syscall.Flock(3, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, err
	}
	if err := lock.Truncate(0); err != nil {
		lock.Close()
		return nil, err
	}
	if _, err := lock.WriteAt([]byte(fmt.Sprintf("%d\n", os.Getpid())), 0); err != nil {
		lock.Close()
		return nil, err
	}
	return lock, nil
}

// The supervisor owns runtime/proxy/controller lifetimes. Client connections are
// leases, including while booting; EOF releases only that client's lease.
func serveAgentProject(parent context.Context, p agentProject, digest string, lock *os.File, boot func(context.Context) (agentSupervisorBackend, error), idleGrace time.Duration) (resultErr error) {
	defer lock.Close()
	if err := os.Remove(p.socket()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: p.socket(), Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chmod(p.socket(), 0600); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	ready := make(chan struct{})
	var backend agentSupervisorBackend
	var bootErr error
	bootTimer := time.AfterFunc(9*time.Minute, cancel)
	defer bootTimer.Stop()
	go func() {
		backend, bootErr = boot(ctx)
		close(ready)
	}()
	accepted := make(chan net.Conn)
	acceptErr := make(chan error, 1)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				acceptErr <- err
				return
			}
			select {
			case accepted <- conn:
			case <-ctx.Done():
				conn.Close()
				return
			}
		}
	}()
	clients := make(map[net.Conn]struct{})
	released := make(chan net.Conn)
	var handlers sync.WaitGroup
	defer func() {
		cancel()
		listener.Close()
		for conn := range clients {
			conn.Close()
		}
		handlers.Wait()
		<-ready
		if backend != nil {
			cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
			defer stop()
			resultErr = errors.Join(resultErr, backend.Close(cleanup))
		}
	}()
	idle := time.NewTimer(idleGrace)
	defer idle.Stop()
	bootDone := (<-chan struct{})(ready)
	var backendDone <-chan struct{}
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-acceptErr:
			return err
		case <-bootDone:
			bootTimer.Stop()
			bootDone = nil
			if bootErr != nil {
				return bootErr
			}
			backendDone = backend.Done()
		case <-backendDone:
			return errors.New("project sandbox policy supervision stopped")
		case conn := <-accepted:
			clients[conn] = struct{}{}
			idle.Stop()
			handlers.Go(func() {
				defer conn.Close()
				defer func() {
					select {
					case released <- conn:
					case <-ctx.Done():
					}
				}()
				handleAgentLease(ctx, conn, p, digest, ready, func() (agentSession, error) {
					if bootErr != nil {
						return agentSession{}, bootErr
					}
					return backend.descriptor(p.Workspace, digest), nil
				})
			})
		case conn := <-released:
			delete(clients, conn)
			if len(clients) == 0 {
				idle.Reset(idleGrace)
			}
		case <-idle.C:
			if len(clients) == 0 {
				return nil
			}
		}
	}
}

func handleAgentLease(ctx context.Context, conn net.Conn, p agentProject, digest string, ready <-chan struct{}, descriptor func() (agentSession, error)) {
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var request agentSession
	if err := json.NewDecoder(io.LimitReader(conn, 16<<10)).Decode(&request); err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	if request.Protocol != agentSupervisorProtocol || request.Workspace != p.Workspace || request.Helper != digest {
		_ = json.NewEncoder(conn).Encode(agentSession{Error: "project sandbox belongs to another workspace or EnvVault build; close its existing terminals and retry"})
		return
	}
	lost := make(chan struct{})
	go func() {
		var one [1]byte
		_, _ = conn.Read(one[:])
		close(lost)
	}()
	defer func() { conn.Close(); <-lost }()
	select {
	case <-ctx.Done():
		return
	case <-lost:
		return
	case <-ready:
	}
	session, err := descriptor()
	if err != nil {
		session = agentSession{Error: agentLogError(err)}
	}
	if err := json.NewEncoder(conn).Encode(session); err != nil {
		return
	}
	select {
	case <-ctx.Done():
	case <-lost:
	}
}
