package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var errAgentStateBusy = errors.New("sandbox state is in use")

func acquireAgentLock(path string) (*os.File, error) {
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		defer lock.Close()
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("lock project sandbox state: %w", err)
		}
		owner := ""
		data, _ := io.ReadAll(io.LimitReader(lock, 32))
		if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 0 {
			owner = fmt.Sprintf(" (launcher PID %d)", pid)
		}
		return nil, fmt.Errorf("%w%s", errAgentStateBusy, owner)
	}
	if err := lock.Truncate(0); err != nil {
		lock.Close()
		return nil, err
	}
	if _, err := fmt.Fprintf(lock, "%d\n", os.Getpid()); err != nil {
		lock.Close()
		return nil, err
	}
	return lock, nil
}

// Serialize only host runtime/image preparation, not the lifetime of a VM.
func acquireAgentSetup(ctx context.Context, stateDir string) (*os.File, error) {
	return waitAgentLock(ctx, filepath.Join(stateDir, "agent-setup.lock"))
}

func waitAgentLock(ctx context.Context, path string) (*os.File, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		lock, err := acquireAgentLock(path)
		if !errors.Is(err, errAgentStateBusy) {
			return lock, err
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
