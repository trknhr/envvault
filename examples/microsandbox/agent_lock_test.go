package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAgentLockIsExclusiveAndReleasedOnClose(t *testing.T) {
	filename := t.TempDir() + "/owner.lock"
	first, err := acquireAgentLock(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := acquireAgentLock(filename); !errors.Is(err, errAgentStateBusy) {
		if second != nil {
			second.Close()
		}
		t.Fatal("concurrent lifecycle owner was permitted")
	} else if !strings.Contains(err.Error(), fmt.Sprintf("PID %d", os.Getpid())) {
		t.Fatal("missing owner identity")
	}
	first.Close()
	second, err := acquireAgentLock(filename)
	if err != nil {
		t.Fatalf("released lock file prevented restart: %v", err)
	}
	second.Close()
}

func TestHostPreparationLockWaitIsCancellableAndReleases(t *testing.T) {
	dir := t.TempDir()
	first, err := acquireAgentSetup(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if lock, err := acquireAgentSetup(ctx, dir); !errors.Is(err, context.DeadlineExceeded) {
		if lock != nil {
			lock.Close()
		}
		t.Fatalf("waiting setup did not cancel: %v", err)
	}
	first.Close()
	next, err := acquireAgentSetup(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	next.Close()
}
