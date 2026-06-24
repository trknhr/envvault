package lock_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/trknhr/credlease/internal/clerr"
	"github.com/trknhr/credlease/internal/lock"
)

func TestAcquireCreatesPrivateLockAndReleaseRemovesIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.lock")

	guard, err := lock.Acquire(context.Background(), lock.Options{
		Path:    path,
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("lock path is not a directory")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Fatalf("lock mode = %v, want 0700", info.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(path, "owner.json")); err != nil {
		t.Fatalf("owner.json missing: %v", err)
	}

	if err := guard.Release(); err != nil {
		t.Fatalf("Release() error = %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("lock path still exists after release: %v", err)
	}
}

func TestAcquireTimesOutWhenLockIsHeld(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.lock")
	first, err := lock.Acquire(context.Background(), lock.Options{Path: path, Timeout: time.Second})
	if err != nil {
		t.Fatalf("first Acquire() error = %v", err)
	}
	defer first.Release()

	_, err = lock.Acquire(context.Background(), lock.Options{
		Path:         path,
		Timeout:      25 * time.Millisecond,
		PollInterval: 5 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("second Acquire() error = nil, want timeout")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.LockTimeout {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.LockTimeout)
	}
}

func TestAcquireReclaimsStaleLock(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "runtime.lock")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	staleTime := now.Add(-10 * time.Minute)
	if err := os.Chtimes(path, staleTime, staleTime); err != nil {
		t.Fatalf("Chtimes() error = %v", err)
	}

	guard, err := lock.Acquire(context.Background(), lock.Options{
		Path:         path,
		Timeout:      time.Second,
		StaleAfter:   time.Minute,
		PollInterval: 5 * time.Millisecond,
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	defer guard.Release()

	if _, err := os.Stat(filepath.Join(path, "owner.json")); err != nil {
		t.Fatalf("owner.json missing after stale reclaim: %v", err)
	}
}
