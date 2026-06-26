package lock

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
)

const ownerFile = "owner.json"

type Options struct {
	Path         string
	Timeout      time.Duration
	PollInterval time.Duration
	StaleAfter   time.Duration
	Now          func() time.Time
}

type Guard struct {
	path     string
	released bool
}

type owner struct {
	PID       int       `json:"pid"`
	CreatedAt time.Time `json:"created_at"`
}

func Acquire(ctx context.Context, options Options) (*Guard, error) {
	if options.Path == "" {
		return nil, clerr.New(clerr.ConfigInvalid, "lock path is required")
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	poll := options.PollInterval
	if poll <= 0 {
		poll = 50 * time.Millisecond
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}

	deadline := now().Add(timeout)
	for {
		guard, acquired, err := tryAcquire(options.Path, now)
		if err != nil {
			return nil, err
		}
		if acquired {
			return guard, nil
		}

		if options.StaleAfter > 0 {
			reclaimed, err := reclaimStale(options.Path, now(), options.StaleAfter)
			if err != nil {
				return nil, err
			}
			if reclaimed {
				continue
			}
		}

		if !now().Before(deadline) {
			return nil, clerr.New(clerr.LockTimeout, "runtime lock timeout")
		}

		timer := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func (g *Guard) Release() error {
	if g == nil || g.released {
		return nil
	}
	g.released = true
	if err := os.RemoveAll(g.path); err != nil {
		return clerr.Wrap(clerr.CleanupFailed, "release runtime lock", err)
	}
	return nil
}

func tryAcquire(path string, now func() time.Time) (*Guard, bool, error) {
	if err := os.Mkdir(path, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, false, nil
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, false, clerr.Wrap(clerr.ConfigInvalid, "create lock parent directory", err)
		}
		if err := os.Mkdir(path, 0o700); err != nil {
			if errors.Is(err, os.ErrExist) {
				return nil, false, nil
			}
			return nil, false, clerr.Wrap(clerr.ConfigInvalid, "create runtime lock", err)
		}
	}

	if err := writeOwner(path, now()); err != nil {
		_ = os.RemoveAll(path)
		return nil, false, err
	}
	return &Guard{path: path}, true, nil
}

func writeOwner(path string, createdAt time.Time) error {
	raw, err := json.Marshal(owner{PID: os.Getpid(), CreatedAt: createdAt.UTC()})
	if err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "marshal lock owner", err)
	}
	ownerPath := filepath.Join(path, ownerFile)
	if err := os.WriteFile(ownerPath, raw, 0o600); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "write lock owner", err)
	}
	return nil
}

func reclaimStale(path string, now time.Time, staleAfter time.Duration) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, clerr.Wrap(clerr.ConfigInvalid, "inspect runtime lock", err)
	}
	if !info.IsDir() {
		return false, clerr.New(clerr.ConfigInvalid, "runtime lock path is not a directory")
	}
	if now.Sub(info.ModTime()) < staleAfter {
		return false, nil
	}
	if err := os.RemoveAll(path); err != nil {
		return false, clerr.Wrap(clerr.CleanupFailed, "reclaim stale runtime lock", err)
	}
	return true, nil
}
