package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	m "github.com/superradcompany/microsandbox/sdk/go"
)

const agentEntrypoint = "/usr/local/bin/envvault-agent-exec"
const agentPIDsPath = "/sys/fs/cgroup/envvault-agent/pids.max"

// Host management remains outside this cgroup, including when it is full.
// The agent cannot write its root-owned cgroup or regain privileges.
type agentProcessController struct {
	cancel context.CancelFunc
	done   chan struct{}
	err    error // read only after done closes
}

func startAgentProcessController(ctx context.Context, sb *m.Sandbox, filename string, fail context.CancelFunc) (*agentProcessController, error) {
	if _, err := checkedRootShell(ctx, sb, "printf +pids > /sys/fs/cgroup/cgroup.subtree_control && mkdir -p /sys/fs/cgroup/envvault-agent && test -f "+agentPIDsPath); err != nil {
		return nil, fmt.Errorf("kernel process controller unavailable: %w", err)
	}
	policy, err := readAgentPolicy(filename)
	if err != nil {
		return nil, err
	}
	if err := setAgentProcessLimit(ctx, sb, policy.MaxProcesses); err != nil {
		return nil, err
	}
	watchCtx, cancel := context.WithCancel(ctx)
	c := &agentProcessController{cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(c.done)
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		current := policy.MaxProcesses
		for {
			select {
			case <-watchCtx.Done():
				return
			case <-ticker.C:
				policy, err := readAgentPolicy(filename)
				limit := policy.MaxProcesses
				if err != nil {
					limit = 0 // Invalid policy stops new forks; valid JSON recovers.
				}
				if limit == current {
					continue
				}
				updateCtx, stop := context.WithTimeout(watchCtx, 5*time.Second)
				err = setAgentProcessLimit(updateCtx, sb, limit)
				stop()
				if err != nil {
					if watchCtx.Err() == nil {
						c.err = errors.New("live process limit could not be enforced; session stopped")
						fail()
					}
					return
				}
				current = limit
			}
		}
	}()
	return c, nil
}

func setAgentProcessLimit(ctx context.Context, sb *m.Sandbox, count int) error {
	value := strconv.Itoa(count)
	if err := sb.FS().WriteString(ctx, agentPIDsPath, value); err != nil {
		return errors.New("write kernel process limit failed")
	}
	actual, err := sb.FS().ReadString(ctx, agentPIDsPath)
	if err != nil || strings.TrimSpace(actual) != value {
		return errors.New("kernel process limit verification failed")
	}
	return nil
}

func (c *agentProcessController) Close() error {
	c.cancel()
	<-c.done
	return c.err
}

func startAgentCatalogController(ctx context.Context, sb *m.Sandbox, proxy *agentProxy, fail context.CancelFunc) (*agentProcessController, error) {
	watchCtx, cancel := context.WithCancel(ctx)
	c := &agentProcessController{cancel: cancel, done: make(chan struct{})}
	var current []byte
	update := func() error {
		policy, err := proxy.policy()
		data := policy.credentialCatalog()
		if err != nil {
			data = []byte("{\"references\":[],\"routes\":[],\"error\":\"host policy unavailable\"}\n")
		}
		if bytes.Equal(current, data) {
			return nil
		}
		updateCtx, stop := context.WithTimeout(watchCtx, 5*time.Second)
		defer stop()
		if err := sb.FS().Write(updateCtx, agentCatalogPath+".new", data); err != nil {
			return errors.New("credential catalog update failed")
		}
		if err := sb.FS().Rename(updateCtx, agentCatalogPath+".new", agentCatalogPath); err != nil {
			return errors.New("credential catalog replacement failed")
		}
		current = data
		return nil
	}
	if err := update(); err != nil {
		cancel()
		return nil, err
	}
	go func() {
		defer close(c.done)
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-watchCtx.Done():
				return
			case <-ticker.C:
				if err := update(); err != nil {
					if watchCtx.Err() == nil {
						c.err = err
						fail()
					}
					return
				}
			}
		}
	}()
	return c, nil
}

func checkedRootShell(ctx context.Context, sb *m.Sandbox, command string) (string, error) {
	out, err := sb.Shell(ctx, command, m.WithExecTimeout(90*time.Second))
	if err != nil {
		return "", err
	}
	if out.ExitCode() != 0 {
		return "", fmt.Errorf("host bootstrap failed with code %d (output withheld)", out.ExitCode())
	}
	return strings.TrimSpace(out.Stdout()), nil
}
