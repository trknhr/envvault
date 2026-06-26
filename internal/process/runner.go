package process

import (
	"context"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"syscall"

	"github.com/trknhr/envvault/internal/clerr"
)

type Runner struct{}

type RunInput struct {
	Command []string
	Env     map[string]string
	Signals <-chan os.Signal
	Stdout  io.Writer
	Stderr  io.Writer
}

func (Runner) Run(ctx context.Context, input RunInput) (int, error) {
	if len(input.Command) == 0 || input.Command[0] == "" {
		return 0, clerr.New(clerr.ConfigInvalid, "child command is required")
	}

	cmd := exec.CommandContext(ctx, input.Command[0], input.Command[1:]...)
	cmd.Env = Environ(input.Env)
	cmd.Stdout = input.Stdout
	cmd.Stderr = input.Stderr

	if err := cmd.Start(); err != nil {
		return 0, clerr.Wrap(clerr.RuntimeUnavailable, "start child process", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	stopForwarding := forwardSignals(cmd.Process, input.Signals)
	defer stopForwarding()

	select {
	case err := <-done:
		return exitCode(err)
	case <-ctx.Done():
		_ = cmd.Process.Signal(os.Interrupt)
		err := <-done
		if err != nil {
			return exitCode(err)
		}
		return 0, ctx.Err()
	}
}

func Environ(env map[string]string) []string {
	out := make([]string, 0, len(env))
	for key, value := range env {
		out = append(out, key+"="+value)
	}
	sort.Strings(out)
	return out
}

func exitCode(err error) (int, error) {
	if err == nil {
		return 0, nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode(), nil
	}
	return 0, clerr.Wrap(clerr.RuntimeUnavailable, "wait for child process", err)
}

func forwardSignals(process *os.Process, signals <-chan os.Signal) func() {
	if signals == nil {
		return func() {}
	}
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case sig, ok := <-signals:
				if !ok {
					return
				}
				if sig != nil {
					_ = process.Signal(sig)
				}
			case <-stop:
				return
			}
		}
	}()
	return func() { close(stop) }
}

func NotifyInterrupt(ch chan<- os.Signal) {
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
}
