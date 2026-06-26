package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const captureEnv = "ENVVAULT_FAKE_BROWSER_CAPTURE"

type runInput struct {
	Args      []string
	Environ   []string
	Now       func() time.Time
	Stdout    io.Writer
	Stderr    io.Writer
	ProcessID int
}

type launchRecord struct {
	URL      string `json:"url"`
	OpenedAt string `json:"opened_at"`
	PID      int    `json:"pid"`
}

func main() {
	os.Exit(run(runInput{
		Args:      os.Args[1:],
		Environ:   os.Environ(),
		Now:       time.Now,
		Stdout:    os.Stdout,
		Stderr:    os.Stderr,
		ProcessID: os.Getpid(),
	}))
}

func run(input runInput) int {
	stdout := input.Stdout
	if stdout == nil {
		stdout = io.Discard
	}
	stderr := input.Stderr
	if stderr == nil {
		stderr = io.Discard
	}
	if len(input.Args) != 1 || strings.TrimSpace(input.Args[0]) == "" {
		fmt.Fprintln(stderr, "fake-browser: usage: fake-browser <launch-url>")
		return 2
	}
	capturePath := environToMap(input.Environ)[captureEnv]
	if strings.TrimSpace(capturePath) == "" {
		fmt.Fprintf(stderr, "fake-browser: %s is required\n", captureEnv)
		return 2
	}
	now := input.Now
	if now == nil {
		now = time.Now
	}
	record := launchRecord{
		URL:      input.Args[0],
		OpenedAt: now().UTC().Format(time.RFC3339),
		PID:      input.ProcessID,
	}
	if err := appendRecord(capturePath, record); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, "captured")
	return 0
}

func appendRecord(path string, record launchRecord) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("fake-browser: create capture directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("fake-browser: open capture file: %w", err)
	}
	defer file.Close()
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("fake-browser: set capture permissions: %w", err)
	}
	encoder := json.NewEncoder(file)
	if err := encoder.Encode(record); err != nil {
		return fmt.Errorf("fake-browser: write capture record: %w", err)
	}
	return nil
}

func environToMap(environ []string) map[string]string {
	env := make(map[string]string, len(environ))
	for _, item := range environ {
		key, value, ok := strings.Cut(item, "=")
		if !ok || key == "" {
			continue
		}
		env[key] = value
	}
	return env
}
