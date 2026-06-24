package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

const (
	readyEnv   = "CREDLEASE_WAIT_SIGNAL_READY"
	captureEnv = "CREDLEASE_WAIT_SIGNAL_CAPTURE"
)

type signalRecord struct {
	Signal string `json:"signal"`
	PID    int    `json:"pid"`
}

func main() {
	os.Exit(run())
}

func run() int {
	readyPath := os.Getenv(readyEnv)
	capturePath := os.Getenv(captureEnv)
	if readyPath == "" || capturePath == "" {
		fmt.Fprintf(os.Stderr, "wait-signal: %s and %s are required\n", readyEnv, captureEnv)
		return 2
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	if err := writeFile(readyPath, []byte("ready\n")); err != nil {
		fmt.Fprintf(os.Stderr, "wait-signal: write ready marker: %v\n", err)
		return 1
	}
	received := <-signals
	name, code := signalNameAndExitCode(received)
	record := signalRecord{Signal: name, PID: os.Getpid()}
	raw, err := json.Marshal(record)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wait-signal: marshal signal record: %v\n", err)
		return 1
	}
	raw = append(raw, '\n')
	if err := writeFile(capturePath, raw); err != nil {
		fmt.Fprintf(os.Stderr, "wait-signal: write signal record: %v\n", err)
		return 1
	}
	return code
}

func signalNameAndExitCode(sig os.Signal) (string, int) {
	switch sig {
	case os.Interrupt:
		return "interrupt", 130
	case syscall.SIGTERM:
		return "terminated", 143
	default:
		return sig.String(), 128
	}
}

func writeFile(path string, body []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o600)
}
