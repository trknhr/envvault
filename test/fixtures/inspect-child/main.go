package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const inspectPortsEnv = "ENVVAULT_INSPECT_PORTS"

type inspectInput struct {
	Args      []string
	Environ   []string
	Ports     []string
	Now       func() time.Time
	PID       int
	PPID      int
	CheckPort func(address string) (bool, string)
}

type snapshot struct {
	Args      []string              `json:"args"`
	Env       map[string]string     `json:"env"`
	PID       int                   `json:"pid"`
	PPID      int                   `json:"ppid"`
	StartedAt string                `json:"started_at"`
	Ports     map[string]portStatus `json:"ports"`
}

type portStatus struct {
	Reachable bool   `json:"reachable"`
	Error     string `json:"error,omitempty"`
}

func main() {
	result := buildSnapshot(inspectInput{
		Args:      os.Args[1:],
		Environ:   os.Environ(),
		Ports:     parsePorts(os.Getenv(inspectPortsEnv)),
		Now:       time.Now,
		PID:       os.Getpid(),
		PPID:      os.Getppid(),
		CheckPort: checkTCPPort,
	})
	encoder := json.NewEncoder(os.Stdout)
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func buildSnapshot(input inspectInput) snapshot {
	now := input.Now
	if now == nil {
		now = time.Now
	}
	checkPort := input.CheckPort
	if checkPort == nil {
		checkPort = checkTCPPort
	}

	ports := make(map[string]portStatus, len(input.Ports))
	for _, address := range input.Ports {
		address = strings.TrimSpace(address)
		if address == "" {
			continue
		}
		reachable, errText := checkPort(address)
		ports[address] = portStatus{
			Reachable: reachable,
			Error:     errText,
		}
	}

	return snapshot{
		Args:      append([]string(nil), input.Args...),
		Env:       environToMap(input.Environ),
		PID:       input.PID,
		PPID:      input.PPID,
		StartedAt: now().UTC().Format(time.RFC3339Nano),
		Ports:     ports,
	}
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

func parsePorts(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func checkTCPPort(address string) (bool, string) {
	conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
	if err != nil {
		return false, err.Error()
	}
	_ = conn.Close()
	return true, ""
}
