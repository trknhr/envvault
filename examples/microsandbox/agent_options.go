package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type agentOptions struct {
	mode, workspace string
	args            []string
}

func parseAgentOptions(args []string) (agentOptions, error) {
	if len(args) == 0 {
		return agentOptions{}, errors.New("an agent mode is required")
	}
	options := agentOptions{mode: args[0]}
	switch options.mode {
	case "codex", "login", "shell", "agent-setup", "agent-check", "rules", "agent-serve":
	default:
		return agentOptions{}, errors.New("use [codex|login|shell|agent-setup|agent-check|rules]")
	}
	var err error
	options.workspace, err = os.Getwd()
	if err != nil {
		return agentOptions{}, errors.New("current workspace is unavailable")
	}
	args = args[1:]
	for len(args) > 0 {
		if args[0] == "--" {
			args = args[1:]
			break
		}
		if args[0] == "--workspace" {
			if len(args) < 2 || args[1] == "" || strings.HasPrefix(args[1], "--") {
				return agentOptions{}, errors.New("--workspace requires a directory")
			}
			options.workspace, args = args[1], args[2:]
		} else if strings.HasPrefix(args[0], "--workspace=") {
			options.workspace, args = strings.TrimPrefix(args[0], "--workspace="), args[1:]
			if options.workspace == "" {
				return agentOptions{}, errors.New("--workspace requires a directory")
			}
		} else {
			break
		}
	}
	options.args = append([]string(nil), args...)
	options.workspace, err = filepath.Abs(options.workspace)
	if err == nil {
		options.workspace, err = filepath.EvalSymlinks(options.workspace)
	}
	if err != nil {
		return agentOptions{}, errors.New("workspace directory is unavailable")
	}
	info, err := os.Stat(options.workspace)
	if err != nil || !info.IsDir() {
		return agentOptions{}, errors.New("workspace must be a directory")
	}
	return options, nil
}
