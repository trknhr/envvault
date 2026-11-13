package main

import (
	"embed"
	"errors"
	"os"
	"path/filepath"
)

// Installed launchers never load host code, policy defaults, or image build
// files from the directory shared with the guest.
//
//go:embed Dockerfile agent-entrypoint git-credential-envvault agent-policy.json .dockerignore MICROSANDBOX_LICENSE
var agentAssets embed.FS

func agentBuildContext() (string, func(), error) {
	dir, err := os.MkdirTemp("", "envvault-msb-image-")
	if err != nil {
		return "", nil, errors.New("private image build directory unavailable")
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	for _, name := range []string{"Dockerfile", "agent-entrypoint", "git-credential-envvault", ".dockerignore"} {
		data, err := agentAssets.ReadFile(name)
		if err == nil {
			err = os.WriteFile(filepath.Join(dir, name), data, 0600)
		}
		if err != nil {
			cleanup()
			return "", nil, errors.New("embedded image build files unavailable")
		}
	}
	return dir, cleanup, nil
}
