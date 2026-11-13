package microsandbox

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Project identifies the exact mounted directory. Symlink aliases share state;
// other directories, including other Git worktrees, have distinct state.
type Project struct {
	Workspace string `json:"workspace"`
	ID        string `json:"id"`
}

func ProjectForWorkspace(workspace string) (Project, error) {
	canonical, err := filepath.Abs(workspace)
	if err == nil {
		canonical, err = filepath.EvalSymlinks(canonical)
	}
	if err != nil {
		return Project{}, errors.New("workspace directory is unavailable")
	}
	info, err := os.Stat(canonical)
	if err != nil || !info.IsDir() {
		return Project{}, errors.New("workspace must be a directory")
	}
	digest := sha256.Sum256([]byte("envvault-project-v1\x00" + canonical))
	return Project{Workspace: canonical, ID: fmt.Sprintf("%x", digest[:16])}, nil
}

func (p Project) Volume() string  { return "envvault-project-home-" + p.ID }
func (p Project) Sandbox() string { return "envvault-project-" + p.ID }
