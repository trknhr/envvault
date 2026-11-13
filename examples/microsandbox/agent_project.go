package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	managedmsb "github.com/trknhr/envvault/internal/runtime/microsandbox"
)

type agentProject struct {
	managedmsb.Project
	dir string
}

func newAgentProject(stateDir, workspace string) (agentProject, error) {
	identity, err := managedmsb.ProjectForWorkspace(workspace)
	if err != nil {
		return agentProject{}, err
	}
	project := agentProject{Project: identity, dir: filepath.Join(stateDir, "p", identity.ID)}
	if err := protectAgentVaultPath(project.dir, identity.Workspace); err != nil {
		return agentProject{}, err
	}
	for _, dir := range []string{filepath.Join(stateDir, "p"), project.dir} {
		if err := privateProjectDirectory(dir); err != nil {
			return agentProject{}, err
		}
	}
	if err := project.ensureIdentity(); err != nil {
		return agentProject{}, err
	}
	return project, nil
}

func privateProjectDirectory(dir string) error {
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("project state must be a private directory without symlinks")
	}
	return os.Chmod(dir, 0700)
}

// Publish complete metadata with link-if-absent, so concurrent first launches
// cannot overwrite an existing workspace association or read a partial document.
func (p agentProject) ensureIdentity() error {
	filename := filepath.Join(p.dir, "project.json")
	if _, err := os.Lstat(filename); errors.Is(err, os.ErrNotExist) {
		f, err := os.CreateTemp(p.dir, ".project-")
		if err != nil {
			return err
		}
		defer os.Remove(f.Name())
		defer f.Close()
		if err := json.NewEncoder(f).Encode(p.Project); err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		if err := os.Link(f.Name(), filename); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
	}
	info, err := os.Lstat(filename)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 16<<10 || info.Mode().Perm()&0077 != 0 {
		return errors.New("invalid project identity metadata")
	}
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	var stored managedmsb.Project
	d := json.NewDecoder(io.LimitReader(f, 16<<10))
	d.DisallowUnknownFields()
	if err := d.Decode(&stored); err != nil || stored != p.Project {
		return errors.New("project state belongs to a different workspace")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("invalid project identity metadata trailer")
	}
	return nil
}

func (p agentProject) socket() string    { return filepath.Join(p.dir, "ctl") }
func (p agentProject) ownerLock() string { return filepath.Join(p.dir, "owner.lock") }
func (p agentProject) loginLock() string { return filepath.Join(p.dir, "login.lock") }
func (p agentProject) logPath() string   { return filepath.Join(p.dir, "supervisor.log") }
