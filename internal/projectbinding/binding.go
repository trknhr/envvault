package projectbinding

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/profile"
)

type Identity struct {
	Root      string
	GitRemote string
}

func Detect(ctx context.Context, start string) (Identity, error) {
	if err := ctx.Err(); err != nil {
		return Identity{}, err
	}
	root, err := cleanRoot(start)
	if err != nil {
		return Identity{}, err
	}
	gitRoot, ok, err := findGitRoot(root)
	if err != nil {
		return Identity{}, err
	}
	if !ok {
		return Identity{Root: root}, nil
	}
	remote, err := readOriginRemote(filepath.Join(gitRoot, ".git", "config"))
	if err != nil {
		return Identity{}, err
	}
	return Identity{Root: gitRoot, GitRemote: remote}, nil
}

func Approve(mode profile.ProjectBindingMode, identity Identity) (profile.ProjectBinding, error) {
	switch mode {
	case "", profile.ProjectBindingNone:
		return profile.ProjectBinding{Mode: profile.ProjectBindingNone}, nil
	case profile.ProjectBindingPathHash:
		hash, err := PathHash(identity.Root)
		if err != nil {
			return profile.ProjectBinding{}, err
		}
		return profile.ProjectBinding{
			Mode:     profile.ProjectBindingPathHash,
			PathHash: hash,
		}, nil
	case profile.ProjectBindingGitRemoteAndRoot:
		root, err := cleanRoot(identity.Root)
		if err != nil {
			return profile.ProjectBinding{}, err
		}
		remote := strings.TrimSpace(identity.GitRemote)
		if remote == "" {
			return profile.ProjectBinding{}, clerr.New(clerr.ProjectNotTrusted, "git remote is required for project approval")
		}
		return profile.ProjectBinding{
			Mode:      profile.ProjectBindingGitRemoteAndRoot,
			GitRoot:   root,
			GitRemote: remote,
		}, nil
	default:
		return profile.ProjectBinding{}, clerr.New(clerr.ConfigInvalid, "unknown project binding mode")
	}
}

func Check(binding profile.ProjectBinding, identity Identity) error {
	switch binding.Mode {
	case "", profile.ProjectBindingNone:
		return nil
	case profile.ProjectBindingPathHash:
		hash, err := PathHash(identity.Root)
		if err != nil {
			return err
		}
		if binding.PathHash == "" || binding.PathHash != hash {
			return notTrusted()
		}
		return nil
	case profile.ProjectBindingGitRemoteAndRoot:
		root, err := cleanRoot(identity.Root)
		if err != nil {
			return err
		}
		if binding.GitRoot == "" || binding.GitRemote == "" {
			return notTrusted()
		}
		if binding.GitRoot != root || binding.GitRemote != strings.TrimSpace(identity.GitRemote) {
			return notTrusted()
		}
		return nil
	default:
		return clerr.New(clerr.ConfigInvalid, "unknown project binding mode")
	}
}

func PathHash(root string) (string, error) {
	clean, err := cleanRoot(root)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(clean))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func cleanRoot(root string) (string, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return "", notTrusted()
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", clerr.Wrap(clerr.ProjectNotTrusted, "resolve project root", err)
	}
	return filepath.Clean(abs), nil
}

func notTrusted() error {
	return clerr.New(clerr.ProjectNotTrusted, "project binding is not approved")
}

func findGitRoot(start string) (string, bool, error) {
	current := start
	for {
		if info, err := os.Stat(filepath.Join(current, ".git")); err == nil {
			if info.IsDir() {
				return current, true, nil
			}
		} else if !os.IsNotExist(err) {
			return "", false, clerr.Wrap(clerr.ConfigInvalid, "inspect git metadata", err)
		}

		parent := filepath.Dir(current)
		if parent == current {
			return "", false, nil
		}
		current = parent
	}
}

func readOriginRemote(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", clerr.Wrap(clerr.ConfigInvalid, "read git config", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	inOrigin := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inOrigin = line == `[remote "origin"]`
			continue
		}
		if !inOrigin {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if ok && strings.TrimSpace(key) == "url" {
			return strings.TrimSpace(value), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", clerr.Wrap(clerr.ConfigInvalid, "scan git config", err)
	}
	return "", nil
}
