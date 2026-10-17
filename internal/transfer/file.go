package transfer

import (
	"os"
	"path/filepath"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/keyring"
)

// WritePrivateFile atomically replaces path with body and restricts it to the user.
func WritePrivateFile(path string, body []byte) error {
	if path == "" || path == "." || path == string(filepath.Separator) {
		return clerr.New(clerr.ConfigInvalid, "export path is required")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "create export directory", err)
	}
	tmp, err := os.CreateTemp(dir, ".envvault-export-*")
	if err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "create export file", err)
	}
	tmpName := tmp.Name()
	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return clerr.Wrap(clerr.ConfigInvalid, "set export permissions", err)
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return clerr.Wrap(clerr.ConfigInvalid, "write export file", err)
	}
	if err := tmp.Close(); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "close export file", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "replace export file", err)
	}
	success = true
	if err := os.Chmod(path, 0o600); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "set export permissions", err)
	}
	return nil
}

// ReadFile reads a regular export file. It refuses symlinks and files larger
// than the format allows.
func ReadFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, clerr.Wrap(clerr.ConfigInvalid, "read export file", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, clerr.New(clerr.ConfigInvalid, "export file must not be a symlink")
	}
	if !info.Mode().IsRegular() {
		return nil, clerr.New(clerr.ConfigInvalid, "export file is invalid")
	}
	if info.Size() > maxFileBytes {
		return nil, clerr.New(clerr.ConfigInvalid, "export file is too large")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, clerr.Wrap(clerr.ConfigInvalid, "read export file", err)
	}
	if len(body) > maxFileBytes {
		keyring.Zero(body)
		return nil, clerr.New(clerr.ConfigInvalid, "export file is too large")
	}
	return body, nil
}
