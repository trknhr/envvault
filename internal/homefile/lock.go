package homefile

import (
	"os"
	"sync"

	"github.com/trknhr/envvault/internal/clerr"
)

type workspaceLock struct {
	file      *os.File
	closeOnce sync.Once
	closeErr  error
}

func acquireWorkspaceLock(rootPath string) (*workspaceLock, error) {
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, clerr.Wrap(clerr.ConfigInvalid, "open isolated home workspace", err)
	}
	file, openErr := root.OpenFile(LockFilename, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	rootCloseErr := root.Close()
	if openErr != nil {
		return nil, clerr.Wrap(clerr.ConfigInvalid, "create isolated home active lock", openErr)
	}
	if rootCloseErr != nil {
		_ = file.Close()
		return nil, clerr.Wrap(clerr.CleanupFailed, "close isolated home workspace", rootCloseErr)
	}
	if err := secureFile(file); err != nil {
		_ = file.Close()
		return nil, clerr.Wrap(clerr.ConfigInvalid, "secure isolated home active lock", err)
	}
	acquired, err := lockFile(file, false)
	if err != nil {
		_ = file.Close()
		return nil, clerr.Wrap(clerr.ConfigInvalid, "lock isolated home workspace", err)
	}
	if !acquired {
		_ = file.Close()
		return nil, clerr.New(clerr.ConfigInvalid, "isolated home workspace is already active")
	}
	return &workspaceLock{file: file}, nil
}

// IsActive reports whether an isolated-home workspace is held by a running
// EnvVault process. It fails closed when its lock metadata is missing or
// malformed so callers never delete a workspace whose state is unknown.
func IsActive(rootPath string) (bool, error) {
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return false, clerr.Wrap(clerr.ConfigInvalid, "open isolated home workspace", err)
	}
	defer root.Close()
	info, err := root.Lstat(LockFilename)
	if err != nil {
		return false, clerr.Wrap(clerr.ConfigInvalid, "inspect isolated home active lock", err)
	}
	if !info.Mode().IsRegular() {
		return false, clerr.New(clerr.ConfigInvalid, "isolated home active lock is not a regular file")
	}
	file, err := root.OpenFile(LockFilename, os.O_RDWR, 0)
	if err != nil {
		return false, clerr.Wrap(clerr.ConfigInvalid, "open isolated home active lock", err)
	}
	acquired, lockErr := lockFile(file, true)
	if lockErr != nil {
		_ = file.Close()
		return false, clerr.Wrap(clerr.ConfigInvalid, "probe isolated home active lock", lockErr)
	}
	if !acquired {
		if err := file.Close(); err != nil {
			return false, clerr.Wrap(clerr.CleanupFailed, "close isolated home active lock", err)
		}
		return true, nil
	}
	unlockErr := unlockFile(file)
	closeErr := file.Close()
	if unlockErr != nil {
		return false, clerr.Wrap(clerr.CleanupFailed, "unlock isolated home workspace", unlockErr)
	}
	if closeErr != nil {
		return false, clerr.Wrap(clerr.CleanupFailed, "close isolated home active lock", closeErr)
	}
	return false, nil
}

func (l *workspaceLock) Close() error {
	if l == nil {
		return nil
	}
	l.closeOnce.Do(func() {
		unlockErr := unlockFile(l.file)
		closeErr := l.file.Close()
		if unlockErr != nil {
			l.closeErr = clerr.Wrap(clerr.CleanupFailed, "unlock isolated home workspace", unlockErr)
			return
		}
		if closeErr != nil {
			l.closeErr = clerr.Wrap(clerr.CleanupFailed, "close isolated home active lock", closeErr)
		}
	})
	return l.closeErr
}
