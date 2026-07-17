//go:build windows

package homefile

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func lockFile(file *os.File, nonblocking bool) (bool, error) {
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK)
	if nonblocking {
		flags |= windows.LOCKFILE_FAIL_IMMEDIATELY
	}
	var overlapped windows.Overlapped
	err := windows.LockFileEx(windows.Handle(file.Fd()), flags, 0, 1, 0, &overlapped)
	if err == nil {
		return true, nil
	}
	if nonblocking && (errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_IO_PENDING)) {
		return false, nil
	}
	return false, err
}

func unlockFile(file *os.File) error {
	var overlapped windows.Overlapped
	return windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped)
}
