//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package homefile

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func lockFile(file *os.File, nonblocking bool) (bool, error) {
	operation := unix.LOCK_EX
	if nonblocking {
		operation |= unix.LOCK_NB
	}
	err := unix.Flock(int(file.Fd()), operation)
	if err == nil {
		return true, nil
	}
	if nonblocking && (errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN)) {
		return false, nil
	}
	return false, err
}

func unlockFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_UN)
}
