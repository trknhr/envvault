//go:build aix || (!darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows)

package homefile

import (
	"errors"
	"os"
)

func lockFile(_ *os.File, _ bool) (bool, error) {
	return false, errors.New("isolated home locking is unsupported on this platform")
}

func unlockFile(_ *os.File) error {
	return nil
}
