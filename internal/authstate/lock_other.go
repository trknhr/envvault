//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package authstate

import (
	"errors"
	"os"
)

func tryLock(*os.File) (bool, error) { return false, errors.New("authentication locking unsupported") }
func unlock(*os.File)                {}
