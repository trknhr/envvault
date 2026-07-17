//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package homefile

import (
	"os"

	"golang.org/x/sys/unix"
)

func sourceOpenFlags() int {
	return os.O_RDONLY | unix.O_NONBLOCK
}
