//go:build windows || (!aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris)

package homefile

import "os"

func sourceOpenFlags() int {
	return os.O_RDONLY
}
