//go:build !windows

package homefile

import "os"

func secureDirectory(path string) error {
	return os.Chmod(path, 0o700)
}

func secureFile(file *os.File) error {
	return file.Chmod(0o600)
}
