//go:build !darwin && !linux && !freebsd && !netbsd && !openbsd

package admin

import "os/exec"

func configureBackgroundCommand(_ *exec.Cmd) {}
