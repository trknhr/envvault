//go:build darwin || linux || freebsd || netbsd || openbsd

package admin

import "testing"

func TestNewBackgroundCommandStartsDetachedProcessGroup(t *testing.T) {
	cmd := newBackgroundCommand("/bin/echo", []string{"ok"})
	if cmd.SysProcAttr == nil {
		t.Fatal("SysProcAttr = nil, want detached process group")
	}
	if !cmd.SysProcAttr.Setpgid {
		t.Fatal("Setpgid = false, want detached process group")
	}
}
