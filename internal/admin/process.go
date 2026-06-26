package admin

import "os/exec"

func newBackgroundCommand(executable string, args []string) *exec.Cmd {
	cmd := exec.Command(executable, args...)
	configureBackgroundCommand(cmd)
	return cmd
}
