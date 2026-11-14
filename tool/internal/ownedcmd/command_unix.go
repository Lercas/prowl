//go:build unix

package ownedcmd

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func configureOwnedCommand(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.SysProcAttr.Pgid = 0
	cmd.Cancel = func() error { return killOwnedGroup(cmd) }
}

func killOwnedGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return os.ErrProcessDone
	}
	err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}

func finishOwnedCommand(cmd *exec.Cmd) { _ = killOwnedGroup(cmd) }
