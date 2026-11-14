//go:build !unix

package ownedcmd

import "os/exec"

func configureOwnedCommand(_ *exec.Cmd) {}
func finishOwnedCommand(_ *exec.Cmd)    {}
