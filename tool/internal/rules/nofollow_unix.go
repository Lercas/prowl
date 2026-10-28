//go:build !windows

package rules

import "syscall"

const oNonBlock = syscall.O_NONBLOCK
