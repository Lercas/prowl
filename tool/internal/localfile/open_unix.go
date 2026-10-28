//go:build !windows

package localfile

import "syscall"

const oNonBlock = syscall.O_NONBLOCK
