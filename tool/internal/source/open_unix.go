//go:build unix

package source

import "syscall"

// A regular file can be replaced by a FIFO between enumeration and open; never block on that race.
const sourceOpenFlags = syscall.O_NONBLOCK
