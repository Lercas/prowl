//go:build !windows

package main

import (
	"os"
	"syscall"
)

// Refuse leaf symlinks and avoid blocking if a FIFO replaces the selected key.
const identityOpenFlags = os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
