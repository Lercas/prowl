//go:build !windows

package main

import "syscall"

// oNoFollow is O_NOFOLLOW on POSIX (refuse to open through a symlink) and 0 on Windows, which lacks it.
const oNoFollow = syscall.O_NOFOLLOW
