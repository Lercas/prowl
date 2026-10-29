//go:build !windows

package main

import "syscall"

const oNoFollow = syscall.O_NOFOLLOW
