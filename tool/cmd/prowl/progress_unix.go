//go:build !windows

package main

import (
	"github.com/mattn/go-isatty"
	"golang.org/x/sys/unix"
	"os"
)

func terminalColumns(f *os.File) int {
	if size, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ); err == nil && size.Col > 0 {
		return int(size.Col)
	}
	return 72
}

func supportsProgressTerminal(f *os.File) bool { return isatty.IsTerminal(f.Fd()) }
