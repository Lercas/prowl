package main

import (
	"golang.org/x/sys/windows"
	"os"
)

func terminalColumns(f *os.File) int {
	var info windows.ConsoleScreenBufferInfo
	if windows.GetConsoleScreenBufferInfo(windows.Handle(f.Fd()), &info) == nil {
		return int(info.Window.Right - info.Window.Left + 1)
	}
	return 72
}

// Do not enable terminal modes or emit cursor controls to a legacy console.
func supportsProgressTerminal(f *os.File) bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(f.Fd()), &mode) == nil && mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0
}
