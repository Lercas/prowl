//go:build windows

package main

import (
	"os"
	"syscall"
)

func scanSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}
