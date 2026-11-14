//go:build windows

package main

import (
	"os"
	"syscall"
)

func auditSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}
