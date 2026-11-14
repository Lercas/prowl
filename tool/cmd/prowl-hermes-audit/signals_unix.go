//go:build !windows

package main

import (
	"os"
	"syscall"
)

func auditSignals() []os.Signal {
	// Report pipe failures should return through run's cleanup, with the normal error exit code.
	return []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGPIPE}
}
