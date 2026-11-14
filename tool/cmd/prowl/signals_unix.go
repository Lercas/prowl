//go:build !windows

package main

import (
	"os"
	"syscall"
)

// A broken report pipe must return its write error through caller cleanup, not kill the process
// before downloaded scan data is released. SIGPIPE also cancels any remaining scan work.
func scanSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGPIPE}
}
