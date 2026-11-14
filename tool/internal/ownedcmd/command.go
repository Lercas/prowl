// Package ownedcmd runs acquisition commands with bounded diagnostics and pipe waits.
package ownedcmd

import (
	"os/exec"
	"strings"
	"sync"
	"time"
)

// MaxOutput caps retained diagnostics; excess output is drained, not buffered.
const MaxOutput = 64 << 10

// Output is a bounded, concurrent-safe diagnostic writer.
type Output struct {
	mu        sync.Mutex
	text      strings.Builder
	truncated bool
}

func (out *Output) Write(p []byte) (int, error) {
	out.mu.Lock()
	defer out.mu.Unlock()
	n := len(p)
	remaining := MaxOutput - out.text.Len()
	if len(p) > remaining {
		out.truncated = true
		p = p[:remaining]
	}
	_, _ = out.text.Write(p)
	return n, nil // drain the child even after the diagnostic output cap
}

func (out *Output) String() string {
	out.mu.Lock()
	defer out.mu.Unlock()
	if out.truncated {
		return out.text.String() + "\n[command output truncated]"
	}
	return out.text.String()
}

// Run bounds diagnostics and inherited-pipe waits. Unix commands use a fresh process
// group so cancellation and completion also stop workers spawned by this acquisition command.
func Run(cmd *exec.Cmd) (string, error) {
	configureOwnedCommand(cmd)
	defer finishOwnedCommand(cmd)
	cmd.WaitDelay = time.Second
	out := &Output{}
	cmd.Stdout, cmd.Stderr = out, out
	err := cmd.Run()
	return out.String(), err
}
