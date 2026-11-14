package ownedcmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

func helperCommand(t *testing.T, ctx context.Context, mode string) *exec.Cmd {
	t.Helper()
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, bin, "-test.run=^TestOwnedCommandHelper$")
	cmd.Env = append(os.Environ(), "PROWL_OWNEDCMD_TEST_MODE="+mode)
	return cmd
}

func TestOwnedCommandHelper(t *testing.T) {
	switch os.Getenv("PROWL_OWNEDCMD_TEST_MODE") {
	case "output":
		fmt.Fprint(os.Stdout, strings.Repeat("x", MaxOutput*2))
		fmt.Fprint(os.Stderr, "stderr drained")
		os.Exit(0)
	case "failure":
		fmt.Fprint(os.Stderr, "acquisition failed")
		os.Exit(7)
	case "wait":
		time.Sleep(time.Minute)
		os.Exit(0)
	}
}

func TestOutputCapDrainsAndKeepsExactBoundary(t *testing.T) {
	var out Output
	data := strings.Repeat("x", MaxOutput)
	if n, err := out.Write([]byte(data)); err != nil || n != len(data) || out.String() != data {
		t.Fatal("exact-size diagnostic was lost or marked truncated")
	}
	if n, err := out.Write([]byte("more")); n != 4 || err != nil {
		t.Fatal("overflow must still report a complete write")
	}
	if got := out.String(); got != data+"\n[command output truncated]" {
		t.Fatal("unbounded or missing truncation diagnostic")
	}
}

func TestOutputConcurrentWritersAndReaders(t *testing.T) {
	var out Output
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 100 {
				if n, err := out.Write([]byte("12345678")); n != 8 || err != nil {
					t.Error("diagnostic write failed")
				}
				_ = out.String()
			}
		})
	}
	workers.Wait()
	if len(out.String()) != 6400 {
		t.Fatal("concurrent diagnostic output was lost")
	}
}

func TestRunBoundsOutputAndPreservesExitError(t *testing.T) {
	output, err := Run(helperCommand(t, context.Background(), "output"))
	if err != nil || output != strings.Repeat("x", MaxOutput)+"\n[command output truncated]" {
		t.Fatalf("bounded command: bytes=%d err=%v", len(output), err)
	}
	output, err = Run(helperCommand(t, context.Background(), "failure"))
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 7 || output != "acquisition failed" {
		t.Fatalf("failed command lost diagnostics: %q %v", output, err)
	}
}

func TestRunCancellationAndStartFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := Run(helperCommand(t, ctx, "wait"))
	if err == nil || ctx.Err() == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("cancelled acquisition did not stop promptly: %v", err)
	}
	_, err = Run(exec.Command(t.TempDir() + "/absent-program"))
	if err == nil {
		t.Fatal("start failure was hidden")
	}
}

func TestRunWithStdoutSeparatesDataAndBoundsDiagnostics(t *testing.T) {
	var data bytes.Buffer
	diagnostic, err := RunWithStdout(helperCommand(t, context.Background(), "output"), &data)
	if err != nil || data.String() != strings.Repeat("x", MaxOutput*2) || diagnostic != "stderr drained" {
		t.Fatal("stdout data was truncated or mixed with stderr")
	}
}
