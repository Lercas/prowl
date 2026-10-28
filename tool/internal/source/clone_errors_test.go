package source

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCloneFailureWithholdsCommandDiagnostics(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake Git command is POSIX-only")
	}
	const secret = "OWNED_GIT_DIAGNOSTIC_SECRET"
	bin := t.TempDir()
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" >&2\nprintf '%s\\n' '" + secret + "' >&2\nexit 7\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	dir, cleanup, err := CloneRepo(context.Background(), CloneOpts{URL: "https://user:" + secret + "@owned.invalid/repo.git"})
	defer cleanup()
	if err == nil || dir != "" || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe clone failure: dir=%q err=%v", dir, err)
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 7 || !strings.Contains(err.Error(), "exit status 7") {
		t.Fatalf("clone failure lost exit classification: %v", err)
	}
}

func TestCloneMissingExecutableRetainsCause(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	_, cleanup, err := CloneRepo(context.Background(), CloneOpts{URL: "https://owned.invalid/repo.git"})
	defer cleanup()
	if !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("missing executable cause lost: %v", err)
	}
}

func TestCloneCancellationRetainsCause(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, cleanup, err := CloneRepo(ctx, CloneOpts{URL: "https://owned.invalid/repo.git"})
	defer cleanup()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("clone cancellation cause lost: %v", err)
	}
}

func TestCloneTimeoutRetainsCauseWithoutDiagnostics(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake Git command is POSIX-only")
	}
	const secret = "OWNED_GIT_TIMEOUT_SECRET"
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte("#!/bin/sh\nprintf '%s\\n' '"+secret+"' >&2\nsleep 30\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	_, cleanup, err := CloneRepo(context.Background(), CloneOpts{URL: "https://owned.invalid/repo.git", Timeout: 25 * time.Millisecond})
	defer cleanup()
	if !errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), "timed out after") {
		t.Fatalf("unsafe or unclassified clone timeout: %v", err)
	}
}
