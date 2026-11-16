package source

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestAcquisitionTimeoutSnapshotsAndExplicitPrecedence(t *testing.T) {
	defer SetCloneTimeout(DefaultFetchTimeout)
	SetCloneTimeout(time.Second)
	legacy := snapshotFetchTimeout(t.Context())
	explicit := WithFetchTimeout(t.Context(), 2*time.Second)
	defaults := WithFetchTimeout(t.Context(), 0)
	SetCloneTimeout(3 * time.Second)
	if contextFetchTimeout(legacy, 0) != time.Second || contextFetchTimeout(explicit, 0) != 2*time.Second || contextFetchTimeout(defaults, 0) != DefaultFetchTimeout || contextFetchTimeout(explicit, 4*time.Second) != 4*time.Second {
		t.Fatal("source timeout changed or ignored explicit operation override")
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 1000 {
			SetCloneTimeout(time.Second)
			SetCloneTimeout(3 * time.Second)
		}
	})
	wg.Go(func() {
		for range 100 {
			if contextFetchTimeout(explicit, 0) != 2*time.Second {
				t.Error("explicit source timeout changed")
			}
			_ = snapshotFetchTimeout(context.Background())
		}
	})
	wg.Wait()
}

func TestSelectedSourceTimeoutControlsOwnedCloneCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("owned command fixture requires POSIX shell")
	}
	defer SetCloneTimeout(DefaultFetchTimeout)
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte("#!/bin/sh\nexec /bin/sleep 0.05\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	SetCloneTimeout(time.Nanosecond)
	ctx := WithFetchTimeout(t.Context(), time.Second)
	_, cleanup, err := CloneRepo(ctx, CloneOpts{URL: "https://owned.invalid/repo.git"})
	defer cleanup()
	if err != nil {
		t.Fatal("legacy timeout changed selected clone budget", err)
	}
	if err := runSync(ctx, t.TempDir(), 1024, 0, "/bin/sleep", "owned-sync", "0.05"); err != nil {
		t.Fatal("legacy timeout changed selected bucket budget", err)
	}
	if err := repositoryData(ctx, t.TempDir(), CloneOpts{}, io.Discard, 1024, "rev-parse", "HEAD"); err != nil {
		t.Fatal("legacy timeout changed selected metadata budget", err)
	}
	_, cleanup2, err := CloneRepo(ctx, CloneOpts{URL: "https://owned.invalid/repo.git", Timeout: time.Nanosecond})
	defer cleanup2()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("explicit per-operation timeout did not override selected budget", err)
	}
}
