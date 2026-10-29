package source

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestBucketBudget(t *testing.T) {
	if got := BucketBudget(math.MinInt64/64 - 1); got != DefaultBucketBudget {
		t.Errorf("negative max-size overflowed the bucket budget: %d", got)
	}
	if got := BucketBudget(math.MaxInt64); got != math.MaxInt64 {
		t.Errorf("large max-size overflowed the bucket budget: %d", got)
	}
	// Below the scaling threshold -> the default floor; above it -> 64x --max-size.
	if got := BucketBudget(0); got != DefaultBucketBudget {
		t.Errorf("BucketBudget(0) = %d, want default %d", got, DefaultBucketBudget)
	}
	if got := BucketBudget(1 << 20); got != DefaultBucketBudget { // 64 MiB < 5 GiB -> floor
		t.Errorf("BucketBudget(1MiB) = %d, want default floor %d", got, DefaultBucketBudget)
	}
	big := int64(1 << 30) // 1 GiB --max-size -> 64 GiB budget
	if got := BucketBudget(big); got != big*64 {
		t.Errorf("BucketBudget(1GiB) = %d, want %d", got, big*64)
	}
}

func TestDirSize(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "a.txt"), strings.Repeat("x", 100))
	write(t, filepath.Join(dir, "sub", "b.txt"), strings.Repeat("y", 50))
	if got, err := measureBucketDir(context.Background(), dir, 1000, false); err != nil || got != 150 {
		t.Errorf("directory size = %d, err=%v, want 150", got, err)
	}
	if _, err := measureBucketDir(context.Background(), dir, 149, false); err == nil {
		t.Fatal("cumulative disk budget ignored")
	}
	if _, err := measureBucketDir(context.Background(), filepath.Join(dir, "a.txt"), 1000, false); err == nil {
		t.Fatal("a regular file was accepted as a bucket destination")
	}
}

func TestBucketBudgetPreventsStartingAnotherDownload(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake cloud CLI is POSIX-only")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "started")
	t.Setenv("PROWL_START_MARKER", marker)
	if err := os.WriteFile(filepath.Join(dir, "aws"), []byte("#!/bin/sh\nprintf ran >> \"$PROWL_START_MARKER\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	dest := t.TempDir()
	write(t, filepath.Join(dest, "already-large"), strings.Repeat("x", 5000))
	if err := SyncBucket(context.Background(), "s3://owned/prefix", dest, 4096, 0); err == nil {
		t.Fatal("existing over-budget destination was accepted")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("terminal budget failure launched another acquisition command")
	}
}

func TestBucketFinalMeasurementCannotIgnoreMissingDestination(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake cloud CLI is POSIX-only")
	}
	binDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(binDir, "aws"), []byte("#!/bin/sh\nmv \"$4\" \"$4-moved\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	dest := filepath.Join(t.TempDir(), "destination")
	if err := os.Mkdir(dest, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := SyncBucket(context.Background(), "s3://owned/prefix", dest, 4096, time.Second); err == nil {
		t.Fatal("sync certified success without measuring its final destination")
	}
}

func TestBucketCancellationDoesNotWaitForChildPipes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process-group cancellation is Unix-only")
	}
	dir := t.TempDir()
	started, release := filepath.Join(dir, "started"), filepath.Join(dir, "release")
	t.Setenv("PROWL_CHILD_STARTED", started)
	t.Setenv("PROWL_CHILD_RELEASE", release)
	script := "#!/bin/sh\n(printf started > \"$PROWL_CHILD_STARTED\"; while [ ! -f \"$PROWL_CHILD_RELEASE\" ]; do sleep 0.01; done) &\nwhile :; do sleep 1; done\n"
	if err := os.WriteFile(filepath.Join(dir, "aws"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- SyncBucket(ctx, "s3://owned/prefix", t.TempDir(), 4096, 30*time.Second) }()
	deadline := time.After(3 * time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			break
		}
		select {
		case <-deadline:
			cancel()
			_ = os.WriteFile(release, nil, 0o600)
			t.Fatal("fake cloud CLI did not reach child barrier")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled sync certified success")
		}
	case <-time.After(500 * time.Millisecond):
		// Release the test-owned child so the original implementation cannot leave it behind.
		if err := os.WriteFile(release, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("cancelled fake cloud CLI did not terminate")
		}
		t.Fatal("cancellation waited for a surviving child to close inherited pipes")
	}
}

// TestSyncBucketAbortsOnBudget: a fake `aws` writes past the budget then sleeps; the size watcher must
// kill it and SyncBucket must return the cap error.
func TestSyncBucketAbortsOnBudget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake-CLI shell script is POSIX-only")
	}
	// Shrink the poll interval so the test doesn't wait the production 2s between checks.
	old := bucketSizePollInterval
	bucketSizePollInterval = 20 * time.Millisecond
	defer func() { bucketSizePollInterval = old }()

	binDir := t.TempDir()
	// `aws s3 sync <uri> <destDir> --no-progress` -> dest is $4. Write 1 MiB then sleep long enough
	// for at least one poll tick to fire and trip the cap.
	fakeAws := "#!/bin/sh\ndest=\"$4\"\nmkdir -p \"$dest\"\nhead -c 1048576 /dev/zero > \"$dest/big.bin\"\nsleep 5\n"
	awsPath := filepath.Join(binDir, "aws")
	if err := os.WriteFile(awsPath, []byte(fakeAws), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	dest := t.TempDir()
	// Budget far below the 1 MiB the fake CLI writes, so the cap trips on the first poll.
	err := SyncBucket(context.Background(), "s3://bucket/prefix", dest, 4096, 30*time.Second)
	if err == nil {
		t.Fatal("SyncBucket should abort when the download exceeds the disk budget")
	}
	if !strings.Contains(err.Error(), "size cap") {
		t.Fatalf("error %q does not mention the size cap; the budget abort did not fire", err)
	}
}

// TestSyncBucketPostRunCapCatchesFastSync: a sync that writes past the budget and exits before any poll
// tick (interval set to an hour) must still be aborted by the post-run size re-measure.
func TestSyncBucketPostRunCapCatchesFastSync(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake-CLI shell script is POSIX-only")
	}
	// Poll interval far longer than the sync runs -> no tick fires; the poll watcher is effectively off.
	old := bucketSizePollInterval
	bucketSizePollInterval = time.Hour
	defer func() { bucketSizePollInterval = old }()

	binDir := t.TempDir()
	// Write 1 MiB and exit immediately (no sleep): the whole sync completes well within one poll window.
	fakeAws := "#!/bin/sh\ndest=\"$4\"\nmkdir -p \"$dest\"\nhead -c 1048576 /dev/zero > \"$dest/big.bin\"\n"
	if err := os.WriteFile(filepath.Join(binDir, "aws"), []byte(fakeAws), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	dest := t.TempDir()
	// Budget far below the 1 MiB written; only the post-run check can catch it since no poll tick fires.
	err := SyncBucket(context.Background(), "s3://bucket/prefix", dest, 4096, 30*time.Second)
	if err == nil {
		t.Fatal("a fast over-budget sync must still be aborted by the post-run size check (poll-only gap)")
	}
	if !strings.Contains(err.Error(), "size cap") {
		t.Fatalf("error %q does not mention the size cap; the post-run cap check did not fire", err)
	}
}

// TestSyncBucketSucceedsUnderBudget confirms a normal under-budget sync is not falsely aborted.
func TestSyncBucketSucceedsUnderBudget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake-CLI shell script is POSIX-only")
	}
	old := bucketSizePollInterval
	bucketSizePollInterval = 20 * time.Millisecond
	defer func() { bucketSizePollInterval = old }()

	binDir := t.TempDir()
	fakeAws := "#!/bin/sh\ndest=\"$4\"\nmkdir -p \"$dest\"\nprintf 'small' > \"$dest/f.txt\"\n"
	if err := os.WriteFile(filepath.Join(binDir, "aws"), []byte(fakeAws), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	dest := t.TempDir()
	if err := SyncBucket(context.Background(), "s3://bucket/prefix", dest, 1<<20, 30*time.Second); err != nil {
		t.Fatalf("under-budget sync wrongly failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "f.txt")); err != nil {
		t.Errorf("expected synced file present: %v", err)
	}
}
