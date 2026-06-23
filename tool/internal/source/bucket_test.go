package source

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestBucketBudget(t *testing.T) {
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
	if got := dirSize(dir); got != 150 {
		t.Errorf("dirSize = %d, want 150", got)
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
