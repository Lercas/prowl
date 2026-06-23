package source

import (
	"context"
	"fmt"
	"io/fs"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/resilience"
)

// DefaultBucketBudget caps the bytes a `prowl bucket` sync may write to disk before it is aborted.
// The whole prefix lands on disk before scanning (unlike `image`, which streams in memory), so without
// a cap a broad prefix can fill the filesystem.
const DefaultBucketBudget int64 = 5 << 30 // 5 GiB

// bucketSizePollInterval is how often the running sync's destination size is checked against the
// budget. Short enough to bound the overshoot, cheap enough not to matter. A var so tests can shrink it.
var bucketSizePollInterval = 2 * time.Second

// BucketBudget returns the disk budget for a bucket sync: the larger of DefaultBucketBudget and a
// multiple of --max-size, so raising --max-size for big files also grants proportional headroom.
func BucketBudget(maxSize int64) int64 {
	if scaled := maxSize * 64; scaled > DefaultBucketBudget {
		return scaled
	}
	return DefaultBucketBudget
}

// SyncBucket downloads a cloud-storage prefix (s3://… or gs://…) into destDir via the platform CLI
// (aws / gcloud), reusing the operator's existing credentials, then scans it like any directory.
// Retried for transient failures, each attempt bounded by its own timeout; the CLI resumes from disk,
// so a retry reuses the partial download. Ctx cancellation aborts immediately and is never retried.
func SyncBucket(ctx context.Context, uri, destDir string, budget int64, timeout time.Duration) error {
	if budget <= 0 {
		budget = DefaultBucketBudget
	}
	switch {
	case strings.HasPrefix(uri, "s3://"):
		// Whole prefix lands on disk first; runSync aborts once destDir exceeds the budget.
		warnDiskFootprint(uri, budget)
		return runSync(ctx, destDir, budget, timeout, "aws", "the AWS CLI", "s3", "sync", uri, destDir, "--no-progress")
	case strings.HasPrefix(uri, "gs://"):
		warnDiskFootprint(uri, budget)
		return runSync(ctx, destDir, budget, timeout, "gcloud", "the Google Cloud CLI", "storage", "rsync", "--recursive", uri, destDir)
	default:
		return fmt.Errorf("unsupported bucket URI %q (use s3://bucket/prefix or gs://bucket/prefix)", uri)
	}
}

// warnDiskFootprint warns that the entire prefix downloads to disk before scanning, and states the cap.
func warnDiskFootprint(uri string, budget int64) {
	logx.Warn("downloading the entire prefix to local disk before scanning; the sync is aborted past the size cap — use a narrow prefix to bound disk use",
		"uri", uri, "cap_bytes", budget)
}

// runSync runs the cloud CLI, polling destDir's size on a ticker and killing the command the moment it
// exceeds budget bytes, returning a clear error instead of running the disk out.
func runSync(ctx context.Context, destDir string, budget int64, timeout time.Duration, bin, label string, args ...string) error {
	if _, err := exec.LookPath(bin); err != nil {
		return fmt.Errorf("%s (%q) is required to scan this bucket but is not on PATH; install it and configure your cloud credentials", label, bin)
	}
	perAttempt := fetchTimeout(timeout)
	// capErr, set once a sync blows the disk budget, is captured outside the retry closure so a retry
	// short-circuits: re-downloading the same oversized tree would just hit the cap again (terminal).
	var capErr error
	err := resilience.Retry(ctx, 3, time.Second, 10*time.Second, func() error {
		if capErr != nil {
			return capErr // a prior attempt already blew the budget — don't re-download
		}
		actx, cancel := context.WithTimeout(ctx, perAttempt)
		defer cancel()

		// Watch the destination size; on crossing the budget, cancel the CLI and record that the cap
		// (not ctx/timeout) was the cause, since the killed process only surfaces "signal: killed".
		capExceeded := make(chan int64, 1)
		watchDone := make(chan struct{})
		go func() {
			defer close(watchDone)
			t := time.NewTicker(bucketSizePollInterval)
			defer t.Stop()
			for {
				select {
				case <-actx.Done():
					return
				case <-t.C:
					if sz := dirSize(destDir); sz > budget {
						select {
						case capExceeded <- sz:
						default:
						}
						cancel() // kill the CLI; the disk budget is blown
						return
					}
				}
			}
		}()

		cmd := exec.CommandContext(actx, bin, args...)
		out, err := cmd.CombinedOutput()
		cancel()    // stop the watcher promptly
		<-watchDone // and wait for it to exit before reading capExceeded
		select {
		case sz := <-capExceeded:
			capErr = fmt.Errorf("bucket download aborted: exceeded the %d-byte size cap (reached %d bytes); scope the prefix narrower or raise --max-size", budget, sz)
			return capErr
		default:
		}
		if err != nil {
			if ctx.Err() != nil { // parent cancelled: give up, don't retry
				return ctx.Err()
			}
			if actx.Err() == context.DeadlineExceeded {
				return fmt.Errorf("%s download timed out after %s", bin, perAttempt)
			}
			return fmt.Errorf("%s download failed: %v: %s", bin, err, strings.TrimSpace(string(out)))
		}
		// Post-run cap check: a sync that starts and finishes within one poll window never trips a tick,
		// so re-measure the final size here. Terminal (capErr) like the poll path.
		if sz := dirSize(destDir); sz > budget {
			capErr = fmt.Errorf("bucket download aborted: exceeded the %d-byte size cap (reached %d bytes); scope the prefix narrower or raise --max-size", budget, sz)
			return capErr
		}
		return nil
	})
	return err
}

// dirSize returns the total bytes of regular files under dir (symlinks not followed). Walk errors are
// ignored: an in-flight sync may momentarily list a vanished file, and the next poll re-measures.
func dirSize(dir string) int64 {
	var total int64
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, ierr := d.Info(); ierr == nil && info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	return total
}
