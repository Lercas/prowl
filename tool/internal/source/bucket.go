package source

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
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
	if maxSize <= 0 {
		return DefaultBucketBudget
	}
	if maxSize > math.MaxInt64/64 {
		return math.MaxInt64
	}
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
	err := resilience.Retry(ctx, 3, time.Second, 10*time.Second, func() error {
		if _, err := measureBucketDir(ctx, destDir, budget, true); err != nil {
			return resilience.Permanent(err)
		}
		actx, cancel := context.WithTimeout(ctx, perAttempt)
		defer cancel()

		// Watch the destination size; on crossing the budget, cancel the CLI and record that the cap
		// (not ctx/timeout) was the cause, since the killed process only surfaces "signal: killed".
		measureFailed := make(chan error, 1)
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
					if _, err := measureBucketDir(actx, destDir, budget, true); err != nil {
						if actx.Err() != nil {
							return
						}
						select {
						case measureFailed <- err:
						default:
						}
						cancel() // stop downloading when the destination cannot be measured safely
						return
					}
				}
			}
		}()

		cmd := exec.CommandContext(actx, bin, args...)
		out, err := runOwnedCommand(cmd)
		cancel()    // stop the watcher promptly
		<-watchDone // and wait for it to exit before reading measureFailed
		select {
		case err := <-measureFailed:
			return resilience.Permanent(err)
		default:
		}
		if err != nil {
			if ctx.Err() != nil { // parent cancelled: give up, don't retry
				return ctx.Err()
			}
			if actx.Err() == context.DeadlineExceeded {
				return fmt.Errorf("%s download timed out after %s", bin, perAttempt)
			}
			return fmt.Errorf("%s download failed: %v: %s", bin, err, strings.TrimSpace(out))
		}
		// Post-run cap check: a sync that starts and finishes within one poll window never trips a tick,
		// so re-measure the final size here. Final traversal errors are terminal as well.
		if _, err := measureBucketDir(ctx, destDir, budget, false); err != nil {
			return resilience.Permanent(err)
		}
		return nil
	})
	return err
}

// measureBucketDir stops at the budget and propagates traversal errors. Only vanished paths may be
// ignored during an active sync; its final measurement must succeed with the destination present.
func measureBucketDir(ctx context.Context, dir string, budget int64, allowVanished bool) (int64, error) {
	var total int64
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			if allowVanished && os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if p == dir && !d.IsDir() {
			return errors.New("bucket destination is not a directory")
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			if allowVanished && os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.Mode().IsRegular() {
			if info.Size() < 0 || info.Size() > budget-total {
				return fmt.Errorf("bucket download aborted: exceeded the %d-byte size cap; scope the prefix narrower or raise --max-size", budget)
			}
			total += info.Size()
		}
		return nil
	})
	return total, err
}
