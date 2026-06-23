package main

import (
	"fmt"
	"os"

	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/source"
)

// cmdBucket downloads a cloud-storage prefix (s3:// or gs://) into a temp dir with the platform CLI and
// scans it, then removes the download. The bucket is untrusted, so its own .prowl.yaml is ignored.
func cmdBucket(args []string) int {
	c, rest := parseCommon(args)
	setupLogging(c)
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "usage: prowl bucket <s3://bucket/prefix | gs://bucket/prefix> [scan flags]")
		fmt.Fprintln(os.Stderr, "  downloads via the aws / gcloud CLI using your existing cloud credentials")
		return 2
	}
	if len(rest) > 1 {
		logx.Error("scan one bucket prefix at a time", "given", len(rest))
		return 2
	}
	uri := rest[0]
	ctx, stop := rootContext(c)
	defer stop()

	tmp, err := os.MkdirTemp("", "prowl-bucket-*")
	if err != nil {
		logx.Error("tempdir failed", "err", err)
		return 2
	}
	defer os.RemoveAll(tmp)

	logx.Info("downloading bucket", "uri", uri)
	// Cap how much the sync may write to disk (scaled off --max-size) so a broad prefix can't fill the
	// filesystem; SyncBucket aborts once the destination exceeds this budget.
	if err := source.SyncBucket(ctx, uri, tmp, source.BucketBudget(c.maxSize), c.timeout); err != nil {
		logx.Error("bucket download failed", "err", err)
		return 2
	}
	saved, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		logx.Error("cannot enter download dir", "err", err)
		return 2
	}
	if saved != "" {
		defer os.Chdir(saved)
	}
	c.noAutoConfig = true // a downloaded bucket is untrusted — ignore any .prowl.yaml it contains
	return scanItems(ctx, c, []string{"."})
}
