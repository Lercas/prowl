package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/source"
)

// cmdBucket downloads a cloud-storage prefix (s3:// or gs://) into a temp dir with the platform CLI and
// scans it, then removes the download. The bucket is untrusted, so its own .prowl.yaml is ignored.
func cmdBucket(args []string) int {
	c, rest := parseCommon(args)
	if code := rejectUnsupportedOCR(c, "bucket"); code != 0 {
		return code
	}
	setupLogging(c)
	if c.staged || c.since != "" || c.history {
		logx.Error("bucket does not support Git source modes (--staged, --since, --history)")
		return 2
	}
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

	c.noAutoConfig = true // a downloaded bucket is untrusted — ignore any .prowl.yaml it contains
	return scanItemStream(ctx, c, func(ctx context.Context, c commonFlags) (<-chan model.Item, error) {
		logx.Info("downloading bucket", "uri", uri)
		syncErr := source.SyncBucket(ctx, uri, tmp, source.BucketBudget(c.maxSize), c.timeout)
		if syncErr != nil {
			logx.Error("bucket download failed", "err", syncErr)
		}
		items := source.Filesystem(ctx, []string{tmp}, c.exclude, c.maxSize)
		var initial []model.Item
		if syncErr != nil {
			initial = append(initial, model.Item{Source: "code", Path: uri, Error: syncErr})
		}
		mapped := mapSourcePaths(ctx, items, func(p string) (string, error) {
			rel, err := relativeSourcePath(tmp, p)
			if err != nil || rel == "." {
				return uri, err
			}
			return strings.TrimRight(uri, "/") + "/" + rel, nil
		}, initial...)
		return bucketURIs(ctx, mapped), nil
	})
}

// Cloud CLIs take literal object keys: '#' and '?' are key bytes, and '%20' is not a space.
func bucketArtifactURI(display string) string {
	scheme, rest, ok := strings.Cut(display, "://")
	if !ok || scheme != "s3" && scheme != "gs" {
		return ""
	}
	host, key, hasKey := strings.Cut(rest, "/")
	u := &url.URL{Scheme: scheme, Host: host}
	if hasKey {
		u.Path = "/" + key
	}
	address := u.String()
	if _, err := url.Parse(address); err != nil {
		return ""
	}
	return address
}

func bucketURIs(ctx context.Context, items <-chan model.Item) <-chan model.Item {
	ch := make(chan model.Item, 128)
	go func() {
		defer close(ch)
		for {
			var it model.Item
			select {
			case next, ok := <-items:
				if !ok {
					return
				}
				it = next
			case <-ctx.Done():
				return
			}
			it.ArtifactURI = bucketArtifactURI(it.Path)
			select {
			case ch <- it:
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch
}
