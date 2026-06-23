package main

import (
	"fmt"
	"os"

	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/source"
)

// cmdImage pulls an OCI/Docker image and scans every layer's files plus the image config (env, labels,
// build-history). Scanning all layers (not just the flattened filesystem) catches a secret COPYed in
// one layer and RM'd in a later one. Auth via the default Docker keychain; public images need none.
func cmdImage(args []string) int {
	c, rest := parseCommon(args)
	setupLogging(c)
	if code := c.mlPreflight(); code != 0 {
		return code
	}
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "usage: prowl image <ref> [scan flags]   (e.g. alpine:latest, ghcr.io/org/app@sha256:…)")
		return 2
	}
	if len(rest) > 1 {
		logx.Error("scan one image at a time", "given", len(rest))
		return 2
	}
	ctx, stop := rootContext(c)
	defer stop()

	// An image has no scanned source tree, so there's no untrusted in-repo .prowl.yaml — the user's
	// own config applies normally.
	cfg := loadConfig(&c)
	det, _, err := loadDetector(c, cfg)
	if err != nil {
		logx.Error("failed to load detector", "err", err)
		return 2
	}

	logx.Info("pulling image", "ref", rest[0])
	items, err := source.Image(ctx, rest[0], c.maxSize, c.timeout, c.exclude)
	if err != nil {
		logx.Error("image pull failed", "ref", rest[0], "err", err)
		return 2
	}
	// dedupe is on by default (the same file appears in several layers, report it once); --no-dedupe
	// shows every occurrence.
	return runScan(ctx, c, cfg, det, items, c.dedupe)
}
