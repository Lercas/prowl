package main

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/source"
)

// cmdImage scans an image — remote ref, local tarball, OCI-layout dir, or stdin "-" — across every layer
// plus the config. --image-input forces the source kind when auto-detect would guess wrong.
func cmdImage(args []string) int {
	c, rest := parseCommon(args)
	setupLogging(c)
	if code := c.mlPreflight(); code != 0 {
		return code
	}
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "usage: prowl image <ref|tarball|oci-dir|-> ... [scan flags]")
		return 2
	}
	ctx, stop := rootContext(c)
	defer stop()

	cfg := loadConfig(&c) // no scanned tree, so no untrusted in-repo .prowl.yaml
	det, _, err := loadDetector(c, cfg)
	if err != nil {
		logx.Error("failed to load detector", "err", err)
		return 2
	}

	kind, ok := imageKind(c.imageInput)
	if !ok {
		logx.Error("invalid --image-input (want: ref|tar|oci-dir|stdin)", "value", c.imageInput)
		return 2
	}
	if kind == source.ImageStdin && len(rest) > 1 {
		logx.Error("--image-input stdin reads one image from '-'; pass a single argument", "args", len(rest))
		return 2
	}
	var (
		finals  []*source.FinalIndex
		finalMu sync.Mutex
		rc      atomic.Int32
	)
	merged := make(chan model.Item, 128)
	go func() {
		defer close(merged)
		for _, arg := range rest {
			if ctx.Err() != nil {
				return
			}
			logx.Info("scanning image", "arg", arg)
			// pull just before draining so a per-attempt deadline can't expire while earlier images scan
			items, fi, err := source.Image(ctx, arg, kind, c.maxSize, c.timeout, c.exclude)
			if err != nil {
				logx.Error("image load failed", "arg", arg, "err", err)
				rc.Store(2)
				continue
			}
			finalMu.Lock()
			finals = append(finals, fi)
			finalMu.Unlock()
			for it := range items {
				select {
				case merged <- it:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	code := runScan(ctx, c, cfg, det, merged, c.dedupe, func(fs []model.Finding) []model.Finding {
		if ctx.Err() != nil { // cancelled: the flatten map is partial — don't assert in_final verdicts
			return fs
		}
		finalMu.Lock()
		defer finalMu.Unlock()
		return source.MarkFinalImage(fs, finals)
	})
	// an anti-bomb / cancel abort means extraction stopped early — fail closed, never certify clean
	finalMu.Lock()
	for _, fi := range finals {
		if fi.Aborted() {
			logx.Error("image extraction was aborted — results incomplete, failing closed")
			rc.Store(2)
			break
		}
	}
	finalMu.Unlock()
	if v := int(rc.Load()); v > code {
		code = v
	}
	return code
}

// imageKind maps --image-input to a source.ImageInput; empty = auto-detect, ok=false on an invalid value.
func imageKind(s string) (source.ImageInput, bool) {
	switch s {
	case "":
		return source.ImageAuto, true
	case "ref":
		return source.ImageRef, true
	case "tar":
		return source.ImageTar, true
	case "oci-dir":
		return source.ImageOCIDir, true
	case "stdin":
		return source.ImageStdin, true
	default:
		return source.ImageAuto, false
	}
}
