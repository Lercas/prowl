package main

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/Lercas/prowl/tool/internal/domain"
	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/scan"
	"github.com/Lercas/prowl/tool/internal/targetlist"
)

func cmdDomain(args []string) int {
	c, rest, err := parseCommand("domain", args)
	if err != nil {
		return commandParseError(err)
	}
	if code := rejectUnsupportedOCR(c, "domain"); code != 0 {
		return code
	}
	setupLogging(c)
	if code := c.scanPreflight(); code != 0 {
		return code
	}
	opts := domain.Options{Recon: c.cmd.recon, Authorized: c.cmd.authorized, MaxAssets: c.cmd.maxAssets}
	if opts.Timeout == 0 {
		opts.Timeout = 12 * time.Second
	}

	var targets []string
	if f := c.cmd.targetsFile; f != "" {
		ts, err := readTargetList(f)
		if err != nil {
			logx.Error("could not read --targets file", "path", f, "err", err)
			return 2
		}
		targets = ts
	} else if len(rest) == 1 {
		targets = []string{rest[0]}
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "usage: prowl domain <host> [--targets file] [--authorized] [--recon]")
		return 2
	}
	if !opts.Authorized {
		fmt.Fprintln(os.Stderr, "refusing: pass --authorized to confirm you are authorized to scan these hosts "+
			"(the scan fetches each host's published pages/JS).")
		return 2
	}
	for i, target := range targets {
		address, err := domain.ParseTarget(target)
		if err != nil {
			logx.Error("invalid domain target", "entry", i+1, "err", err)
			return 2
		}
		if opts.Recon && !address.ReconEligible {
			logx.Error("recon requires DNS hostnames without explicit ports", "entry", i+1)
			return 2
		}
		targets[i] = address.Canonical
	}

	cfg, err := loadConfig(&c)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		return 2
	}
	det, tax, err := loadDetector(c, cfg)
	if err != nil {
		logx.Error("failed to load detector", "err", err)
		return 2
	}
	eng, err := loadConfiguredEngine(c, cfg)
	if err != nil {
		logx.Error("rule setup failed", "err", err)
		return 2
	}
	if code := detectorPreflight(c, tax, eng); code != 0 {
		return code
	}
	vset, verr := loadVerifySet(c)
	if verr != nil {
		logx.Error("verify setup failed", "err", verr)
		return 2
	}

	prepared := prepareScan(c, scan.Options{Detector: det, Rules: eng, Verifiers: vset, Allow: cfg.Allowed})
	if prepared.indexError != nil {
		logx.Error("index setup failed", "err", prepared.indexError)
		return 2
	}
	ctx, stop := rootContext(c)
	defer stop()
	start := time.Now()

	// Hosts run across a bounded pool — a subdomain sweep is mostly dead hosts whose connect-timeout
	// dominates wall time, so they must time out concurrently, not one after another. Each host's own
	// asset fetches stay internally concurrent; the pool fans across DISTINCT hosts (no single host is
	// hammered). One host == one worker, so the positional single-target path is unchanged.
	var (
		mu         sync.Mutex
		findings   []model.Finding
		reachedAny bool
		wg         sync.WaitGroup
		jobs       = make(chan string)
	)
	hostWorkers := 8
	if hostWorkers > len(targets) {
		hostWorkers = len(targets)
	}
	for w := 0; w < hostWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				if ctx.Err() != nil {
					return
				}
				logx.Info("scanning domain", "target", target, "recon", opts.Recon)
				items, reached := domain.Discover(ctx, target, opts)
				fs := prepared.Collect(ctx, items)
				if !reached.Load() {
					logx.Warn("root page could not be read completely", "target", target)
				}
				mu.Lock()
				reachedAny = reachedAny || reached.Load()
				findings = append(findings, fs...)
				mu.Unlock()
			}
		}()
	}
	for _, t := range targets {
		select {
		case jobs <- t:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(jobs)
	wg.Wait()

	if !reachedAny && ctx.Err() == nil { // every host unreachable must error, not exit-0 "clean"
		logx.Error("no root page could be read completely — results are incomplete")
	}
	if err := ctx.Err(); err != nil {
		findings = append(findings, orgDiagnostic("domain", err.Error()))
	}
	return reportScan(ctx, c, findings, time.Since(start))
}

func readTargetList(path string) ([]string, error) {
	return targetlist.Read(path)
}
