package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Lercas/prowl/tool/internal/forge"
	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/ocr"
	"github.com/Lercas/prowl/tool/internal/scan"
	"github.com/Lercas/prowl/tool/internal/source"
)

// cmdOrg lists every repo under a GitHub org/user, GitLab group, or Bitbucket workspace, then clones
// and scans them on a worker pool, building the detector/engine/verifier once and merging findings into
// one report. Target is "<platform>:<name>"; auth via GITHUB_TOKEN / GITLAB_TOKEN / BITBUCKET_TOKEN.
// --concurrency N caps the pool (default min(4, #repos)); a failed repo remains a diagnostic. Exit is
// 2 whenever repository acquisition or scanning is incomplete.
func cmdOrg(args []string) int {
	c, rest, err := parseCommand("org", args)
	if err != nil {
		return commandParseError(err)
	}
	conc, excludeRepo := c.cmd.concurrency, c.cmd.excludeRepos
	setupLogging(c)
	if code := checkSourceModes(c, nil); code != 0 {
		return code
	}
	if code := c.scanPreflight(); code != 0 {
		return code
	}
	target := ""
	if len(rest) == 1 {
		target = rest[0]
	}
	if target == "" {
		fmt.Fprintln(os.Stderr, "usage: prowl org <github|gitlab|bitbucket>:<name> [--gists] [--history] [--concurrency N] [--exclude-repo S,…] [scan flags]")
		fmt.Fprintln(os.Stderr, "  auth via GITHUB_TOKEN / GITLAB_TOKEN / BITBUCKET_TOKEN env (for private repos)")
		return 2
	}
	gists := c.cmd.gists
	ctx, stop := rootContext(c)
	defer stop()
	// Load config before listing so limits.org_max_pages bounds ListRepos. noAutoConfig is set first so
	// a cloned repo's own untrusted .prowl.yaml can never apply — only an explicit --config.
	c.noAutoConfig = true
	cfg, err := loadConfig(&c)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		return 2
	}
	ocrEngine, err := setupOCR(c)
	if err != nil {
		logx.Error("OCR setup failed", "err", err)
		return 2
	}
	if ocrEngine != nil {
		ctx = source.WithOCR(ctx, ocrEngine)
		c.indexCoverageComplete = func() bool { stats := ocrEngine.Stats(); return stats.Failures == 0 && stats.Skipped == 0 }
		logx.Info("OCR enabled", "model", firstNonEmpty(c.ocrModel, ocr.DefaultModel),
			"endpoint", redactURL(firstNonEmpty(c.ocrURL, ocr.DefaultURL)),
			"pdf_pages", c.ocrMaxPages, "all_pdf_pages", c.ocrAllPages)
	}
	// Build the detector + rule engine + verifier set once and share them across workers (read-only
	// after construction; Pipeline.Run/verify serialise their own internal state).
	det, tax, err := loadDetector(c, cfg)
	if err != nil {
		logx.Error("failed to load detector", "err", err)
		return 2
	}
	if len(tax.Skipped) > 0 {
		logx.Debug("some detector regexes not RE2-compatible, skipped", "count", len(tax.Skipped))
	}
	eng, err := loadConfiguredEngine(c, cfg)
	if err != nil {
		logx.Error("rule setup failed", "err", err)
		return 2
	}
	vset, verr := loadVerifySet(c)
	if verr != nil {
		logx.Error("verify setup failed", "err", verr)
		return 2
	}

	prepared := prepareScan(c, scan.Options{Detector: det, Rules: eng, Verifiers: vset, Allow: cfg.Allowed})
	if prepared.indexError != nil {
		logx.Error("подготовка индекса не удалась", "err", prepared.indexError)
		return 2
	}
	var urls []string
	if gists {
		logx.Info("listing gists", "target", target)
		urls, err = forge.ListGists(ctx, target)
	} else {
		logx.Info("listing repositories", "target", target)
		urls, err = forge.ListRepos(ctx, target)
	}
	var listingDiagnostics []model.Finding
	if err != nil {
		logx.Error("listing failed", "err", err)
		listingDiagnostics = append(listingDiagnostics, orgDiagnostic(target, "repository listing is incomplete"))
	}
	if len(excludeRepo) > 0 { // skip repos matching any --exclude-repo substring (e.g. a vendored fork)
		kept := urls[:0]
		for _, u := range urls {
			if !matchesAny(u, excludeRepo) {
				kept = append(kept, u)
			}
		}
		if n := len(urls) - len(kept); n > 0 {
			logx.Info("excluded repositories", "count", n)
		}
		urls = kept
	}

	workers := conc
	if workers == 0 {
		workers = 4
	}
	if len(urls) < workers {
		workers = len(urls)
	}
	logx.Info("scanning repositories", "count", len(urls), "concurrency", workers)

	start := time.Now()
	var (
		mu      sync.Mutex
		all     = listingDiagnostics
		scanned int // repos that completed (clone+scan) without a fatal error
		failed  int // repos skipped due to a clone/scan error
		jobs    = make(chan string)
		wg      sync.WaitGroup
	)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range jobs {
				if ctx.Err() != nil {
					return
				}
				fs, ok := scanOrgRepo(ctx, prepared, u)
				mu.Lock()
				all = append(all, fs...)
				if ok {
					scanned++
					logx.Info("scanned", "repo", source.RepositoryLocator(u), "findings", len(fs))
				} else {
					failed++
				}
				mu.Unlock()
			}
		}()
	}
	for _, u := range urls {
		// select (not a bare send) so a Ctrl-C draining the workers mid-dispatch can't deadlock here.
		select {
		case jobs <- u:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(jobs)
	wg.Wait()

	if failed > 0 {
		logx.Warn("some repositories could not be scanned", "failed", failed, "scanned", scanned, "total", len(urls))
	}
	if ctx.Err() != nil {
		all = append(all, orgDiagnostic(target, "organization scan interrupted; results are incomplete"))
	}
	// A timeout/interrupt mid-sweep leaves repos unscanned — fail closed rather than gate over partial.
	code := reportScan(ctx, c, all, time.Since(start))
	return finalizeOCR(ocrEngine, code)
}

// scanOrgRepo uses a repository-qualified locator before allowlisting and fingerprinting.
// Failed clones remain diagnostics in the aggregate rather than silently skipped repositories.
func scanOrgRepo(ctx context.Context, prepared preparedScan, url string) (findings []model.Finding, ok bool) {
	c := prepared.flags
	label := repoLabel(url)
	dir, cleanup, err := source.CloneRepo(ctx, source.CloneOpts{URL: url, Full: c.history, Timeout: c.timeout})
	if err != nil {
		logx.Error("clone failed", "url", source.RepositoryLocator(url), "err", err)
		return []model.Finding{orgDiagnostic(label, "repository clone failed; scan results are incomplete")}, false
	}
	defer cleanup()
	ctx, revisionErr := source.RepositoryContext(ctx, dir, source.CloneOpts{URL: url, Full: c.history, Timeout: c.timeout})
	var initial []model.Item
	if revisionErr != nil {
		initial = append(initial, model.Item{Source: "code", Path: label, Error: revisionErr})
	}
	var items <-chan model.Item
	if c.history {
		if c.gitTimeline {
			items = source.GitTimelineBlobs(ctx, dir, c.exclude, c.maxSize)
		} else {
			items = source.GitHistoryBlobs(ctx, dir, c.exclude, c.maxSize)
		}
	} else {
		items = source.Filesystem(ctx, []string{dir}, c.exclude, c.maxSize)
	}
	items = mapSourcePaths(ctx, items, func(p string) (string, error) {
		if !c.history {
			var err error
			p, err = relativeSourcePath(dir, p)
			if err != nil {
				return label, err
			}
		}
		return label + ": " + p, nil
	}, initial...)
	fs := prepared.Collect(ctx, items)
	complete := true
	for _, f := range fs {
		if model.IsIncompleteFinding(f) {
			complete = false
		}
	}
	return fs, complete
}

func orgDiagnostic(path, reason string) model.Finding {
	return model.Finding{Detector: "source", Type: "source_error", Severity: "info", Source: "code", Path: path, Stage: "intake", Rationale: reason}
}

// Keep the host in identities so equally named repositories on different forges cannot collide.
func repoLabel(url string) string { return strings.TrimSuffix(source.RepositoryLocator(url), ".git") }
