package main

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Lercas/prowl/tool/internal/atlassian"
	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/scan"
)

func cmdJira(args []string) int       { return cmdAtlassian(args, "jira") }
func cmdConfluence(args []string) int { return cmdAtlassian(args, "confluence") }

// cmdAtlassian scans a Jira or Confluence instance — Cloud, Server, or Data Center — across EVERY
// historical version of each issue/page (default), feeding the extracted text through the same
// cascade as every other source. It mirrors cmdDomain: detect/connect, stream items, scan, gate.
func cmdAtlassian(args []string, product string) int {
	c, rest, err := parseCommand(product, args)
	if err != nil {
		return commandParseError(err)
	}
	if code := rejectUnsupportedOCR(c, product); code != 0 {
		return code
	}
	setupLogging(c)
	if code := c.mlPreflight(); code != 0 {
		return code
	}

	base := c.cmd.baseURL
	if base == "" {
		if len(rest) == 1 {
			base = rest[0]
		}
	}
	if base == "" {
		base = os.Getenv("ATLASSIAN_BASE_URL")
	}
	if base == "" {
		fmt.Fprintf(os.Stderr, "usage: prowl %s <base-url> [--current-only] [--project KEY]... [--space KEY]...\n", product)
		fmt.Fprintln(os.Stderr, "  auth via env: ATLASSIAN_EMAIL + ATLASSIAN_API_TOKEN (Cloud)  |  ATLASSIAN_PAT (Server/Data Center)")
		fmt.Fprintln(os.Stderr, "  default scans every version from the first; --current-only scans only the latest")
		return 2
	}
	if !strings.Contains(base, "://") {
		base = "https://" + base
	}

	auth := atlassianAuthFromEnv()
	if auth.Empty() {
		fmt.Fprintln(os.Stderr, "refusing: no Atlassian credentials found.")
		fmt.Fprintln(os.Stderr, "  set ATLASSIAN_EMAIL + ATLASSIAN_API_TOKEN (Cloud) or ATLASSIAN_PAT (Server/Data Center).")
		return 2
	}

	opts := atlassian.Options{
		CurrentOnly: c.cmd.currentOnly,
		Projects:    c.cmd.projects,
		Spaces:      c.cmd.spaces,
		Fields:      c.cmd.fields,
		MaxItems:    c.cmd.maxItems,
		Workers:     c.workers, // --workers tunes the per-item fetch concurrency (0 -> package default)
	}

	cfg, err := loadConfig(&c)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		return 2
	}
	det, _, err := loadDetector(c, cfg)
	if err != nil {
		logx.Error("failed to load detector", "err", err)
		return 2
	}
	eng, err := loadEngine(c)
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
	if err := prepared.mlError; err != nil {
		logx.Error("ML setup failed", "err", err)
		return 2
	}

	ctx, stop := rootContext(c)
	defer stop()
	start := time.Now()

	items, dep, derr := atlassian.Collect(ctx, base, product, auth, opts)
	if derr != nil {
		logx.Error("could not connect to "+product, "err", derr)
		return 2
	}
	logx.Info("connected", "deployment", dep.String(), "history", !opts.CurrentOnly)

	// Count emitted items so a scan that reaches NOTHING (credentials scoped to nothing, every project
	// 403, a typo'd --project, a genuinely empty instance) fails loud rather than exiting 0 "clean".
	var itemCount atomic.Int64
	counted := make(chan model.Item, 64)
	go func() {
		defer close(counted)
		for it := range items {
			// ctx-aware send: on --timeout/Ctrl-C, Pipeline.Run's workers stop reading `counted`, so a bare
			// `counted <- it` would block this goroutine forever (and never close the channel). Bail on
			// ctx.Done instead; Collect's emit already respects the same ctx, so the walker unwinds too.
			select {
			case counted <- it:
				itemCount.Add(1)
			case <-ctx.Done():
				return
			}
		}
	}()

	findings := prepared.pipeline.Run(ctx, counted)
	if itemCount.Load() == 0 && ctx.Err() == nil {
		logx.Error("scanned 0 items — check credentials, the account's project/space access, and any --project/--space filter", "product", product)
		return 2
	}
	if c.verifiedOnly {
		findings = keepVerified(findings)
	}
	if c.failOnVerified {
		escalateLive(findings)
	}
	// reportFindings (not the bare gate) so --baseline / --write-baseline / --min-severity /
	// --min-confidence / --disable and the in-repo baseline/.gitleaksignore pickup all apply, exactly
	// as for scan/repo/org/image/bucket.
	return reportScan(ctx, c, findings, time.Since(start))
}

// atlassianAuthFromEnv reads credentials from the environment. ATLASSIAN_API_LOGIN /
// ATLASSIAN_API_KEY are accepted as aliases (the names the leakhunt collector used) so existing
// setups keep working. Secrets are taken from the environment only — never a flag — per policy.
func atlassianAuthFromEnv() atlassian.Auth {
	return atlassian.Auth{
		Email: firstEnv("ATLASSIAN_EMAIL", "ATLASSIAN_API_LOGIN"),
		Token: firstEnv("ATLASSIAN_API_TOKEN", "ATLASSIAN_API_KEY"),
		PAT:   os.Getenv("ATLASSIAN_PAT"),
		User:  os.Getenv("ATLASSIAN_USER"),
		Pass:  os.Getenv("ATLASSIAN_PASSWORD"),
	}
}

func firstEnv(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}
