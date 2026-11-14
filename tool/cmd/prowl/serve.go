package main

import (
	"fmt"
	"os"

	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/scan"
	"github.com/Lercas/prowl/tool/internal/server"
)

func cmdServe(args []string) int {
	c, _, err := parseCommand("serve", args)
	if err != nil {
		return commandParseError(err)
	}
	if code := rejectUnsupportedOCR(c, "serve"); code != 0 {
		return code
	}
	setupLogging(c)
	if c.verify || c.verifiedOnly || c.failOnVerified {
		logx.Error("verify setup failed", "err", "serve does not support live verification (--verify/--verified-only/--fail-on-verified); use scan --verify")
		return 2
	}
	// Default to loopback: the server is unauthenticated, so the operator must opt into network
	// exposure with an explicit --addr 0.0.0.0:PORT (behind auth/a proxy).
	addr, maxConc := c.cmd.addr, c.cmd.maxConcurrent
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
	// Load the rule templates too (as scan and lsp do) so the HTTP worker has the same coverage as the
	// CLI, not just the embedded taxonomy detectors.
	eng, err := loadConfiguredEngine(c, cfg)
	if err != nil {
		logx.Error("rule setup failed", "err", err)
		return 2
	}
	ctx, stop := rootContext(c)
	defer stop()
	if err := server.Serve(ctx, addr, server.New(scan.New(scan.Options{Detector: det, Rules: eng, Allow: cfg.Allowed}), maxConc)); err != nil {
		logx.Error("server error", "err", err)
		return 2
	}
	return 0
}
