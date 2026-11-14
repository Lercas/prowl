package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"

	"github.com/Lercas/prowl/tool/internal/hermesaudit"
	"github.com/Lercas/prowl/tool/internal/targetlist"
)

// cmdHermesAudit uses an isolated schema: scan-only options such as --show-secrets
// are never accepted by this authorized inventory command.
func cmdHermesAudit(args []string) int {
	c, rest, err := parseCommand("hermes-audit", args)
	if err != nil {
		return commandParseError(err)
	}
	targets, providers := c.cmd.targets, c.cmd.providers
	targetsFile, output := c.cmd.targetsFile, c.output
	timeout, retries, concurrency := c.timeout, c.cmd.maxRetries, c.cmd.concurrency
	authorized, active, passive := c.cmd.authorized, c.cmd.active, c.cmd.passive
	if !authorized {
		fmt.Fprintln(os.Stderr, "refusing: pass --authorized to attest that every target is in your scope")
		return 2
	}
	if retries < 0 || retries > 5 || timeout <= 0 {
		fmt.Fprintln(os.Stderr, "--max-retries must be 0..5 and --timeout must be positive")
		return 2
	}
	if targetsFile != "" {
		loaded, err := targetlist.Read(targetsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read --targets: %v\n", err)
			return 2
		}
		targets = append(targets, loaded...)
	}
	targets = append(targets, rest...)
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "usage: prowl hermes-audit [IP ...] --authorized [--targets FILE]")
		return 2
	}
	for i := range providers {
		providers[i] = strings.ToLower(providers[i])
	}
	sort.Strings(providers)

	ctx, stop := signal.NotifyContext(context.Background(), scanSignals()...)
	defer stop()
	reports, err := hermesaudit.Audit(ctx, targets, hermesaudit.Options{
		Timeout:        timeout,
		MaxRetries:     retries,
		Providers:      providers,
		IncludeActive:  active,
		IncludePassive: passive,
		Concurrency:    concurrency,
		Authorized:     authorized,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "hermes audit: %v\n", err)
		return 2
	}
	envelope := map[string]any{
		"tool":       "prowl hermes-audit",
		"version":    version,
		"authorized": true,
		"reports":    reports,
		"notes": []string{
			"Only exact input IPs were queried.",
			"Target response bodies and provider banners are not serialized.",
			"No target provider credential values or cookies were supplied; masked /api/env, credential-pool, and custom-endpoint metadata may be checked only when Hermes exposes its own session-token marker; /api/env/reveal is never requested.",
			"Rate limits are honored with bounded backoff; no proxy or Tor rotation is used.",
		},
	}
	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode hermes report: %v\n", err)
		return 2
	}
	data = append(data, '\n')
	if err := writeArtifactBytes(output, data, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "write hermes report: %v\n", err)
		return 2
	}
	return 0
}
