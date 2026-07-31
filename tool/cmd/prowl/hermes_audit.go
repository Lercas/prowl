package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/Lercas/prowl/tool/internal/hermesaudit"
)

type hermesAuditList []string

func (s *hermesAuditList) String() string { return strings.Join(*s, ",") }

func (s *hermesAuditList) Set(value string) error {
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			*s = append(*s, item)
		}
	}
	return nil
}

// cmdHermesAudit is intentionally a small command-specific parser. Passing its
// flags through parseCommon would make a safe, redacted report accidentally
// inherit scan-only options such as --show-secrets.
func cmdHermesAudit(args []string) int {
	fs := flag.NewFlagSet("hermes-audit", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var targets hermesAuditList
	var providers hermesAuditList
	var targetsFile, output string
	var timeout time.Duration
	var retries, concurrency int
	var authorized, active, passive bool
	fs.Var(&targets, "target", "literal IP or IP:port (repeatable or comma-separated)")
	fs.Var(&providers, "provider", "passive provider(s): censys,shodan,fofa,zoomeye,leakix")
	fs.StringVar(&targetsFile, "targets", "", "newline-delimited IP inventory")
	fs.StringVar(&output, "output", "", "write JSON to this file instead of stdout")
	fs.StringVar(&output, "o", "", "alias for --output")
	fs.DurationVar(&timeout, "timeout", 12*time.Second, "per-request timeout")
	fs.IntVar(&retries, "max-retries", 2, "bounded retries after provider rate limits/server errors (0..5)")
	fs.IntVar(&concurrency, "concurrency", 2, "target concurrency (capped at 8)")
	fs.BoolVar(&authorized, "authorized", false, "REQUIRED: attest that every target is in your authorized inventory")
	fs.BoolVar(&active, "active", true, "probe status/schema and bounded root dashboard assets")
	fs.BoolVar(&passive, "passive", true, "query configured providers for the exact IP only")
	if err := fs.Parse(normalizeHermesArgs(args)); err != nil {
		return 2
	}
	if !authorized {
		fmt.Fprintln(os.Stderr, "refusing: pass --authorized to attest that every target is in your scope")
		return 2
	}
	if retries < 0 || retries > 5 || timeout <= 0 {
		fmt.Fprintln(os.Stderr, "--max-retries must be 0..5 and --timeout must be positive")
		return 2
	}
	if targetsFile != "" {
		data, err := os.ReadFile(targetsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read --targets: %v\n", err)
			return 2
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
	}
	targets = append(targets, fs.Args()...)
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "usage: prowl hermes-audit [IP ...] --authorized [--targets FILE]")
		return 2
	}
	for i := range providers {
		providers[i] = strings.ToLower(providers[i])
	}
	sort.Strings(providers)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
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
	if output == "" {
		_, _ = os.Stdout.Write(data)
		return 0
	}
	if err := os.WriteFile(output, data, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "write hermes report: %v\n", err)
		return 2
	}
	return 0
}

// normalizeHermesArgs lets operators put positional IPs before or after flags,
// matching the rest of Prowl's CLI instead of the standard flag package's
// "stop at first positional" behavior.
func normalizeHermesArgs(args []string) []string {
	valueFlags := map[string]bool{
		"--target": true, "--provider": true, "--targets": true, "--output": true, "-o": true,
		"--timeout": true, "--max-retries": true, "--concurrency": true,
	}
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		name := a
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name = name[:eq]
		}
		if valueFlags[name] && !strings.Contains(a, "=") && i+1 < len(args) {
			flags = append(flags, args[i+1])
			i++
		}
	}
	return append(flags, positional...)
}
