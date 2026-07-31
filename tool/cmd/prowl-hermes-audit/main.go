// prowl-hermes-audit is a standalone, bounded wrapper around the Hermes audit
// package. It is kept separate from the main CLI while the Prowl command tree
// is under active change in this checkout.
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
	"github.com/Lercas/prowl/tool/internal/safehttp"
)

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(value string) error {
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			*s = append(*s, item)
		}
	}
	return nil
}

func main() {
	var targetsFile string
	var targets stringList
	var providers stringList
	var output string
	var timeout time.Duration
	var retries int
	var concurrency int
	var authorized bool
	var active, passive bool
	flag.Var(&targets, "target", "literal IP or IP:port (repeatable or comma-separated)")
	flag.Var(&providers, "provider", "passive provider(s): censys,shodan,fofa,zoomeye,leakix")
	flag.StringVar(&targetsFile, "targets", "", "newline-delimited IP inventory")
	flag.StringVar(&output, "output", "", "write JSON to this file instead of stdout")
	flag.DurationVar(&timeout, "timeout", 12*time.Second, "per-request timeout")
	flag.IntVar(&retries, "max-retries", 2, "bounded retries after provider rate limits/server errors (0..5)")
	flag.IntVar(&concurrency, "concurrency", 2, "target concurrency (capped at 8)")
	flag.BoolVar(&authorized, "authorized", false, "REQUIRED: attest that every target is in your authorized inventory")
	flag.BoolVar(&active, "active", true, "probe status/schema and bounded root dashboard assets")
	flag.BoolVar(&passive, "passive", true, "query configured providers for the exact IP only")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: prowl-hermes-audit --authorized --targets ips.txt [options]")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "Provider credentials are read from environment variables only; target secret values are never requested or stored (masked metadata may be checked when Hermes exposes its own session marker).")
	}
	flag.Parse()

	if !authorized {
		fatal("refusing to run: pass --authorized for an owned/engaged asset inventory")
	}
	if retries < 0 || retries > 5 {
		fatal("--max-retries must be between 0 and 5")
	}
	if timeout <= 0 {
		fatal("--timeout must be positive")
	}
	if targetsFile != "" {
		data, err := os.ReadFile(targetsFile)
		if err != nil {
			fatalf("read --targets: %v", err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			targets = append(targets, line)
		}
	}
	if len(targets) == 0 {
		fatal("provide at least one --target or --targets file")
	}
	if len(providers) > 0 {
		for i := range providers {
			providers[i] = strings.ToLower(providers[i])
		}
		sort.Strings(providers)
	}

	// The existing Prowl SSRF guard remains the default. Set
	// PROWL_ALLOW_PRIVATE_IPS only from a controlled internal runner, never as
	// a proxy-rotation or public-scan escape hatch.
	safehttp.AllowPrivate.Store(os.Getenv("PROWL_ALLOW_PRIVATE_IPS") != "")
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
		fatalf("audit: %v", err)
	}

	var out interface{} = map[string]interface{}{
		"tool":       "prowl-hermes-audit",
		"version":    "0.1",
		"authorized": true,
		"reports":    reports,
		"notes": []string{
			"Only exact input IPs were queried.",
			"Target response bodies and provider banners are not serialized.",
			"No target provider credential values or cookies were supplied; masked /api/env, credential-pool, and custom-endpoint metadata may be checked only when Hermes exposes its own session-token marker; /api/env/reveal is never requested.",
			"Rate limits are honored with bounded backoff; no proxy or Tor rotation is used.",
		},
	}

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		fatalf("encode report: %v", err)
	}
	data = append(data, '\n')
	if output == "" {
		_, _ = os.Stdout.Write(data)
		return
	}
	if err := os.WriteFile(output, data, 0o600); err != nil {
		fatalf("write report: %v", err)
	}
}

func fatal(message string) {
	fatalf("%s", message)
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "prowl-hermes-audit: "+format+"\n", args...)
	os.Exit(2)
}
