// prowl-hermes-audit is a standalone, bounded wrapper around the Hermes audit
// package. It is kept separate from the main CLI while the Prowl command tree
// is under active change in this checkout.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	"github.com/Lercas/prowl/tool/internal/hermesaudit"
	"github.com/Lercas/prowl/tool/internal/localfile"
	"github.com/Lercas/prowl/tool/internal/safehttp"
	"github.com/Lercas/prowl/tool/internal/targetlist"
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
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("prowl-hermes-audit", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var targetsFile string
	var targets stringList
	var providers stringList
	var output string
	var timeout time.Duration
	var retries int
	var concurrency int
	var authorized bool
	var active, passive bool
	fs.Var(&targets, "target", "literal IP or IP:port (repeatable or comma-separated)")
	fs.Var(&providers, "provider", "passive provider(s): censys,shodan,fofa,zoomeye,leakix")
	fs.StringVar(&targetsFile, "targets", "", "newline-delimited IP inventory")
	fs.StringVar(&output, "output", "", "write JSON to this file instead of stdout")
	fs.DurationVar(&timeout, "timeout", 12*time.Second, "per-request timeout")
	fs.IntVar(&retries, "max-retries", 2, "bounded retries after provider rate limits/server errors (0..5)")
	fs.IntVar(&concurrency, "concurrency", 2, "target concurrency (capped at 8)")
	fs.BoolVar(&authorized, "authorized", false, "REQUIRED: attest that every target is in your authorized inventory")
	fs.BoolVar(&active, "active", true, "probe status/schema and bounded root dashboard assets")
	fs.BoolVar(&passive, "passive", true, "query configured providers for the exact IP only")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: prowl-hermes-audit --authorized --targets ips.txt [options]")
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, "Provider credentials are read from environment variables only; target secret values are never requested or stored (masked metadata may be checked when Hermes exposes its own session marker).")
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if !authorized {
		return fatal("refusing to run: pass --authorized for an owned/engaged asset inventory")
	}
	if retries < 0 || retries > 5 {
		return fatal("--max-retries must be between 0 and 5")
	}
	if timeout <= 0 {
		return fatal("--timeout must be positive")
	}
	if targetsFile != "" {
		loaded, err := targetlist.Read(targetsFile)
		if err != nil {
			return fatalf("read --targets: %v", err)
		}
		targets = append(targets, loaded...)
	}
	if len(targets) == 0 {
		return fatal("provide at least one --target or --targets file")
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
	ctx, stop := signal.NotifyContext(context.Background(), auditSignals()...)
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
		return fatalf("audit: %v", err)
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
		return fatalf("encode report: %v", err)
	}
	data = append(data, '\n')
	if err := writeReportOutput(output, data); err != nil {
		return fatalf("write report: %v", err)
	}
	return 0
}

func writeReportOutput(path string, raw []byte) error {
	if path != "" {
		return localfile.WriteAtomicBytes(path, raw, 0o600)
	}
	n, err := os.Stdout.Write(raw)
	if err == nil && n != len(raw) {
		return io.ErrShortWrite
	}
	return err
}

func fatal(message string) int {
	return fatalf("%s", message)
}

func fatalf(format string, args ...interface{}) int {
	fmt.Fprintf(os.Stderr, "prowl-hermes-audit: "+format+"\n", args...)
	return 2
}
