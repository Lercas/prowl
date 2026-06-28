// Command prowl is a fast, configurable secret scanner (filesystem + domain recon).
package main

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Lercas/prowl/tool/internal/config"
	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/doctor"
	"github.com/Lercas/prowl/tool/internal/domain"
	"github.com/Lercas/prowl/tool/internal/forge"
	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/lsp"
	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/post"
	"github.com/Lercas/prowl/tool/internal/report"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/safehttp"
	"github.com/Lercas/prowl/tool/internal/saferegex"
	"github.com/Lercas/prowl/tool/internal/scan"
	"github.com/Lercas/prowl/tool/internal/server"
	"github.com/Lercas/prowl/tool/internal/source"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
	"github.com/Lercas/prowl/tool/internal/verify"
)

const usage = `prowl — fast, configurable secret scanner

USAGE:
  prowl scan [path...]        scan files/dirs (default: .); use '-' to scan stdin
  prowl compare [path...]     show how many detector candidates Prowl's ML suppresses as noise
                              (auto-loads .gitleaks.toml, so it scores your gitleaks rules' findings)
  prowl repo <git-url>        clone & scan a remote repo (GitHub/GitLab/Bitbucket/any git URL)
  prowl org <platform>:<name> clone & scan every repo in a GitHub org / GitLab group / Bitbucket workspace
  prowl image <ref>           pull & scan a container image — every layer's files + config (env/labels/history)
  prowl mobile <apk|ipa|url>   unpack & scan an Android/iOS app (resources + dex/arsc/.so strings)
  prowl bucket <s3://|gs://>   download & scan a cloud storage prefix (via the aws / gcloud CLI)
  prowl domain <domain>       scan a domain: HTML + __NEXT_DATA__/state blobs + referenced JS + maps
  prowl jira <base-url>       scan a Jira instance (Cloud/Server/DC) across every issue version from the first
  prowl confluence <base-url> scan a Confluence instance (Cloud/Server/DC) across every page version
  prowl serve [--addr :8080]  run as a stateless HTTP scan worker (horizontally scalable)
  prowl lsp                   run as a Language Server (in-editor secret highlighting)
  prowl mcp                   run as an MCP server (AI agents call scans as tools)
  prowl doctor                self-diagnose the install (taxonomy/checksums/detection/config/git)
  prowl detectors             list detector types
  prowl rules export -o FILE  write the built-in rules to an editable file (rules live outside the binary)
  prowl rules list   [DIR]    list active rules + provenance (built-in / gitleaks / trufflehog / template)
  prowl rules validate [DIR]  lint nuclei-style templates (parse / RE2 / fields); exit 1 on error
  prowl rules update [--source SRC]   install/refresh templates into ~/.prowl/rules (bundled, or a dir / git URL)
  prowl rules stats  [DIR]    template counts by category / severity / tag
  prowl verifiers list|validate|update|manifest [DIR]  manage data-driven live-verifiers (integrity-checked YAML)
                             update of a third-party --source needs a MANIFEST.sha256 or --allow-unsigned;
                             'manifest' (re)generates MANIFEST.sha256 to bless a verifier dir's contents
  prowl version              show binary + installed rule/verifier versions

  Once installed (rules/verifiers update), 'scan' auto-loads ~/.prowl/rules and '--verify' uses
  ~/.prowl/verifiers — no --rules-dir/--verifiers flags needed. PROWL_HOME overrides the dir.

  env: PROWL_HOME (install dir) · GITHUB_TOKEN / GITLAB_TOKEN / BITBUCKET_TOKEN (org auth) ·
       PROWL_ALLOW_PRIVATE_IPS=1 (let --verify/domain reach internal/loopback IPs) · NO_COLOR

  scan also supports: --staged (git staged files) | --since <rev> (git diff) | --history (all blobs)
                      --baseline FILE | --write-baseline FILE | --config FILE | --output FILE

  gitleaks migration is automatic: in a repo with a .gitleaks.toml its rules are loaded, a
  .gitleaksignore suppresses the same findings, and the gitleaks:allow inline comment is honored.

scan flags:
  --format pretty|json|sarif  (default pretty)
  --fail-on info|low|medium|high|critical   exit 1 if any finding >= level
  --exclude substr            (repeatable) skip paths containing substr
  --max-size BYTES            skip files larger (default 10485760)
  --workers N                 concurrency (default NumCPU)
  --timeout DUR               abort after e.g. 30s/5m (partial results reported)
  --taxonomy PATH             override embedded taxonomy
  --rules FILE                (repeatable) import external rules — gitleaks .toml / trufflehog .yaml / prowl yaml
  --rules-only                use ONLY --rules files (no built-in taxonomy) — pure gitleaks/trufflehog drop-in
  --rules-dir DIR             (repeatable) load nuclei-style rule templates from a directory
  --tags T1,T2                run only templates with any of these tags
  --exclude-tags T1,T2        skip templates with any of these tags
  --rule-severity S1,S2       run only templates of these severities
  --min-confidence F          report only findings with confidence >= F (0..1)
  --min-severity LEVEL        report only findings >= LEVEL (filters built-ins too, unlike --rule-severity)
  --disable T1,T2             drop findings of these detector types
  --no-dedupe                 report every occurrence (default: collapse the same secret per file)
  --verify                    confirm findings are LIVE via the provider (data-driven verifiers/)
  --verified-only             report ONLY provider-confirmed-live secrets (strongest FP filter)
  --verifiers DIR             (repeatable) verifier YAML dir (default ./verifiers)

output / logging:
  -s, --silence               no output at all — CI mode, exit code is the only signal
  -q, --quiet                 only warnings+errors (still prints the report)
  -v, --verbose               debug logging
  --log-format console|json   structured JSON logs for CI/aggregation (default console)
  --no-color                  disable ANSI colour (also honours NO_COLOR)

domain flags:
  --authorized               REQUIRED: confirm you are authorized to scan this domain
  --recon                    opt-in DEEP sweep: subdomains (crt.sh) + wayback history
  --max-assets N             cap fetched assets (default 300)
  --format ...               (as above)

  By default the domain scan is focused on the host itself: its HTML, inline state blobs
  (__NEXT_DATA__, __NUXT__, __INITIAL_STATE__, __APOLLO_STATE__, window.env, …), and the
  JavaScript bundles + source-maps the page references. No subdomain enumeration unless --recon.

EXAMPLES:
  prowl scan .                                        scan the current directory
  prowl scan src --rules-dir rules/ --tags aws        run extra rule templates, AWS only
  prowl scan . --verify --verified-only               keep only provider-confirmed-live secrets
  prowl scan --staged --fail-on high                  pre-commit / CI gate
  prowl rules validate rules/                         lint your rule templates
  prowl domain example.com --authorized               scan a live site you own

Run 'prowl <command> --help' for command-specific flags and examples.
`

// version is the binary version, stamped at release via -ldflags; "dev" for a plain go build.
var version = "dev"

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Print(usage)
		os.Exit(2)
	}
	// Block outbound connections to private/loopback IPs (SSRF guard) by default; opt out explicitly.
	safehttp.AllowPrivate.Store(os.Getenv("PROWL_ALLOW_PRIVATE_IPS") != "")
	cmd := args[0]
	if cmd == "version" || cmd == "--version" || cmd == "-V" {
		printVersions()
		return
	}
	if cmd == "help" || cmd == "-h" || cmd == "--help" {
		topic := ""
		if len(args) > 1 {
			topic = args[1]
		}
		helpFor(topic)
		return
	}
	if hasHelpFlag(args[1:]) { // prowl <cmd> --help
		helpFor(cmd)
		return
	}
	switch cmd {
	case "scan":
		os.Exit(cmdScan(args[1:]))
	case "compare":
		os.Exit(cmdCompare(args[1:]))
	case "repo":
		os.Exit(cmdRepo(args[1:]))
	case "org":
		os.Exit(cmdOrg(args[1:]))
	case "image":
		os.Exit(cmdImage(args[1:]))
	case "mobile":
		os.Exit(cmdMobile(args[1:]))
	case "bucket":
		os.Exit(cmdBucket(args[1:]))
	case "domain":
		os.Exit(cmdDomain(args[1:]))
	case "jira":
		os.Exit(cmdJira(args[1:]))
	case "confluence":
		os.Exit(cmdConfluence(args[1:]))
	case "serve":
		os.Exit(cmdServe(args[1:]))
	case "config":
		os.Exit(cmdConfig(args[1:]))
	case "doctor":
		os.Exit(cmdDoctor(args[1:]))
	case "detectors":
		os.Exit(cmdDetectors())
	case "rules":
		os.Exit(cmdRules(args[1:]))
	case "verifiers":
		os.Exit(cmdVerifiers(args[1:]))
	case "lsp":
		if err := lsp.Serve(); err != nil {
			fmt.Fprintln(os.Stderr, "lsp error:", err)
			os.Exit(2)
		}
	case "mcp":
		os.Exit(cmdMCP(args[1:]))
	default:
		dieUnknownCommand(cmd)
	}
}

// loadDetector builds the detector from the taxonomy, external --rules, and config overrides.
func loadDetector(c commonFlags, cfg *config.Config) (*detect.Detector, *taxonomy.Taxonomy, error) {
	var tax *taxonomy.Taxonomy
	var err error
	switch {
	case c.rulesOnly:
		tax = &taxonomy.Taxonomy{}
	case c.taxonomy != "":
		tax, err = taxonomy.Load(c.taxonomy)
	default:
		tax, err = taxonomy.LoadDefault()
	}
	if err != nil {
		return nil, nil, err
	}
	ruleFiles := c.rules
	// gitleaks migration: with no explicit --rules, auto-load a .gitleaks.toml from the working dir so
	// its rules join the taxonomy and their IDs line up with any .gitleaksignore.
	if len(ruleFiles) == 0 && !c.rulesOnly {
		for _, name := range []string{".gitleaks.toml", "gitleaks.toml"} {
			if _, err := os.Stat(name); err == nil {
				ruleFiles = append(ruleFiles, name)
				logx.Info("auto-loaded gitleaks config", "file", name)
				break
			}
		}
	}
	for _, rp := range ruleFiles {
		ext, al, err := taxonomy.LoadAny(rp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "rules %q: %v\n", rp, err)
			continue
		}
		tax.Types = append(tax.Types, ext.Types...)
		if cfg != nil && al != nil {
			cfg.MergeAllowlist(al.Regexes, al.Paths, al.StopWords)
		}
		logx.Info("imported external rules", "file", rp, "rules", len(ext.Types), "skipped", len(ext.Skipped))
	}
	if cfg != nil {
		origTypes := len(tax.Types)
		kept := tax.Types[:0]
		for _, t := range tax.Types {
			if cfg.TypeEnabled(t.ID) {
				kept = append(kept, t)
			}
		}
		tax.Types = kept
		// detectors.enable is restrict-to-only, so an enable list matching no real type disables every
		// taxonomy detector — warn rather than scan with zero detectors and exit 0 "clean".
		if len(cfg.Detectors.Enable) > 0 && origTypes > 0 && len(tax.Types) == 0 {
			logx.Warn("detectors.enable matched no known type — ALL taxonomy detectors are disabled",
				"enable", cfg.Detectors.Enable)
		}
		for _, cr := range cfg.Detectors.Custom {
			// saferegex caps an attacker-controlled custom-rule regex on the executing path (a bare
			// regexp.Compile would let a packed bomb OOM the scan before any finding).
			re, err := saferegex.Compile(cr.Regex)
			if err != nil {
				fmt.Fprintf(os.Stderr, "custom rule %q: bad regex: %v\n", cr.ID, err)
				continue
			}
			cat := cr.Category
			if cat == "" {
				cat = "generic"
			}
			tax.Types = append(tax.Types, taxonomy.SecretType{
				ID: cr.ID, Name: cr.ID, Category: cat,
				Detection: taxonomy.Detection{Regex: cr.Regex}, RE: re,
			})
		}
	}
	return detect.New(tax), tax, nil
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// loadEngine builds the template engine from --rules-dir, or nil if none was given. --rules-only
// isolates it too: only an explicit --rules-dir is loaded, never the auto-discovered ~/.prowl/rules.
func loadEngine(c commonFlags) *rules.Engine {
	dirs := discoverRulesDirs(c.rulesDir)
	if c.rulesOnly {
		dirs = c.rulesDir // ONLY what the user passed; never the auto-discovered installed dir
	}
	if len(dirs) == 0 {
		return nil
	}
	eng, err := rules.Load(dirs...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rules-dir: %v\n", err)
	}
	eng.Filter(rules.FilterOpts{
		Tags:        splitCSV(c.tags),
		ExcludeTags: splitCSV(c.excludeTags),
		Severities:  splitCSV(c.ruleSeverity),
	})
	logx.Info("loaded rule templates", "count", eng.Len())
	return eng
}

// loadVerifySet builds the verifier set from --verifiers dirs when --verify is on. --verify with no
// verifiers installed is an error (a silent unverified scan + --verified-only would drop everything).
func loadVerifySet(c commonFlags) (*verify.Set, error) {
	if !c.verify {
		return nil, nil
	}
	dirs := discoverVerifierDirs(c.verifiers)
	if len(dirs) == 0 {
		return nil, fmt.Errorf("--verify needs verifiers, but none are installed — run 'prowl verifiers update' (or pass --verifiers DIR)")
	}
	vs, err := verify.Load(c.verifyTimeout, dirs...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verifiers: %v\n", err) // a partial parse failure: warn but use what loaded
	}
	if vs == nil || vs.Count() == 0 {
		return nil, fmt.Errorf("--verify needs verifiers, but the loaded set is empty — run 'prowl verifiers update'")
	}
	logx.Info("live-verification enabled", "verifiers", vs.Count())
	return vs, nil
}

// keepVerified drops findings that were not confirmed live (--verified-only).
func keepVerified(fs []model.Finding) []model.Finding {
	out := fs[:0]
	inconclusive, unverifiable := 0, 0
	for _, f := range fs {
		switch {
		case f.Verified != nil && *f.Verified: // provider-confirmed live
			out = append(out, f)
		case f.Verified == nil && strings.HasPrefix(f.Rationale, "verification inconclusive"):
			// the verifier errored (timeout/rate-limit/WAF) — keep a possibly-live secret rather than
			// turn a transient failure into a false-negative.
			inconclusive++
			out = append(out, f)
		case f.Verified == nil && model.SeverityOrder[f.Severity] >= model.SeverityOrder["high"]:
			// no verifier for this type — "couldn't check" is not "confirmed dead", so keep high/critical
			// (with a warning); low/medium unverifiable findings are still dropped for precision.
			unverifiable++
			out = append(out, f)
		}
		// else: provider-confirmed dead, or a low/medium finding with no verifier — dropped
	}
	if inconclusive > 0 {
		logx.Warn("verified-only kept findings whose verification was inconclusive (verifier errored, not confirmed dead)", "count", inconclusive)
	}
	if unverifiable > 0 {
		logx.Warn("verified-only kept high/critical findings with no verifier (could not be checked, not confirmed dead)", "count", unverifiable)
	}
	return out
}

type commonFlags struct {
	format, failOn, taxonomy, config, output string
	since, baseline, writeBaseline           string
	logFormat, logLevel                      string
	staged, history                          bool
	silence, quiet, verbose, noColor         bool
	rulesOnly                                bool
	noAutoConfig                             bool    // repo/org: don't honor the scanned tree's own .prowl.yaml
	dedupe                                   bool    // collapse the same secret found repeatedly in one file (default on)
	maxPerFile                               int     // cap generic findings per file (data-file guard; 0 = off)
	mlEmbed                                  bool    // run the L2 model in-process (embedded), no sidecar
	mlModel                                  string  // load the in-process model from this file (implies --ml)
	mlURL                                    string  // ML sidecar URL for the L2 secret/not-secret stage (off if empty)
	mlThreshold                              float64 // drop a non-checksum finding the ML scores below this
	mlThresholdSet                           bool    // user passed --ml-threshold (so config must not override it)
	minConfidence                            float64 // report-time: drop findings below this confidence (0 = off)
	minSeverity                              string  // report-time: drop findings below this severity (incl. built-ins)
	disable                                  string  // report-time: comma-separated detector types to drop
	rules                                    []string
	rulesDir                                 []string
	tags, excludeTags, ruleSeverity          string
	verify, verifiedOnly                     bool
	showSecrets                              bool // --show-secrets: emit the full unredacted value
	failOnVerified                           bool // gate (exit 1) only on a provider-confirmed-LIVE secret
	verifiers                                []string
	verifyTimeout                            time.Duration
	exclude                                  []string
	maxSize                                  int64
	workers                                  int
	timeout                                  time.Duration
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// setupLogging configures the global logger.
// Precedence: --silence > --log-level > --verbose > --quiet > info.
func setupLogging(c commonFlags) {
	level := slog.LevelInfo
	switch {
	case c.silence:
		level = logx.LevelSilent
	case c.logLevel != "":
		_ = level.UnmarshalText([]byte(c.logLevel))
	case c.verbose:
		level = slog.LevelDebug
	case c.quiet:
		level = slog.LevelWarn
	}
	color := !c.noColor && os.Getenv("NO_COLOR") == "" && c.logFormat != "json" && isTTY(os.Stderr)
	logx.Setup(logx.Options{Level: level, Format: c.logFormat, Color: color})
}

// rootContext returns a context cancelled on Ctrl-C / SIGTERM and, with --timeout, after that
// deadline. Caller must defer the stop func.
func rootContext(c commonFlags) (context.Context, context.CancelFunc) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	if c.timeout > 0 {
		tctx, cancel := context.WithTimeout(ctx, c.timeout)
		return tctx, func() { cancel(); stop() }
	}
	return ctx, stop
}

// writeReport sends findings to the --output file or stdout. A write failure exits non-zero rather
// than leave an empty report CI would read as "clean".
func writeReport(c commonFlags, findings []model.Finding) {
	if c.output != "" {
		if err := writeReportFile(c.output, findings, c.format); err != nil {
			logx.Error("cannot write output file", "path", c.output, "err", err)
			os.Exit(2)
		}
		logx.Info("report written", "findings", len(findings), "path", c.output)
		return
	}
	if c.silence && c.format == "pretty" {
		return // --silence suppresses the human report; an explicit --format json/sarif still writes for CI
	}
	color := !c.noColor && os.Getenv("NO_COLOR") == "" && isTTY(os.Stdout)
	report.Write(os.Stdout, findings, c.format, color)
}

// writeReportFile writes the report to path, returning any error. It opens with O_NOFOLLOW so a
// symlink planted at the target isn't followed, and removes the file if the write fails after
// create/truncate so a stale empty report can't be mistaken for "no findings".
func writeReportFile(path string, findings []model.Finding, format string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|oNoFollow, 0o644)
	if err != nil {
		return err
	}
	if err := writeAndClose(f, findings, format); err != nil {
		_ = os.Remove(path) // best-effort: drop the truncated file we just created
		return err
	}
	return nil
}

// writeAndClose renders the report into f and closes f, surfacing whichever error comes first (a
// buffered flush can fail on a full disk only at Close).
func writeAndClose(f *os.File, findings []model.Finding, format string) error {
	if err := report.Write(f, findings, format, false); err != nil { // never colour a file
		_ = f.Close()
		return err
	}
	return f.Close()
}

// summarize logs a one-line scan summary grouped by severity (suppressed by --silence).
func summarize(findings []model.Finding, dur time.Duration) {
	bySev := map[string]int{}
	live, rejected, attempted := 0, 0, 0
	for _, f := range findings {
		bySev[f.Severity]++
		if f.Verified != nil {
			attempted++
			if *f.Verified {
				live++
			} else {
				rejected++
			}
		}
	}
	args := []any{
		"findings", len(findings), "critical", bySev["critical"], "high", bySev["high"],
		"medium", bySev["medium"], "low", bySev["low"], "took", dur.Round(time.Millisecond),
	}
	if attempted > 0 {
		args = append(args, "verified_live", live, "rejected", rejected)
	}
	logx.Info("scan complete", args...)
}

// loadConfig resolves the config file (--config or auto-discovered) and applies its defaults for
// any value not set on the command line.
func loadConfig(c *commonFlags) *config.Config {
	if c.failOnVerified && !c.verify {
		// Without --verify nothing is ever confirmed live, so the gate would always pass — require it.
		fmt.Fprintln(os.Stderr, "--fail-on-verified needs --verify (it gates on provider-confirmed-live secrets)")
		os.Exit(2)
	}
	var cfg *config.Config
	if c.config != "" {
		var err error
		if cfg, err = config.Load(c.config); err != nil {
			// An explicit --config that fails to load must abort, not fall through to an auto-discovered
			// (possibly untrusted) in-repo .prowl.yaml.
			fmt.Fprintln(os.Stderr, "config error:", err)
			os.Exit(2)
		}
	}
	if cfg == nil && c.noAutoConfig {
		// repo/org scan an untrusted tree — never honor its own .prowl.yaml; only --config is trusted.
		cfg = &config.Config{}
	}
	if cfg == nil {
		cfg = config.Discover()
		// A scanned repo's own .prowl.yaml is attacker-controlled (a fork PR, a dependency). Warn if it
		// suppresses detection so a kill-switch can't silently blind the scan; pass --config to vouch.
		if p := cfg.LoadedFrom(); p != "" {
			// Warn on every channel that can hide a finding: disabling a detector, allowlisting,
			// detection/ML tuning, and a restrict-to-only `enable` list (which narrows or zeroes
			// detection). `exclude` (path scoping) is excluded as noise.
			allow := len(cfg.Allowlist.Regexes) + len(cfg.Allowlist.Values) + len(cfg.Allowlist.StopWords) + len(cfg.Allowlist.Paths)
			tuning := cfg.Detection.GenericEntropyMin > 0 || cfg.Detection.PlaceholderMaxEntropy > 0 ||
				cfg.Detection.MaxMatchesPerFile > 0 || cfg.Performance.MLThreshold > 0
			enable := len(cfg.Detectors.Enable)
			if len(cfg.Detectors.Disable) > 0 || allow > 0 || tuning || enable > 0 {
				logx.Warn("in-repo .prowl.yaml suppresses detection — review if scanning untrusted code",
					"path", p, "disabled_detectors", len(cfg.Detectors.Disable), "allowlist_rules", allow,
					"detection_tuning", tuning, "enable_only", enable)
			}
		}
	}
	for _, is := range cfg.Issues() { // surface bad allowlist/custom regexes instead of silently dropping them
		logx.Warn("config issue", "detail", is)
	}
	c.exclude = append(c.exclude, cfg.Exclude...)
	if c.format == "pretty" && cfg.Output.Format != "" {
		c.format = cfg.Output.Format
	}
	if c.failOn == "" {
		c.failOn = cfg.Output.FailOn
	}
	if c.maxSize == 10<<20 && cfg.Performance.MaxSize > 0 {
		c.maxSize = cfg.Performance.MaxSize
	}
	if c.workers == 0 && cfg.Performance.Workers > 0 {
		c.workers = cfg.Performance.Workers
	}
	// Apply config-file detection thresholds + operational limits (zero/empty keeps the default; these
	// are process-wide). Flags win: the ML threshold and verify timeout come from config only if unset.
	detect.ApplyTuning(cfg.Detection.GenericEntropyMin, cfg.Detection.PlaceholderMaxEntropy, cfg.Detection.MaxMatchesPerFile)
	forge.SetMaxPages(cfg.Limits.OrgMaxPages)
	verify.SetConcurrency(cfg.Performance.VerifyConcurrency)
	scan.SetRevealSecrets(c.showSecrets)
	if !c.mlThresholdSet && cfg.Performance.MLThreshold > 0 {
		c.mlThreshold = cfg.Performance.MLThreshold
	}
	if c.verifyTimeout == 0 {
		if d, err := time.ParseDuration(cfg.Performance.VerifyTimeout); err == nil && d > 0 {
			c.verifyTimeout = d
		}
	}
	if d, err := time.ParseDuration(cfg.Limits.CloneTimeout); err == nil && d > 0 {
		source.SetCloneTimeout(d)
	}
	return cfg
}

// parseByteSize parses a byte size: a plain integer, or an integer with a KB/MB/GB (or K/M/G, optional
// trailing B) base-1024 suffix, case-insensitive. It rejects trailing garbage (fmt.Sscan would
// partial-parse "10MB" to 10 bytes, skipping every file and exiting 0).
func parseByteSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	mult := int64(1)
	for _, u := range []struct { // longest suffix first so "KB" wins over a trailing "B"
		suf string
		m   int64
	}{{"KB", 1 << 10}, {"MB", 1 << 20}, {"GB", 1 << 30}, {"K", 1 << 10}, {"M", 1 << 20}, {"G", 1 << 30}, {"B", 1}} {
		if len(s) >= len(u.suf) && strings.EqualFold(s[len(s)-len(u.suf):], u.suf) {
			mult, s = u.m, strings.TrimSpace(s[:len(s)-len(u.suf)])
			break
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	if n < 0 || (mult > 1 && n > math.MaxInt64/mult) {
		return 0, fmt.Errorf("size out of range")
	}
	return n * mult, nil
}

// mustInt strictly parses an int flag value (>= min), exiting 2 on failure. Uses strconv, not
// fmt.Sscan, which would partial-parse "5x" to 5 and let a typo'd flag take a bogus value.
func mustInt(name, v string, min int) int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < min {
		fmt.Fprintf(os.Stderr, "%s needs an integer >= %d, got %q\n", name, min, v)
		os.Exit(2)
	}
	return n
}

// mustEnum validates that v is one of the allowed values, exiting 2 otherwise (a bogus enum value must
// not fall back silently and hide a typo).
func mustEnum(name, v string, allowed ...string) string {
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	fmt.Fprintf(os.Stderr, "%s must be one of %s, got %q\n", name, strings.Join(allowed, "|"), v)
	os.Exit(2)
	return ""
}

// mustFloat01 strictly parses a flag value as a number in [0,1] (rejecting trailing garbage, NaN, Inf).
func mustFloat01(name, v string) float64 {
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 1 {
		fmt.Fprintf(os.Stderr, "%s needs a number in 0..1, got %q\n", name, v)
		os.Exit(2)
	}
	return f
}

// redactURL strips embedded credentials (`user:token@`) from a clone URL before logging, so a token
// injected from a CI secret store never lands in build logs.
func redactURL(raw string) string { return safehttp.RedactURL(raw) }

func parseCommon(args []string) (commonFlags, []string) {
	checkUnknownFlags(args)
	c := commonFlags{format: "pretty", maxSize: 10 << 20, dedupe: true, maxPerFile: 30, mlThreshold: 0.3}
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		inlineVal, hasInline := "", false
		if strings.HasPrefix(a, "--") { // support the --key=value form (and an escape for --leading values)
			if eq := strings.IndexByte(a, '='); eq >= 0 {
				a, inlineVal, hasInline = a[:eq], a[eq+1:], true
			}
		}
		next := func() string {
			if hasInline {
				return inlineVal
			}
			i++
			if i < len(args) {
				if v := args[i]; strings.HasPrefix(v, "--") { // don't swallow the next flag as a value
					fmt.Fprintf(os.Stderr, "flag %q expects a value, got %q (use %s=VALUE if the value must start with --)\n", a, v, a)
					os.Exit(2)
				}
				return args[i]
			}
			return ""
		}
		switch {
		case a == "--format":
			c.format = mustEnum("--format", next(), "pretty", "json", "sarif", "defectdojo", "dojo")
		case a == "--fail-on":
			c.failOn = next()
			if _, ok := model.SeverityOrder[c.failOn]; !ok {
				fmt.Fprintf(os.Stderr, "--fail-on must be info|low|medium|high|critical, got %q\n", c.failOn)
				os.Exit(2)
			}
		case a == "--fail-on-verified":
			c.failOnVerified = true
		case a == "--exclude":
			c.exclude = append(c.exclude, next())
		case a == "--taxonomy":
			c.taxonomy = next()
		case a == "--rules":
			c.rules = append(c.rules, next())
		case a == "--rules-only":
			c.rulesOnly = true
		case a == "--rules-dir":
			c.rulesDir = append(c.rulesDir, next())
		case a == "--tags":
			c.tags = next()
		case a == "--exclude-tags":
			c.excludeTags = next()
		case a == "--rule-severity":
			c.ruleSeverity = next()
			for _, s := range splitCSV(c.ruleSeverity) { // CSV of severities — a typo'd one silently filtered nothing
				if _, ok := model.SeverityOrder[s]; !ok {
					fmt.Fprintf(os.Stderr, "--rule-severity entries must be info|low|medium|high|critical, got %q\n", s)
					os.Exit(2)
				}
			}
		case a == "--verify":
			c.verify = true
		case a == "--verified-only":
			c.verify = true
			c.verifiedOnly = true
		case a == "--show-secrets":
			c.showSecrets = true
		case a == "--verifiers":
			c.verifiers = append(c.verifiers, next())
		case a == "--config":
			c.config = next()
		case a == "--output" || a == "-o":
			c.output = next()
		case a == "--staged":
			c.staged = true
		case a == "--history":
			c.history = true
		case a == "--since":
			c.since = next()
		case a == "--baseline":
			c.baseline = next()
		case a == "--write-baseline":
			c.writeBaseline = next()
		case a == "--max-size":
			v := next()
			sz, err := parseByteSize(v)
			if err != nil || sz < 1 {
				fmt.Fprintf(os.Stderr, "--max-size needs a positive size like 10485760, 10MB, or 4M, got %q\n", v)
				os.Exit(2)
			}
			c.maxSize = sz
		case a == "--workers":
			c.workers = mustInt("--workers", next(), 0)
		case a == "--timeout":
			v := next()
			d, err := time.ParseDuration(v)
			if err != nil || d <= 0 {
				fmt.Fprintf(os.Stderr, "--timeout needs a positive Go duration (e.g. 30s, 5m), got %q\n", v)
				os.Exit(2)
			}
			c.timeout = d
		case a == "--silence" || a == "--silent" || a == "-s":
			c.silence = true
		case a == "--quiet" || a == "-q":
			c.quiet = true
		case a == "--verbose" || a == "-v":
			c.verbose = true
		case a == "--no-dedupe":
			c.dedupe = false
		case a == "--dedupe":
			c.dedupe = true
		case a == "--min-confidence":
			c.minConfidence = mustFloat01("--min-confidence", next())
		case a == "--min-severity":
			c.minSeverity = next()
			if _, ok := model.SeverityOrder[c.minSeverity]; !ok {
				fmt.Fprintf(os.Stderr, "--min-severity must be info|low|medium|high|critical, got %q\n", c.minSeverity)
				os.Exit(2)
			}
		case a == "--disable":
			c.disable = next()
		case a == "--max-per-file":
			c.maxPerFile = mustInt("--max-per-file", next(), 0)
		case a == "--ml":
			c.mlEmbed = true
		case a == "--ml-model":
			c.mlModel = next()
		case a == "--ml-url":
			c.mlURL = strings.TrimRight(next(), "/")
		case a == "--ml-threshold":
			v := next()
			// strconv (not fmt.Sscan) so NaN/Inf are caught — a NaN threshold passes < / > as false and
			// would delete every non-exempt finding (score >= NaN is never true).
			f, err := strconv.ParseFloat(v, 64)
			if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 1 {
				fmt.Fprintf(os.Stderr, "--ml-threshold needs a number in 0..1, got %q\n", v)
				os.Exit(2)
			}
			c.mlThreshold = f
			c.mlThresholdSet = true
		case a == "--no-color":
			c.noColor = true
		case a == "--log-format":
			c.logFormat = mustEnum("--log-format", next(), "console", "json")
		case a == "--log-level":
			c.logLevel = next()
			var lvl slog.Level // validate via slog (debug|info|warn|error, case-insensitive) — was silently ignored
			if err := lvl.UnmarshalText([]byte(c.logLevel)); err != nil {
				fmt.Fprintf(os.Stderr, "--log-level must be debug|info|warn|error, got %q\n", c.logLevel)
				os.Exit(2)
			}
		case strings.HasPrefix(a, "--"):
			// Preserve the ORIGINAL token (incl. the --key=value form) — a command-specific flag's
			// inline value must survive for the caller's flagVal/multiFlag/stripValueFlags (which all
			// understand --key=value). Appending the stripped name dropped `=value` silently.
			rest = append(rest, args[i])
		default:
			rest = append(rest, a)
		}
	}
	return c, rest
}

func cmdScan(args []string) int {
	c, rest := parseCommon(args)
	if code := checkSourceModes(c, rest); code != 0 {
		return code
	}
	ctx, stop := rootContext(c)
	defer stop()
	return scanItems(ctx, c, rest)
}

// cmdCompare shows the false-positive reduction over a regex-only scanner on the user's own tree: it
// runs the regex/cascade detectors alone, then the same scan with Prowl's ML context filter, and
// reports how many findings the model suppresses as not-a-secret.
func cmdCompare(args []string) int {
	c, rest := parseCommon(args)
	ctx, stop := rootContext(c)
	defer stop()
	cfg := loadConfig(&c)
	setupLogging(c)
	det, _, err := loadDetector(c, cfg)
	if err != nil {
		logx.Error("failed to load detector", "err", err)
		return 2
	}
	eng := loadEngine(c)

	mkItems := func() <-chan model.Item {
		if c.staged {
			files, ferr := source.GitChangedFiles(ctx, "staged", "")
			if ferr != nil {
				logx.Error("git error", "err", ferr)
			}
			return source.FilesFromList(ctx, files, c.maxSize)
		}
		roots := rest
		if len(roots) == 0 {
			roots = []string{"."}
		}
		return source.Filesystem(ctx, roots, c.exclude, c.maxSize)
	}

	// Pass 1: regex/cascade only — the noisy set a regex scanner reports. No ML, no per-file cap.
	rawC := c
	rawC.mlEmbed, rawC.mlModel, rawC.mlURL = false, "", ""
	rawC.verifiedOnly, rawC.maxPerFile = false, 0
	raw := collectFindings(ctx, rawC, cfg, det, eng, nil, mkItems(), c.dedupe)

	// Pass 2: the same scan + Prowl's in-process ML context filter (isolated from the per-file cap).
	mlC := c
	mlC.mlEmbed = true
	mlC.verifiedOnly, mlC.maxPerFile = false, 0
	// compare requires the in-process model — fail closed rather than run cascade-only and report a
	// misleading "0% suppressed by ML" (e.g. on a nocgo binary or a bad --ml-model).
	if code := mlC.mlPreflight(); code != 0 {
		return code
	}
	kept := collectFindings(ctx, mlC, cfg, det, eng, nil, mkItems(), c.dedupe)

	printCompare(raw, kept)
	return 0
}

func compareKey(f model.Finding) string {
	if f.Fingerprint != "" {
		return f.Fingerprint
	}
	return f.Path + "\x00" + f.Type + "\x00" + strconv.Itoa(f.Line)
}

// printCompare renders the regex-baseline -> Prowl funnel and a breakdown of what the ML suppressed.
func printCompare(raw, kept []model.Finding) {
	keptSet := make(map[string]bool, len(kept))
	for _, f := range kept {
		keptSet[compareKey(f)] = true
	}
	byType := map[string]int{}
	var sample []model.Finding
	suppressed := 0
	for _, f := range raw {
		if keptSet[compareKey(f)] {
			continue
		}
		suppressed++
		byType[f.Type]++
		if len(sample) < 8 {
			sample = append(sample, f)
		}
	}
	n, m := len(raw), len(kept)
	pct := 0.0
	if n > 0 {
		pct = 100 * float64(suppressed) / float64(n)
	}
	fmt.Printf("\nProwl compare — detector candidates vs the ML-confirmed set\n\n")
	fmt.Printf("  detectors (regex + cascade, no ML):  %6d findings\n", n)
	fmt.Printf("  after Prowl's ML context filter:     %6d findings\n", m)
	fmt.Printf("  -----------------------------------------------------\n")
	fmt.Printf("  suppressed by ML as not-a-secret:    %6d  (%.0f%%)\n", suppressed, pct)
	fmt.Printf("\n  (the cascade already rejects hashes/UUIDs/placeholders before the ML runs, so the\n")
	fmt.Printf("   gap vs a raw-regex tool like gitleaks is larger than the ML delta shown here. In a\n")
	fmt.Printf("   repo with a .gitleaks.toml, those rules are auto-loaded into the baseline above.)\n")
	if suppressed == 0 {
		fmt.Printf("\n  The ML kept every candidate here — nothing the cascade surfaced looked like noise.\n\n")
		return
	}
	type tc struct {
		typ string
		n   int
	}
	tcs := make([]tc, 0, len(byType))
	for t, c := range byType {
		tcs = append(tcs, tc{t, c})
	}
	sort.Slice(tcs, func(i, j int) bool { return tcs[i].n > tcs[j].n })
	fmt.Printf("\n  suppressed by detector type (a regex scanner would report these):\n")
	for i, t := range tcs {
		if i >= 8 {
			fmt.Printf("    %6d  … and %d more types\n", 0, len(tcs)-8)
			break
		}
		fmt.Printf("    %6d  %s\n", t.n, logx.SanitizeTerminal(t.typ))
	}
	fmt.Printf("\n  examples Prowl silenced:\n")
	for _, f := range sample {
		// f.Path/Type/Redacted come from a (possibly hostile) scanned repo — strip terminal escapes.
		fmt.Printf("    %s:%d  %s  %s\n", logx.SanitizeTerminal(f.Path), f.Line,
			logx.SanitizeTerminal(f.Type), logx.SanitizeTerminal(f.Redacted))
	}
	fmt.Println()
}

// checkSourceModes rejects mutually-exclusive scan inputs (--staged / --since / --history / '-' stdin /
// paths) with a clear message instead of letting one silently win.
func checkSourceModes(c commonFlags, rest []string) int {
	var modes []string
	if c.staged {
		modes = append(modes, "--staged")
	}
	if c.since != "" {
		modes = append(modes, "--since")
	}
	if c.history {
		modes = append(modes, "--history")
	}
	if len(rest) == 1 && rest[0] == "-" {
		modes = append(modes, "- (stdin)")
	} else if len(rest) > 0 {
		modes = append(modes, "paths")
	}
	if len(modes) > 1 {
		logx.Error("scan input modes are mutually exclusive — use only one", "given", strings.Join(modes, " + "))
		return 2
	}
	return 0
}

// scanItems runs the full scan pipeline (config, detector, source, report) for the given roots under
// the caller's context. It is shared by `scan`, `repo`, and `org` (which clone and scan in ".").
func scanItems(ctx context.Context, c commonFlags, rest []string) int {
	if code := c.mlPreflight(); code != 0 {
		return code
	}
	cfg := loadConfig(&c)
	setupLogging(c)
	det, tax, err := loadDetector(c, cfg)
	if err != nil {
		logx.Error("failed to load detector", "err", err)
		return 2
	}
	if len(tax.Skipped) > 0 {
		logx.Debug("some detector regexes not RE2-compatible, skipped", "count", len(tax.Skipped))
	}

	var items <-chan model.Item
	switch {
	case c.staged || c.since != "":
		mode, rev := "staged", ""
		if c.since != "" {
			mode, rev = "since", c.since
		}
		files, err := source.GitChangedFiles(ctx, mode, rev)
		if err != nil {
			logx.Error("git error", "err", err)
			return 2
		}
		if len(files) == 0 {
			logx.Info("no changed files to scan")
			return 0
		}
		items = source.FilesFromList(ctx, files, c.maxSize)
	case c.history:
		if !source.IsGitRepo("") { // mirror --staged/--since: fail loudly outside a git repo, not exit-0 "clean"
			logx.Error("--history needs a git repository, but this is not one")
			return 2
		}
		items = source.GitHistoryBlobs(ctx, "", c.exclude, c.maxSize)
	case len(rest) == 1 && rest[0] == "-":
		items = source.Stdin(ctx)
	case len(rest) == 0 && !isTTY(os.Stdin):
		items = source.Stdin(ctx) // input is piped and no path was given — read stdin
	default:
		roots := rest
		if len(roots) == 0 {
			roots = []string{"."}
		}
		for _, r := range roots { // a typo'd path must error, not silently scan nothing and exit 0
			if _, err := os.Stat(r); err != nil {
				logx.Error("scan path not found", "path", r)
				return 2
			}
		}
		items = source.Filesystem(ctx, roots, c.exclude, c.maxSize)
	}

	return runScan(ctx, c, cfg, det, items, c.dedupe)
}

// runScan executes the scan pipeline over an already-built item stream, composing collectFindings
// (scan -> findings) and reportFindings (findings -> report + exit code). Shared by scan/repo/image;
// org drives the two halves separately so it can collect per-repo on a worker pool.
func runScan(ctx context.Context, c commonFlags, cfg *config.Config, det *detect.Detector, items <-chan model.Item, dedupe bool) int {
	start := time.Now()
	eng := loadEngine(c)
	vset, err := loadVerifySet(c)
	if err != nil {
		logx.Error("verify setup failed", "err", err)
		return 2
	}
	findings := collectFindings(ctx, c, cfg, det, eng, vset, items, dedupe)
	code := reportFindings(c, findings, time.Since(start))
	return failClosedIfIncomplete(ctx, code)
}

// failClosedIfIncomplete raises a clean exit to non-zero when the scan didn't finish (timeout or
// signal): an incomplete scan can't certify "no secrets". Partial results are still written.
func failClosedIfIncomplete(ctx context.Context, code int) int {
	if ctx.Err() != nil {
		logx.Error("scan did not complete (timeout/interrupt) — failing closed; partial results may miss secrets")
		if code == 0 {
			return 2
		}
	}
	return code
}

// mlPreflight fails closed: if --ml/--ml-model was requested but can't load (a nocgo binary, a bad
// --ml-model path), abort rather than return cascade-only results that look ML-filtered.
func (c commonFlags) mlPreflight() int {
	if !c.mlEmbed && c.mlModel == "" {
		return 0
	}
	if _, err := mlscore.NewEmbedded(c.mlThreshold, c.mlModel); err != nil {
		logx.Error("ml: --ml was requested but the model cannot load — aborting rather than silently "+
			"scanning without the ML stage", "err", err)
		return 2
	}
	return 0
}

// mlScorer builds the L2 ML scorer: the in-process model (--ml), the sidecar (--ml-url), or nil.
func (c commonFlags) mlScorer() mlscore.Scorer {
	switch {
	case c.mlEmbed || c.mlModel != "":
		s, err := mlscore.NewEmbedded(c.mlThreshold, c.mlModel)
		if err != nil { // unreachable after mlPreflight aborts; kept as defense
			logx.Error("ml: cannot load model — scanning without the ML stage", "err", err)
			return nil
		}
		return s
	case c.mlURL != "":
		return mlscore.New(c.mlURL, c.mlThreshold)
	default:
		return nil
	}
}

// collectFindings runs the detector + rule engine (+ optional live-verification) over an item stream,
// applying --verified-only and (for image scans) fingerprint dedupe. The "scan" half of runScan; org
// calls it once per repo on a worker pool.
func collectFindings(ctx context.Context, c commonFlags, cfg *config.Config, det *detect.Detector, eng *rules.Engine, vset *verify.Set, items <-chan model.Item, dedupe bool) []model.Finding {
	findings := scan.Run(ctx, items, det, eng, vset, c.workers, cfg.Allowed, c.mlScorer())
	if c.verifiedOnly {
		findings = keepVerified(findings)
	}
	if dedupe {
		findings = dedupeFingerprints(findings)
	}
	findings = capGenericPerFile(findings, c.maxPerFile)
	return findings
}

// capGenericPerFile bounds how many shape-only generic findings (generic_high_entropy /
// generic_password) one file may contribute — that many is a data/artifact file, not that many leaks.
// Specific detectors cap only at a much higher bound. The drop is logged; max<=0 disables it.
func capGenericPerFile(fs []model.Finding, max int) []model.Finding {
	if max <= 0 {
		return fs
	}
	const specificMult = 8 // specific detectors cap at max*mult to clip only an extreme flood
	type key struct{ path, typ string }
	seen := map[key]int{}
	dropped := map[string]int{}
	out := fs[:0]
	for _, f := range fs {
		limit := max * specificMult
		if f.Type == "generic_high_entropy" || f.Type == "generic_password" {
			limit = max
		}
		k := key{f.Path, f.Type}
		seen[k]++
		if seen[k] > limit {
			dropped[f.Path]++
			continue
		}
		out = append(out, f)
	}
	for path, n := range dropped {
		logx.Warn("capped findings per file — looks like a data/test/artifact file, not leaks",
			"path", path, "dropped", n, "flag", "--max-per-file")
	}
	return out
}

// reportFindings is the "report" half of runScan: it logs the summary, writes/updates a baseline,
// emits the report, and returns the --fail-on exit code. Shared by scan/repo/image and org.
func reportFindings(c commonFlags, findings []model.Finding, elapsed time.Duration) int {
	findings = applyReportFilters(c, findings)
	summarize(findings, elapsed)

	if c.writeBaseline != "" {
		if err := post.WriteBaseline(c.writeBaseline, findings); err != nil {
			logx.Error("baseline write failed", "err", err)
			return 2
		}
		logx.Info("baseline written", "findings", len(findings), "path", c.writeBaseline)
		return 0
	}
	blPath := c.baseline
	if blPath == "" {
		if _, e := os.Stat(".prowl-baseline.json"); e == nil {
			blPath = ".prowl-baseline.json"
		}
	}
	// Under --fail-on-verified, snapshot confirmed-live findings so an in-tree (possibly attacker-shipped)
	// baseline/.gitleaksignore can't suppress them past the gate; restore any that suppression drops.
	var liveGuard []model.Finding
	if c.failOnVerified {
		for _, f := range findings {
			if f.Verified != nil && *f.Verified {
				liveGuard = append(liveGuard, f)
			}
		}
	}
	if blPath != "" {
		before := len(findings)
		findings = post.LoadBaseline(blPath).Suppress(findings)
		if n := before - len(findings); n > 0 {
			logx.Warn("baseline suppressed findings", "count", n, "baseline", blPath)
		}
	}

	// Honor a gitleaks .gitleaksignore in the working dir, so a repo already triaged with gitleaks
	// keeps those exact findings suppressed under Prowl — zero-friction migration off gitleaks.
	if _, e := os.Stat(".gitleaksignore"); e == nil {
		before := len(findings)
		findings = post.LoadGitleaksIgnore(".gitleaksignore").Suppress(findings)
		if n := before - len(findings); n > 0 {
			logx.Warn("gitleaksignore suppressed findings", "count", n, "path", ".gitleaksignore")
		}
	}

	if c.failOnVerified {
		findings = restoreMissingLive(findings, liveGuard)
		escalateLive(findings)
	}
	writeReport(c, findings)
	return gate(findings, c.failOn, c.failOnVerified)
}

// applyReportFilters drops findings hidden at report time: below --min-confidence, below
// --min-severity (built-ins included, unlike --rule-severity), or of a --disable'd detector type.
func applyReportFilters(c commonFlags, fs []model.Finding) []model.Finding {
	disabled := map[string]bool{}
	for _, t := range splitCSV(c.disable) {
		disabled[t] = true
	}
	minSev := -1
	if c.minSeverity != "" {
		minSev = model.SeverityOrder[c.minSeverity]
	}
	if c.minConfidence <= 0 && minSev < 0 && len(disabled) == 0 {
		return fs
	}
	out := fs[:0]
	for _, f := range fs {
		if c.minConfidence > 0 && f.Confidence < c.minConfidence {
			continue
		}
		if minSev >= 0 && model.SeverityOrder[f.Severity] < minSev {
			continue
		}
		if disabled[f.Type] {
			continue
		}
		out = append(out, f)
	}
	return out
}

// dedupeFingerprints drops findings whose Fingerprint was already emitted, collapsing the same secret
// across image layers. Findings without a fingerprint are always kept (no stable identity to dedupe).
func dedupeFingerprints(fs []model.Finding) []model.Finding {
	seen := make(map[string]bool, len(fs))
	out := fs[:0]
	for _, f := range fs {
		if f.Fingerprint != "" {
			if seen[f.Fingerprint] {
				continue
			}
			seen[f.Fingerprint] = true
		}
		out = append(out, f)
	}
	return out
}

// cmdRepo clones a remote git repository (any git URL) into a temp dir and scans it. --history scans
// every blob; otherwise the default-branch working tree. Auth via your existing git credentials.
func cmdRepo(args []string) int {
	branch := flagVal(args, "--branch")
	var depth int
	if d := flagVal(args, "--depth"); d != "" {
		depth = mustInt("--depth", d, 1)
	}
	c, rest := parseCommon(stripValueFlags(args, "--branch", "--depth"))
	setupLogging(c)
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "usage: prowl repo <git-url> [--branch B] [--history] [--depth N] [scan flags]")
		return 2
	}
	if len(rest) > 1 {
		logx.Error("scan one repository at a time (for many, use 'prowl org')", "given", len(rest))
		return 2
	}
	ctx, stop := rootContext(c)
	defer stop()
	return scanCheckout(ctx, c, source.CloneOpts{URL: rest[0], Branch: branch, Full: c.history, Depth: depth})
}

// scanCheckout clones a repository into a temp dir, scans the checkout in place, then removes it and
// restores the working directory. Returns the scan exit code (2 on clone failure).
func scanCheckout(ctx context.Context, c commonFlags, o source.CloneOpts) int {
	logx.Info("cloning repository", "url", redactURL(o.URL), "history", o.Full)
	dir, cleanup, err := source.CloneRepo(ctx, o)
	if err != nil {
		logx.Error("clone failed", "url", redactURL(o.URL), "err", err)
		return 2
	}
	defer cleanup()
	saved, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		logx.Error("cannot enter checkout", "err", err)
		return 2
	}
	if saved != "" {
		defer os.Chdir(saved)
	}
	c.noAutoConfig = true // ignore the cloned repo's own .prowl.yaml (only an explicit --config is trusted)
	return scanItems(ctx, c, []string{"."})
}

// cmdOrg lists every repo under a GitHub org/user, GitLab group, or Bitbucket workspace, then clones
// and scans them on a worker pool, building the detector/engine/verifier once and merging findings into
// one report. Target is "<platform>:<name>"; auth via GITHUB_TOKEN / GITLAB_TOKEN / BITBUCKET_TOKEN.
// --concurrency N caps the pool (default min(4, #repos)); a failed repo is logged and skipped. Exit is
// 2 only when the listing fails or no repo could be scanned.
func cmdOrg(args []string) int {
	conc := 0
	if v := flagVal(args, "--concurrency"); v != "" {
		conc = mustInt("--concurrency", v, 1)
	}
	excludeRepo := splitCSV(flagVal(args, "--exclude-repo"))
	c, rest := parseCommon(stripValueFlags(args, "--branch", "--depth", "--concurrency", "--exclude-repo"))
	setupLogging(c)
	target := firstNonFlag(rest)
	if target == "" {
		fmt.Fprintln(os.Stderr, "usage: prowl org <github|gitlab|bitbucket>:<name> [--gists] [--history] [--concurrency N] [--exclude-repo S,…] [scan flags]")
		fmt.Fprintln(os.Stderr, "  auth via GITHUB_TOKEN / GITLAB_TOKEN / BITBUCKET_TOKEN env (for private repos)")
		return 2
	}
	gists := hasFlag(rest, "--gists")
	ctx, stop := rootContext(c)
	defer stop()
	// Load config before listing so limits.org_max_pages bounds ListRepos. noAutoConfig is set first so
	// a cloned repo's own untrusted .prowl.yaml can never apply — only an explicit --config.
	c.noAutoConfig = true
	cfg := loadConfig(&c)
	var (
		urls []string
		err  error
	)
	if gists {
		logx.Info("listing gists", "target", target)
		urls, err = forge.ListGists(ctx, target)
	} else {
		logx.Info("listing repositories", "target", target)
		urls, err = forge.ListRepos(ctx, target)
	}
	if err != nil {
		logx.Error("listing failed", "err", err)
		return 2
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
	if len(urls) == 0 {
		logx.Warn("nothing to scan", "target", target, "gists", gists)
		return 0
	}

	// Build the detector + rule engine + verifier set once and share them across workers (read-only
	// after construction; scan.Run/verify serialise their own internal state).
	det, tax, err := loadDetector(c, cfg)
	if err != nil {
		logx.Error("failed to load detector", "err", err)
		return 2
	}
	if len(tax.Skipped) > 0 {
		logx.Debug("some detector regexes not RE2-compatible, skipped", "count", len(tax.Skipped))
	}
	eng := loadEngine(c)
	vset, verr := loadVerifySet(c)
	if verr != nil {
		logx.Error("verify setup failed", "err", verr)
		return 2
	}

	workers := conc
	if workers == 0 {
		workers = 4
		if len(urls) < workers {
			workers = len(urls)
		}
	}
	logx.Info("scanning repositories", "count", len(urls), "concurrency", workers)

	start := time.Now()
	var (
		mu      sync.Mutex
		all     []model.Finding
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
				fs, ok := scanOrgRepo(ctx, c, cfg, det, eng, vset, u)
				mu.Lock()
				if ok {
					all = append(all, fs...)
					scanned++
					logx.Info("scanned", "repo", u, "findings", len(fs))
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
	// Nothing scanned (every repo errored): fail hard rather than report a misleading clean exit.
	if scanned == 0 {
		logx.Error("no repositories could be scanned", "total", len(urls))
		return 2
	}
	// A timeout/interrupt mid-sweep leaves repos unscanned — fail closed rather than gate over partial.
	return failClosedIfIncomplete(ctx, reportFindings(c, all, time.Since(start)))
}

// orgPerRepoTimeout bounds a single repo's clone (the smaller of a sane default and the run budget) so
// one slow/hung repo can't consume the whole org sweep; --timeout still bounds the overall run.
func orgPerRepoTimeout(run time.Duration) time.Duration {
	const cap = 10 * time.Minute
	if run > 0 && run < cap {
		return run
	}
	return cap
}

// scanOrgRepo clones one repo into a unique temp dir, scans it without chdir (so workers run in
// parallel), prefixes each finding's Path with the repo, and removes the dir. ok=false on clone
// failure, so the caller can log and skip without aborting the sweep.
func scanOrgRepo(ctx context.Context, c commonFlags, cfg *config.Config, det *detect.Detector, eng *rules.Engine, vset *verify.Set, url string) (findings []model.Finding, ok bool) {
	dir, cleanup, err := source.CloneRepo(ctx, source.CloneOpts{URL: url, Full: c.history, Timeout: orgPerRepoTimeout(c.timeout)})
	if err != nil {
		logx.Error("clone failed (skipping repo)", "url", redactURL(url), "err", err)
		return nil, false
	}
	defer cleanup()

	var items <-chan model.Item
	if c.history {
		items = source.GitHistoryBlobs(ctx, dir, c.exclude, c.maxSize)
	} else {
		items = source.Filesystem(ctx, []string{dir}, c.exclude, c.maxSize)
	}
	fs := collectFindings(ctx, c, cfg, det, eng, vset, items, c.dedupe)

	label := repoLabel(url)
	prefix := dir + string(os.PathSeparator)
	for i := range fs {
		fs[i].Path = label + ": " + strings.TrimPrefix(fs[i].Path, prefix)
	}
	return fs, true
}

// repoLabel derives a stable "<owner>/<repo>" label from a clone URL (dropping the transport+host and
// any ".git" suffix) for prefixing aggregated findings.
func repoLabel(url string) string {
	s := strings.TrimSuffix(url, ".git")
	if i := strings.Index(s, "://"); i >= 0 { // scheme://host/owner/repo -> owner/repo
		s = s[i+3:]
		if j := strings.IndexByte(s, '/'); j >= 0 {
			s = s[j+1:]
		}
	} else if i := strings.LastIndexByte(s, ':'); i >= 0 { // git@host:owner/repo -> owner/repo
		s = s[i+1:]
	}
	if s == "" {
		return url // fall back to the raw URL rather than an empty prefix
	}
	return s
}

// stripValueFlags removes the named value-flags (and their values, in both "--k v" and "--k=v" forms)
// so a subcommand can pre-consume its own flags before handing the remainder to parseCommon.
func stripValueFlags(args []string, names ...string) []string {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		key := a
		if eq := strings.IndexByte(a, '='); eq >= 0 {
			key = a[:eq]
		}
		if want[key] {
			if !strings.Contains(a, "=") && i+1 < len(args) {
				i++ // also skip the separate value token
			}
			continue
		}
		out = append(out, a)
	}
	return out
}

func cmdDomain(args []string) int {
	c, rest := parseCommon(args)
	setupLogging(c)
	if code := c.mlPreflight(); code != 0 {
		return code
	}
	opts := domain.Options{Recon: hasFlag(rest, "--recon"), Authorized: hasFlag(rest, "--authorized"), MaxAssets: 300}
	if v := flagVal(rest, "--max-assets"); v != "" {
		opts.MaxAssets = mustInt("--max-assets", v, 1)
	}
	if opts.Timeout == 0 {
		opts.Timeout = 12 * time.Second
	}

	var targets []string
	if f := flagVal(rest, "--targets"); f != "" {
		ts, err := readTargetList(f)
		if err != nil {
			logx.Error("could not read --targets file", "path", f, "err", err)
			return 2
		}
		targets = ts
	} else if t := firstNonFlag(stripValueFlags(rest, "--max-assets", "--targets")); t != "" {
		targets = []string{t}
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

	cfg := loadConfig(&c)
	det, _, err := loadDetector(c, cfg)
	if err != nil {
		logx.Error("failed to load detector", "err", err)
		return 2
	}
	eng := loadEngine(c)
	vset, verr := loadVerifySet(c)
	if verr != nil {
		logx.Error("verify setup failed", "err", verr)
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
				fs := scan.Run(ctx, items, det, eng, vset, c.workers, cfg.Allowed, c.mlScorer())
				if !reached.Load() { // a dead/typo'd host is skipped, not a whole-run abort
					logx.Warn("host not reachable — skipped", "target", target)
					continue
				}
				mu.Lock()
				reachedAny = true
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
		logx.Error("no host was reachable — nothing was scanned")
		return 2
	}
	if c.verifiedOnly {
		findings = keepVerified(findings)
	}
	if c.failOnVerified {
		escalateLive(findings)
	}
	summarize(findings, time.Since(start))
	writeReport(c, findings)
	return failClosedIfIncomplete(ctx, gate(findings, c.failOn, c.failOnVerified))
}

func readTargetList(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out, nil
}

func cmdServe(args []string) int {
	c, rest := parseCommon(args)
	setupLogging(c)
	// Default to loopback: the server is unauthenticated, so the operator must opt into network
	// exposure with an explicit --addr 0.0.0.0:PORT (behind auth/a proxy).
	addr, maxConc := "127.0.0.1:8080", 0
	// flagVal understands both "--addr X" and "--addr=X" (the exact-match loop missed the = form).
	if v := flagVal(rest, "--addr"); v != "" {
		addr = v
	}
	if v := flagVal(rest, "--max-concurrent"); v != "" {
		maxConc = mustInt("--max-concurrent", v, 0)
	}
	// serve runs the cascade + rule templates only (no ML or live-verification) — warn rather than
	// silently ignore --ml/--ml-url so results aren't mistaken for ML-filtered.
	if c.mlEmbed || c.mlModel != "" || c.mlURL != "" {
		logx.Warn("serve does not run the ML stage or live-verification — ignoring --ml/--ml-model/--ml-url (cascade + rule templates only)")
	}
	cfg := loadConfig(&c)
	det, _, err := loadDetector(c, cfg)
	if err != nil {
		logx.Error("failed to load detector", "err", err)
		return 2
	}
	// Load the rule templates too (as scan and lsp do) so the HTTP worker has the same coverage as the
	// CLI, not just the embedded taxonomy detectors.
	eng := loadEngine(c)
	ctx, stop := rootContext(c)
	defer stop()
	if err := server.Serve(ctx, addr, server.New(det, eng, cfg.Allowed, maxConc)); err != nil {
		logx.Error("server error", "err", err)
		return 2
	}
	return 0
}

func cmdDoctor(args []string) int {
	c, _ := parseCommon(args)
	setupLogging(c)
	cfg := loadConfig(&c)
	det, tax, err := loadDetector(c, cfg)
	if err != nil {
		logx.Error("failed to load detector", "err", err)
		return 2
	}
	checks := doctor.Run(det, tax, cfg)
	color := !c.noColor && os.Getenv("NO_COLOR") == "" && isTTY(os.Stdout)
	fmt.Println("prowl doctor")
	for _, ch := range checks {
		fmt.Println(doctorLine(ch, color))
	}
	if doctor.Healthy(checks) {
		fmt.Println("\nall checks passed — scanner is healthy")
		return 0
	}
	fmt.Println("\nFAILED — one or more checks did not pass (see ✗ above)")
	return 1
}

func doctorLine(ch doctor.Check, color bool) string {
	sym, col := "✓", "\x1b[32m"
	switch ch.Status {
	case doctor.StatusWarn:
		sym, col = "!", "\x1b[33m"
	case doctor.StatusFail:
		sym, col = "✗", "\x1b[31m"
	}
	if color {
		sym = col + sym + "\x1b[0m"
	}
	return fmt.Sprintf("  %s %-26s %s", sym, ch.Name, ch.Detail)
}

func cmdDetectors() int {
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	for _, t := range tax.Types {
		ck := ""
		if t.Checksum.Present {
			ck = " [checksum]"
		}
		fmt.Printf("%-26s %-14s%s\n", t.ID, t.Category, ck)
	}
	return 0
}

// cmdRules manages the rule set: export|list|validate|update|stats. DIR defaults to ./rules.
func cmdRules(args []string) int {
	checkUnknownFlags(args)
	sub := "list"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	var out, source, tagFilter, sevFilter string
	var ruleFiles, dirs []string
	check := false
	allowUnsigned := false
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--tags":
			if i+1 < len(args) {
				i++
				tagFilter = args[i]
			}
		case a == "--rule-severity":
			if i+1 < len(args) {
				i++
				sevFilter = args[i]
			}
		case a == "-o" || a == "--output":
			if i+1 < len(args) {
				i++
				out = args[i]
			}
		case a == "--rules":
			if i+1 < len(args) {
				i++
				ruleFiles = append(ruleFiles, args[i])
			}
		case a == "--source":
			if i+1 < len(args) {
				i++
				source = args[i]
			}
		case a == "--check":
			check = true
		case a == "--allow-unsigned":
			allowUnsigned = true
		case !strings.HasPrefix(a, "-"):
			dirs = append(dirs, a)
		}
	}
	userPos := dirs // positionals as given (rule id / test text for show/test)
	if len(dirs) == 0 {
		dirs = []string{"rules"}
	}

	switch sub {
	case "export":
		data := taxonomy.DefaultYAML()
		if out == "" {
			os.Stdout.Write(data)
			return 0
		}
		if err := os.WriteFile(out, data, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 2
		}
		fmt.Fprintf(os.Stderr, "exported built-in taxonomy to %s — edit and use with --taxonomy %s\n", out, out)
		return 0

	case "list":
		eng, _ := rules.Load(dirs...)
		if eng == nil || eng.Len() == 0 {
			fmt.Fprintln(os.Stderr, "no rule templates found; run 'prowl rules update'")
			return 0
		}
		eng.Filter(rules.FilterOpts{Tags: splitCSV(tagFilter), Severities: splitCSV(sevFilter)})
		renderRulesList(eng)
		return 0

	case "show":
		if len(userPos) == 0 {
			fmt.Fprintln(os.Stderr, "usage: prowl rules show <rule-id>   (see 'prowl rules list')")
			return 2
		}
		return renderRuleShow(loadRulesForQuery(), userPos[0])

	case "test":
		if len(userPos) == 0 {
			fmt.Fprintln(os.Stderr, "usage: prowl rules test <text>   (which rules fire on this string)")
			return 2
		}
		return renderRulesTest(loadRulesForQuery(), strings.Join(userPos, " "))

	case "search":
		if len(userPos) == 0 {
			fmt.Fprintln(os.Stderr, "usage: prowl rules search <term>   (id / tag / description, built-ins + templates)")
			return 2
		}
		return renderRulesSearch(strings.Join(userPos, " "))

	case "validate":
		issues := rules.ValidateDir(dirs...)
		nerr, nwarn := 0, 0
		for _, is := range issues {
			loc := is.Path
			if is.Rule != "" {
				loc += " (" + is.Rule + ")"
			}
			fmt.Printf("  %-5s %s: %s\n", strings.ToUpper(is.Level), loc, is.Msg)
			if is.Level == "error" {
				nerr++
			} else {
				nwarn++
			}
		}
		eng, _ := rules.Load(dirs...)
		fmt.Fprintf(os.Stderr, "\n%d templates, %d error(s), %d warning(s)\n", eng.Len(), nerr, nwarn)
		if nerr > 0 {
			return 1
		}
		return 0

	case "update":
		return updateInto("rules", source, installedRulesDir(), time.Now().UTC().Format(time.RFC3339), check, allowUnsigned)

	case "manifest": // (re)generate MANIFEST.sha256 to bless the current contents of a rule dir
		return rulesManifestCmd(dirs[0], len(userPos) > 0)

	case "stats":
		eng, _ := rules.Load(dirs...)
		renderRulesStats(eng)
		return 0

	default:
		fmt.Fprintln(os.Stderr, "usage: prowl rules list|show <id>|test <text>|search <term>|validate|stats|update|manifest|export")
		return 2
	}
}

// cmdVerifiers manages live-verifiers: list|validate|update. DIR defaults to the installed
// ~/.prowl/verifiers (then ./verifiers); `update` installs there from --source or the bundled set.
func cmdVerifiers(args []string) int {
	checkUnknownFlags(args)
	sub := "list"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	var source string
	var dirs []string
	check := false
	allowUnsigned := false
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--source":
			if i+1 < len(args) {
				i++
				source = args[i]
			}
		case a == "--check":
			check = true
		case a == "--allow-unsigned":
			allowUnsigned = true
		case !strings.HasPrefix(a, "-"):
			dirs = append(dirs, a)
		}
	}
	if sub == "update" {
		return updateInto("verifiers", source, installedVerifiersDir(), time.Now().UTC().Format(time.RFC3339), check, allowUnsigned)
	}
	if len(dirs) == 0 {
		if dirs = discoverVerifierDirs(nil); len(dirs) == 0 {
			dirs = []string{"verifiers"}
		}
	}
	if sub == "manifest" { // (re)generate MANIFEST.sha256 to bless the current contents of a verifier dir
		n, err := verify.GenerateManifest(dirs[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, "manifest:", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "wrote %s (%d files) in %s\n", verify.ManifestName, n, dirs[0])
		return 0
	}
	// list/validate load with bundled trust, honouring --allow-unsigned so an operator can inspect an
	// unsigned set without it being silently trusted.
	set, err := verify.LoadWithPolicy(0, verify.LoadPolicy{AllowUnsigned: allowUnsigned}, dirs...)
	switch sub {
	case "validate":
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "%d verifiers, all valid\n", set.Count())
		return 0
	case "list":
		if err != nil {
			fmt.Fprintln(os.Stderr, "warning:", err)
		}
		fmt.Printf("%-16s %-28s %s\n", "VERIFIER", "MATCHES", "ENDPOINT")
		for _, v := range set.Verifiers() {
			ep := ""
			if len(v.Requests) > 0 {
				ep = v.Requests[0].URL
			}
			fmt.Printf("%-16s %-28s %s\n", v.ID, strings.Join(v.Match, ","), ep)
		}
		fmt.Fprintf(os.Stderr, "\n%d verifiers\n", set.Count())
		return 0
	default:
		fmt.Fprintln(os.Stderr, "usage: prowl verifiers list|validate|update|manifest [DIR] [--source SRC] [--check] [--allow-unsigned]")
		return 2
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func printCounts(title string, m map[string]int) {
	type kv struct {
		k string
		v int
	}
	var xs []kv
	for k, v := range m {
		xs = append(xs, kv{k, v})
	}
	sort.Slice(xs, func(i, j int) bool { return xs[i].v > xs[j].v })
	fmt.Printf("  %s:", title)
	for _, x := range xs {
		fmt.Printf(" %s=%d", x.k, x.v)
	}
	fmt.Println()
}

// restoreMissingLive re-adds (by fingerprint) any confirmed-live finding that baseline/.gitleaksignore
// suppression dropped, so an attacker-shipped allowlist can't hide a live secret from the gate.
func restoreMissingLive(findings, live []model.Finding) []model.Finding {
	if len(live) == 0 {
		return findings
	}
	present := make(map[string]bool, len(findings))
	for _, f := range findings {
		present[f.Fingerprint] = true
	}
	for _, f := range live {
		if !present[f.Fingerprint] {
			findings = append(findings, f)
		}
	}
	return findings
}

// escalateLive bumps a provider-confirmed-live finding to critical so it stands out and trips any
// severity gate. Opt-in via --fail-on-verified; a plain --verify scan keeps its severities.
func escalateLive(fs []model.Finding) {
	for i := range fs {
		if fs[i].Verified != nil && *fs[i].Verified {
			fs[i].Severity = "critical"
		}
	}
}

func gate(fs []model.Finding, failOn string, failOnVerified bool) int {
	if failOnVerified {
		// Fail only on a provider-confirmed-live secret (the near-zero-FP gate); a firewalled CI that
		// can't verify should combine this with --fail-on.
		for _, f := range fs {
			if f.Verified != nil && *f.Verified {
				return 1
			}
		}
	}
	if failOn == "" {
		return 0
	}
	min, ok := model.SeverityOrder[failOn]
	if !ok {
		// An unrecognized fail_on (a config typo) must fail closed, not silently disable the gate.
		logx.Error("fail_on is not a valid severity — failing the gate closed", "value", failOn,
			"valid", "info|low|medium|high|critical")
		return 1
	}
	for _, f := range fs {
		if model.SeverityOrder[f.Severity] >= min {
			return 1
		}
	}
	return 0
}

// flagVal returns the token after the first occurrence of name in ss (for value-flags in --recon-style lists).
func flagVal(ss []string, name string) string {
	for i, s := range ss {
		if s == name && i+1 < len(ss) {
			return ss[i+1] // --branch main
		}
		if strings.HasPrefix(s, name+"=") {
			return s[len(name)+1:] // --branch=main
		}
	}
	return ""
}

// matchesAny reports whether s contains any of the (non-empty) substrings.
func matchesAny(s string, subs []string) bool {
	for _, sub := range subs {
		if sub != "" && strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// hasFlag reports whether a presence (boolean) flag is set. It matches the bare "--flag" AND the
// "--flag=VALUE" form (parseCommon preserves the inline-value token), and — crucially — it HONORS the
// value: "--flag=false"/"=0"/"=no" yield false, so a user being explicit about NOT wanting current-only
// (or NOT being authorized) is not silently flipped to true. A non-boolean value (or bare flag) is
// treated as set, matching presence semantics.
func hasFlag(ss []string, name string) bool {
	eq := name + "="
	for _, s := range ss {
		if s == name {
			return true
		}
		if v, ok := strings.CutPrefix(s, eq); ok {
			return parseBoolFlag(v)
		}
	}
	return false
}

// parseBoolFlag interprets a --flag=VALUE boolean. It accepts the strconv.ParseBool forms PLUS the
// common yes/no/on/off words (ParseBool rejects those, and silently treating "--current-only=no" as set
// would disable the history walk). An unparseable value returns false — the safe direction for every
// flag read this way (--current-only/--recon -> scan MORE; --authorized -> stay unauthorized) — rather
// than treating a typo as set.
func parseBoolFlag(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "t", "true", "y", "yes", "on":
		return true
	case "0", "f", "false", "n", "no", "off", "":
		return false
	}
	if b, err := strconv.ParseBool(v); err == nil {
		return b
	}
	return false
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

func firstNonFlag(ss []string) string {
	for _, s := range ss {
		if !strings.HasPrefix(s, "--") {
			return s
		}
	}
	return ""
}
