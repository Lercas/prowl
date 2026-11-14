// Command prowl is a fast, configurable secret scanner (filesystem + domain recon).
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Lercas/prowl/tool/internal/config"
	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/doctor"
	"github.com/Lercas/prowl/tool/internal/domain"
	"github.com/Lercas/prowl/tool/internal/forge"
	"github.com/Lercas/prowl/tool/internal/localfile"
	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/lsp"
	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/ocr"
	"github.com/Lercas/prowl/tool/internal/post"
	"github.com/Lercas/prowl/tool/internal/report"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/safehttp"
	"github.com/Lercas/prowl/tool/internal/saferegex"
	"github.com/Lercas/prowl/tool/internal/scan"
	"github.com/Lercas/prowl/tool/internal/server"
	"github.com/Lercas/prowl/tool/internal/source"
	"github.com/Lercas/prowl/tool/internal/targetlist"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
	"github.com/Lercas/prowl/tool/internal/verify"
)

const usage = `prowl — fast, configurable secret scanner

USAGE:
  prowl scan [path...]        scan files/dirs/archives/docs/mail (default: .); use '-' to scan stdin
  prowl compare [path...]     show how many detector candidates Prowl's ML suppresses as noise
                              (auto-loads .gitleaks.toml, so it scores your gitleaks rules' findings)
  prowl repo <git-url>        clone & scan a remote repo (GitHub/GitLab/Bitbucket/any git URL)
  prowl org <platform>:<name> clone & scan every repo in a GitHub org / GitLab group / Bitbucket workspace
  prowl cicd <platform>:<repo> scan recent GitHub Actions / GitLab CI logs and artifacts
  prowl image <ref>           pull & scan a container image — every layer's files + config (env/labels/history)
  prowl mobile <apk|ipa|url>   unpack & scan an Android/iOS app (resources + dex/arsc/.so strings)
  prowl bucket <s3://|gs://>   download & scan a cloud storage prefix (via the aws / gcloud CLI)
  prowl domain <domain>       scan a domain: HTML + __NEXT_DATA__/state blobs + referenced JS + maps
  prowl hermes-audit [ip...]  audit authorized Hermes dashboards and exact-IP passive inventory
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

  env: PROWL_HOME (install dir) · GITHUB_TOKEN / GITLAB_TOKEN / BITBUCKET_TOKEN (forge/CI auth) ·
       PROWL_OCR_API_KEY (optional OCR endpoint token; never pass it in argv) ·
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
  --ocr                       OCR images + image-only PDF pages via local OpenAI-compatible VLM
  --ocr-model MODEL           default mlx-community/Qwen3.6-27B-4bit
  --ocr-url URL               default http://127.0.0.1:8080/v1/chat/completions
  --ocr-allow-remote          explicit opt-in for a non-loopback HTTPS endpoint
  --ocr-all-pages             OCR every PDF page (default: only pages without a text layer)
  --ocr-max-pages N           per-PDF OCR page cap (default 20)
  --ocr-timeout DUR           per-request timeout (default 2m)

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

func main() { os.Exit(runCLI(os.Args[1:])) }

func runCLI(args []string) int {
	if len(args) == 0 {
		fmt.Print(usage)
		return 2
	}
	// Block outbound connections to private/loopback IPs (SSRF guard) by default; opt out explicitly.
	safehttp.AllowPrivate.Store(os.Getenv("PROWL_ALLOW_PRIVATE_IPS") != "")
	cmd := args[0]
	if cmd == "version" || cmd == "--version" || cmd == "-V" {
		if _, _, err := parseCommand("version", args[1:]); err != nil {
			return commandParseError(err)
		}
		return printVersions()
	}
	if cmd == "help" || cmd == "-h" || cmd == "--help" {
		topic := ""
		if len(args) > 1 {
			topic = args[1]
		}
		helpFor(topic)
		return 0
	}
	switch cmd {
	case "scan":
		return cmdScan(args[1:])
	case "compare":
		return cmdCompare(args[1:])
	case "repo":
		return cmdRepo(args[1:])
	case "org":
		return cmdOrg(args[1:])
	case "cicd":
		return cmdCICD(args[1:])
	case "image":
		return cmdImage(args[1:])
	case "mobile":
		return cmdMobile(args[1:])
	case "bucket":
		return cmdBucket(args[1:])
	case "domain":
		return cmdDomain(args[1:])
	case "hermes-audit":
		return cmdHermesAudit(args[1:])
	case "jira":
		return cmdJira(args[1:])
	case "confluence":
		return cmdConfluence(args[1:])
	case "serve":
		return cmdServe(args[1:])
	case "config":
		return cmdConfig(args[1:])
	case "doctor":
		return cmdDoctor(args[1:])
	case "detectors":
		if _, _, err := parseCommand("detectors", args[1:]); err != nil {
			return commandParseError(err)
		}
		return cmdDetectors()
	case "rules":
		return cmdRules(args[1:])
	case "verifiers":
		return cmdVerifiers(args[1:])
	case "lsp":
		if _, _, err := parseCommand("lsp", args[1:]); err != nil {
			return commandParseError(err)
		}
		if err := lsp.Serve(); err != nil {
			if errors.Is(err, lsp.ErrExitWithoutShutdown) {
				return 1
			}
			fmt.Fprintln(os.Stderr, "lsp error:", err)
			return 2
		}
	case "mcp":
		return cmdMCP(args[1:])
	default:
		fmt.Fprintln(os.Stderr, unknownCommandMessage(cmd))
		return 2
	}
	return 0
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
	if err := taxonomy.RequireComplete(tax); err != nil {
		return nil, nil, fmt.Errorf("taxonomy: %w", err)
	}
	ruleFiles := c.rules
	// gitleaks migration: with no explicit --rules, auto-load a .gitleaks.toml from the working dir so
	// its rules join the taxonomy and their IDs line up with any .gitleaksignore.
	if len(ruleFiles) == 0 && !c.rulesOnly {
		name, err := taxonomy.DiscoverGitleaks()
		if err != nil {
			return nil, nil, err
		}
		if name != "" {
			ruleFiles = append(ruleFiles, name)
			logx.Info("auto-loaded gitleaks config", "file", name)
		}
	}
	for _, rp := range ruleFiles {
		ext, al, err := taxonomy.LoadAny(rp)
		if err != nil {
			return nil, nil, fmt.Errorf("rules %q: %w", rp, err)
		}
		if err := taxonomy.RequireComplete(ext); err != nil {
			return nil, nil, fmt.Errorf("rules %q: %w", rp, err)
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
				return nil, nil, fmt.Errorf("custom rule %q: bad regex: %w", cr.ID, err)
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
func loadEngine(c commonFlags) (*rules.Engine, error) {
	dirs := c.rulesDir
	if !c.rulesOnly {
		var err error
		dirs, err = discoverRulesDirs(c.rulesDir)
		if err != nil {
			return nil, err
		}
	}
	if len(dirs) == 0 {
		return nil, nil
	}
	eng, err := rules.Load(dirs...)
	if err != nil {
		return nil, fmt.Errorf("incomplete rule template set: %w", err)
	}
	eng.Filter(rules.FilterOpts{
		Tags:        splitCSV(c.tags),
		ExcludeTags: splitCSV(c.excludeTags),
		Severities:  splitCSV(c.ruleSeverity),
	})
	logx.Info("loaded rule templates", "count", eng.Len())
	return eng, nil
}

// loadVerifySet builds the verifier set from --verifiers dirs when --verify is on. --verify with no
// verifiers installed is an error (a silent unverified scan + --verified-only would drop everything).
func loadVerifySet(c commonFlags) (*verify.Set, error) {
	if !c.verify {
		return nil, nil
	}
	dirs, err := discoverVerifierDirs(c.verifiers)
	if err != nil {
		return nil, err
	}
	if len(dirs) == 0 {
		return nil, fmt.Errorf("--verify needs verifiers, but none are installed — run 'prowl verifiers update' (or pass --verifiers DIR)")
	}
	vs, err := verify.Load(c.verifyTimeout, dirs...)
	if err != nil {
		return nil, fmt.Errorf("--verify needs a complete verifier set: %w", err)
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
		case model.IsIncompleteFinding(f):
			out = append(out, f)
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
	cmd                                      commandOptions
	explicitFlags                            map[string]bool // immutable after parsing; explicit defaults override configuration
	format, failOn, taxonomy, config, output string
	since, baseline, writeBaseline           string
	logFormat, logLevel                      string
	staged, history                          bool
	silence, quiet, verbose, noColor         bool
	rulesOnly                                bool
	noAutoConfig                             bool              // repo/org: don't honor the scanned tree's own .prowl.yaml
	dedupe                                   bool              // collapse the same secret found repeatedly in one file (default on)
	maxPerFile                               int               // cap generic findings per file (data-file guard; 0 = off)
	mlEmbed                                  bool              // run the L2 model in-process (embedded), no sidecar
	mlModel                                  string            // load the in-process model from this file (implies --ml)
	mlURL                                    string            // ML sidecar URL for the L2 secret/not-secret stage (off if empty)
	mlThreshold                              float64           // drop a non-checksum finding the ML scores below this
	mlThresholdSet                           bool              // user passed --ml-threshold (so config must not override it)
	mlPrepared                               *mlscore.Embedded // immutable model snapshot from early preflight
	mlPreparedPath                           string            // selector that produced the snapshot
	minConfidence                            float64           // report-time: drop findings below this confidence (0 = off)
	minSeverity                              string            // report-time: drop findings below this severity (incl. built-ins)
	disable                                  string            // report-time: comma-separated detector types to drop
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
	imageInput                               string // force the image source kind: ref|tar|oci-dir|stdin (empty = auto)
	ocrEnabled                               bool
	ocrURL, ocrModel                         string
	ocrAllowRemote, ocrAllPages              bool
	ocrMaxPages                              int
	ocrTimeout                               time.Duration
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
	ctx, stop := signal.NotifyContext(context.Background(), scanSignals()...)
	if c.timeout > 0 {
		tctx, cancel := context.WithTimeout(ctx, c.timeout)
		return tctx, func() { cancel(); stop() }
	}
	return ctx, stop
}

// writeReport sends findings to the --output file or stdout. A write failure exits non-zero rather
// than leave an empty report CI would read as "clean".
func writeReport(c commonFlags, findings []model.Finding) error {
	if c.output != "" {
		if err := writeReportFile(c.output, findings, c.format); err != nil {
			logx.Error("cannot write output file", "path", c.output, "err", err)
			return err
		}
		logx.Info("report written", "findings", len(findings), "path", c.output)
		return nil
	}
	if c.silence && c.format == "pretty" {
		return nil // --silence suppresses the human report; an explicit --format json/sarif still writes for CI
	}
	color := !c.noColor && os.Getenv("NO_COLOR") == "" && isTTY(os.Stdout)
	if err := report.Write(os.Stdout, findings, c.format, color); err != nil {
		logx.Error("cannot write report to stdout", "err", err)
		return err
	}
	return nil
}

// writeReportFile commits a complete report without changing the previous inode on failure.
// Every report is private because --show-secrets can put full credential values into its output.
func writeReportFile(path string, findings []model.Finding, format string) error {
	return localfile.WriteAtomic(path, 0o600, func(w io.Writer) error {
		return report.Write(w, findings, format, false)
	})
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
func loadConfig(c *commonFlags) (*config.Config, error) {
	if c.failOnVerified && !c.verify {
		// Without --verify nothing is ever confirmed live, so the gate would always pass — require it.
		return nil, fmt.Errorf("--fail-on-verified needs --verify (it gates on provider-confirmed-live secrets)")
	}
	var cfg *config.Config
	if c.config != "" {
		var err error
		if cfg, err = config.Load(c.config); err != nil {
			// An explicit --config that fails to load must abort, not fall through to an auto-discovered
			// (possibly untrusted) in-repo .prowl.yaml.
			return nil, err
		}
	}
	if cfg == nil && c.noAutoConfig {
		// repo/org scan an untrusted tree — never honor its own .prowl.yaml; only --config is trusted.
		cfg = &config.Config{}
	}
	if cfg == nil {
		var err error
		cfg, err = config.Discover()
		if err != nil {
			return nil, err
		}
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
	if !c.explicitFlags["--format"] && c.format == "pretty" && cfg.Output.Format != "" {
		c.format = cfg.Output.Format
	}
	if c.failOn == "" {
		c.failOn = cfg.Output.FailOn
	}
	if !c.explicitFlags["--max-size"] && c.maxSize == 10<<20 && cfg.Performance.MaxSize > 0 {
		c.maxSize = cfg.Performance.MaxSize
	}
	if !c.explicitFlags["--workers"] && c.workers == 0 && cfg.Performance.Workers > 0 {
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
	return cfg, nil
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

// redactURL strips embedded credentials (`user:token@`) from a clone URL before logging, so a token
// injected from a CI secret store never lands in build logs.
func redactURL(raw string) string { return safehttp.RedactURL(raw) }

func cmdScan(args []string) int {
	c, rest, err := parseCommand("scan", args)
	if err != nil {
		return commandParseError(err)
	}
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
	c, rest, err := parseCommand("compare", args)
	if err != nil {
		return commandParseError(err)
	}
	if code := checkSourceModes(c, rest); code != 0 {
		return code
	}
	if len(rest) == 1 && rest[0] == "-" {
		fmt.Fprintln(os.Stderr, "compare needs a repeatable source; stdin cannot be scanned twice")
		return 2
	}
	if c.ocrEnabled {
		fmt.Fprintln(os.Stderr, "compare does not support --ocr: it would OCR every image twice")
		return 2
	}
	ctx, stop := rootContext(c)
	defer stop()
	cfg, err := loadConfig(&c)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		return 2
	}
	setupLogging(c)
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

	// With no explicit mode, compare defaults to the current tree even when stdin is not a TTY.
	if len(rest) == 0 && !c.staged && c.since == "" && !c.history {
		rest = []string{"."}
	}

	// Pass 1: regex/cascade only — the noisy set a regex scanner reports. No ML, no per-file cap.
	rawC := c
	rawC.mlEmbed, rawC.mlModel, rawC.mlURL = false, "", ""
	rawC.verifiedOnly, rawC.maxPerFile = false, 0
	rawItems, err := scanInput(ctx, c, rest)
	if err != nil {
		logx.Error("scan source failed", "err", err)
		return 2
	}
	raw := collectFindings(ctx, rawC, cfg, det, eng, nil, rawItems, c.dedupe)
	if code := failClosedIfIncomplete(ctx, gate(raw, "", false)); code != 0 {
		return code
	}

	// Pass 2: the same scan + Prowl's in-process ML context filter (isolated from the per-file cap).
	mlC := c
	mlC.mlEmbed = true
	mlC.verifiedOnly, mlC.maxPerFile = false, 0
	// compare requires the in-process model — fail closed rather than run cascade-only and report a
	// misleading "0% suppressed by ML" (e.g. on a nocgo binary or a bad --ml-model).
	if code := mlC.mlPreflight(); code != 0 {
		return code
	}
	keptItems, err := scanInput(ctx, c, rest)
	if err != nil {
		logx.Error("scan source failed", "err", err)
		return 2
	}
	kept := collectFindings(ctx, mlC, cfg, det, eng, nil, keptItems, c.dedupe)
	if code := failClosedIfIncomplete(ctx, gate(kept, "", false)); code != 0 {
		return code
	}

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
	return scanItemStream(ctx, c, func(ctx context.Context, c commonFlags) (<-chan model.Item, error) {
		return scanInput(ctx, c, rest)
	})
}

// scanItemStream resolves operator configuration before acquiring a source, keeping relative
// report/config paths anchored to the caller's directory and applying configured acquisition limits.
func scanItemStream(ctx context.Context, c commonFlags, acquire func(context.Context, commonFlags) (<-chan model.Item, error)) int {
	if code := c.mlPreflight(); code != 0 {
		return code
	}
	cfg, err := loadConfig(&c)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		return 2
	}
	setupLogging(c)
	ocrEngine, err := setupOCR(c)
	if err != nil {
		logx.Error("OCR setup failed", "err", err)
		return 2
	}
	if ocrEngine != nil {
		ctx = source.WithOCR(ctx, ocrEngine)
		logx.Info("OCR enabled", "model", firstNonEmpty(c.ocrModel, ocr.DefaultModel),
			"endpoint", redactURL(firstNonEmpty(c.ocrURL, ocr.DefaultURL)),
			"pdf_pages", c.ocrMaxPages, "all_pdf_pages", c.ocrAllPages)
	}
	det, tax, err := loadDetector(c, cfg)
	if err != nil {
		logx.Error("failed to load detector", "err", err)
		return 2
	}
	if len(tax.Skipped) > 0 {
		logx.Debug("some detector regexes not RE2-compatible, skipped", "count", len(tax.Skipped))
	}
	eng, err := loadEngine(c)
	if err != nil {
		logx.Error("rule setup failed", "err", err)
		return 2
	}
	vset, err := loadVerifySet(c)
	if err != nil {
		logx.Error("verify setup failed", "err", err)
		return 2
	}

	items, err := acquire(ctx, c)
	if err != nil {
		logx.Error("scan source failed", "err", err)
		return 2
	}
	code := runPreparedScan(ctx, c, cfg, det, eng, vset, items, c.dedupe)
	return finalizeOCR(ocrEngine, code)
}

// scanInput selects the same source for scan and compare, including Git's staged blob content.
func scanInput(ctx context.Context, c commonFlags, rest []string) (<-chan model.Item, error) {
	return scanInputAt(ctx, c, rest, "")
}

func scanInputAt(ctx context.Context, c commonFlags, rest []string, repoDir string) (<-chan model.Item, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch {
	case c.staged || c.since != "":
		mode, rev := "staged", ""
		if c.since != "" {
			mode, rev = "since", c.since
		}
		files, err := source.GitChangedFilesIn(ctx, repoDir, mode, rev)
		if err != nil {
			return nil, err
		}
		if len(files) == 0 {
			logx.Info("no changed files to scan")
		}
		if c.staged {
			return source.GitIndexFilesIn(ctx, repoDir, files, c.exclude, c.maxSize), nil
		}
		return source.GitWorktreeFilesIn(ctx, repoDir, files, c.exclude, c.maxSize), nil
	case c.history:
		if !source.IsGitRepo(repoDir) { // mirror --staged/--since: fail loudly outside a git repo, not exit-0 "clean"
			return nil, fmt.Errorf("--history needs a git repository, but this is not one")
		}
		return source.GitHistoryBlobs(ctx, repoDir, c.exclude, c.maxSize), nil
	case len(rest) == 1 && rest[0] == "-":
		return source.StdinLimited(ctx, c.maxSize), nil
	case len(rest) == 0 && !isTTY(os.Stdin):
		return source.StdinLimited(ctx, c.maxSize), nil // input is piped and no path was given — read stdin
	default:
		roots := rest
		if len(roots) == 0 {
			roots = []string{"."}
		}
		// The source emits per-root diagnostics so one missing root preserves the others' findings.
		return source.Filesystem(ctx, roots, c.exclude, c.maxSize), nil
	}
}

func setupOCR(c commonFlags) (*ocr.Engine, error) {
	if !c.ocrEnabled {
		return nil, nil
	}
	return ocr.New(ocr.Config{
		URL:         c.ocrURL,
		Model:       c.ocrModel,
		APIKey:      os.Getenv("PROWL_OCR_API_KEY"),
		AllowRemote: c.ocrAllowRemote,
		AllPDFPages: c.ocrAllPages,
		MaxPDFPages: c.ocrMaxPages,
		Timeout:     c.ocrTimeout,
	})
}

func rejectUnsupportedOCR(c commonFlags, command string) int {
	if !c.ocrEnabled {
		return 0
	}
	fmt.Fprintf(os.Stderr, "%s does not support --ocr; use scan, repo, or org\n", command)
	return 2
}

func finalizeOCR(engine *ocr.Engine, code int) int {
	if engine == nil {
		return code
	}
	stats := engine.Stats()
	logx.Info("OCR complete", "calls", stats.Calls, "empty", stats.Empty,
		"failures", stats.Failures, "skipped", stats.Skipped)
	if stats.Failures > 0 || stats.Skipped > 0 {
		logx.Error("OCR coverage incomplete — failing closed", "failures", stats.Failures,
			"skipped", stats.Skipped)
		return 2
	}
	return code
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// runPreparedScan consumes an item stream using the detector, rules and verifiers loaded by the caller.
func runPreparedScan(ctx context.Context, c commonFlags, cfg *config.Config, det *detect.Detector, eng *rules.Engine, vset *verify.Set, items <-chan model.Item, dedupe bool, finalize ...func([]model.Finding) []model.Finding) int {
	start := time.Now()
	collectFlags := c
	collectDedupe := dedupe
	if len(finalize) > 0 {
		// Final-image provenance must be known before selecting a duplicate or capping occurrences.
		collectFlags.maxPerFile = 0
		collectDedupe = false
	}
	findings := collectFindings(ctx, collectFlags, cfg, det, eng, vset, items, collectDedupe)
	for _, fz := range finalize { // image scans pass a final-FS marker; other sources pass nothing
		findings = fz(findings)
	}
	if len(finalize) > 0 {
		if dedupe {
			findings = dedupeFingerprints(findings)
		}
		findings = capGenericPerFile(findings, c.maxPerFile)
	}
	return reportScan(ctx, c, findings, time.Since(start))
}

// failClosedIfIncomplete raises a clean exit to non-zero when the scan didn't finish (timeout or
// signal): an incomplete scan can't certify "no secrets". Partial results are still written.
func failClosedIfIncomplete(ctx context.Context, code int) int {
	if ctx.Err() != nil {
		logx.Error("scan did not complete (timeout/interrupt) — failing closed; partial results may miss secrets")
		return 2
	}
	return code
}

// mlPreflight fails closed: if --ml/--ml-model was requested but can't load (a nocgo binary, a bad
// --ml-model path), abort rather than return cascade-only results that look ML-filtered.
func (c *commonFlags) mlPreflight() int {
	if !c.mlEmbed && c.mlModel == "" {
		c.mlPrepared = nil
		return 0
	}
	if c.mlPrepared != nil && c.mlPreparedPath == c.mlModel {
		return 0
	}
	c.mlPrepared = nil
	prepared, err := mlscore.NewEmbedded(c.mlThreshold, c.mlModel)
	if err != nil {
		logx.Error("ml: --ml was requested but the model cannot load — aborting rather than silently "+
			"scanning without the ML stage", "err", err)
		return 2
	}
	c.mlPrepared, c.mlPreparedPath = prepared, c.mlModel
	return 0
}

// mlScorer builds the L2 ML scorer: the in-process model (--ml), the sidecar (--ml-url), or nil.
func (c commonFlags) mlScorer() (mlscore.Scorer, error) {
	switch {
	case c.mlEmbed || c.mlModel != "":
		if c.mlPrepared == nil || c.mlPreparedPath != c.mlModel {
			return nil, fmt.Errorf("in-process ML model has not passed preflight for the selected model")
		}
		return c.mlPrepared.WithThreshold(c.mlThreshold), nil
	case c.mlURL != "":
		return mlscore.New(c.mlURL, c.mlThreshold), nil
	default:
		return nil, nil
	}
}

// collectFindings runs the detector + rule engine (+ optional live-verification) over an item stream,
// applying --verified-only and (for image scans) fingerprint dedupe. The "scan" half of runScan; org
// calls it once per repo on a worker pool.
func collectFindings(ctx context.Context, c commonFlags, cfg *config.Config, det *detect.Detector, eng *rules.Engine, vset *verify.Set, items <-chan model.Item, dedupe bool) []model.Finding {
	ml, mlErr := c.mlScorer()
	findings := scan.Run(ctx, items, det, eng, vset, c.workers, cfg.Allowed, ml)
	if mlErr != nil {
		logx.Error("ML setup failed; scan results are incomplete", "err", mlErr)
		findings = append(findings, model.Finding{Detector: "scan", Type: "response_truncated", Severity: "info",
			Path: "scan", Stage: "ML setup", Rationale: "requested ML model was not prepared; scan results are incomplete"})
	}
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
	specificLimit := math.MaxInt
	if max <= math.MaxInt/specificMult {
		specificLimit = max * specificMult
	}
	type key struct{ path, typ string }
	seen := map[key]int{}
	dropped := map[string]int{}
	out := fs[:0]
	for _, f := range fs {
		if model.IsIncompleteFinding(f) {
			out = append(out, f)
			continue
		}
		limit := specificLimit
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

// reportFindings is the report stage: it logs the summary, writes/updates a baseline,
// emits the report, and returns the --fail-on exit code. Shared by scan/repo/image and org.
func reportFindings(c commonFlags, findings []model.Finding, elapsed time.Duration) int {
	return reportFindingsContext(context.Background(), c, findings, elapsed)
}

// reportScan carries lifecycle cancellation through suppression, baseline commit and the gate.
func reportScan(ctx context.Context, c commonFlags, findings []model.Finding, elapsed time.Duration) int {
	return failClosedIfIncomplete(ctx, reportFindingsContext(ctx, c, findings, elapsed))
}

func markInterrupted(ctx context.Context, findings []model.Finding) []model.Finding {
	if ctx.Err() == nil {
		return findings
	}
	for _, f := range findings {
		if model.IsIncompleteFinding(f) {
			return findings
		}
	}
	return append(findings, model.Finding{Detector: "scan", Type: "response_truncated", Severity: "info",
		Path: "scan", Stage: "post-processing", Rationale: "scan interrupted; results are incomplete"})
}

func reportFindingsContext(ctx context.Context, c commonFlags, findings []model.Finding, elapsed time.Duration) int {
	findings = markInterrupted(ctx, findings)
	findings = applyReportFilters(c, findings)
	summarize(findings, elapsed)

	if c.writeBaseline != "" {
		for _, f := range findings {
			if model.IsIncompleteFinding(f) {
				logx.Error("cannot write a baseline from an incomplete scan")
				_ = writeReport(c, findings) // the incomplete result already requires exit 2
				return 2
			}
		}
		if err := post.WriteBaselineContext(ctx, c.writeBaseline, findings); err != nil {
			logx.Error("baseline write failed", "err", err)
			if ctx.Err() != nil {
				_ = writeReport(c, markInterrupted(ctx, findings))
			}
			return 2
		}
		logx.Info("baseline written", "findings", len(findings), "path", c.writeBaseline)
		return 0
	}
	blPath := c.baseline
	if blPath == "" {
		var err error
		blPath, err = localfile.FirstExisting(".prowl-baseline.json")
		if err != nil {
			logx.Error("baseline discovery failed", "err", err)
			return 2
		}
	}
	var baseline *post.Baseline
	if blPath != "" {
		var err error
		baseline, err = post.LoadBaseline(blPath)
		if err != nil {
			logx.Error("baseline load failed", "path", blPath, "err", err)
			return 2
		}
	}
	ignorePath, err := localfile.FirstExisting(".gitleaksignore")
	if err != nil {
		logx.Error("gitleaksignore discovery failed", "err", err)
		return 2
	}
	var ignore *post.GitleaksIgnore
	if ignorePath != "" {
		ignore, err = post.LoadGitleaksIgnore(ignorePath)
		if err != nil {
			logx.Error("gitleaksignore load failed", "path", ignorePath, "err", err)
			return 2
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
		findings = baseline.Suppress(findings)
		if n := before - len(findings); n > 0 {
			logx.Warn("baseline suppressed findings", "count", n, "baseline", blPath)
		}
	}

	// Honor a gitleaks .gitleaksignore in the working dir, so a repo already triaged with gitleaks
	// keeps those exact findings suppressed under Prowl — zero-friction migration off gitleaks.
	if ignore != nil {
		before := len(findings)
		findings = ignore.Suppress(findings)
		if n := before - len(findings); n > 0 {
			logx.Warn("gitleaksignore suppressed findings", "count", n, "path", ".gitleaksignore")
		}
	}

	if c.failOnVerified {
		findings = restoreMissingLive(findings, liveGuard)
		escalateLive(findings)
	}
	findings = markInterrupted(ctx, findings)
	if err := writeReport(c, findings); err != nil {
		return 2
	}
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
		if model.IsIncompleteFinding(f) {
			out = append(out, f)
			continue
		}
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
// across occurrences. A surviving image entry wins over its overwritten copy. Findings without a
// fingerprint are always kept (no stable identity to dedupe).
func dedupeFingerprints(fs []model.Finding) []model.Finding {
	seen := make(map[string]int, len(fs))
	out := fs[:0]
	for _, f := range fs {
		if f.Fingerprint != "" {
			if idx, exists := seen[f.Fingerprint]; exists {
				if f.InFinalImage != nil && *f.InFinalImage && (out[idx].InFinalImage == nil || !*out[idx].InFinalImage) {
					out[idx] = f
				}
				continue
			}
			seen[f.Fingerprint] = len(out)
		}
		out = append(out, f)
	}
	return out
}

// cmdRepo clones a remote git repository (any git URL) into a temp dir and scans it. --history scans
// every blob; otherwise the default-branch working tree. Auth via your existing git credentials.
func cmdRepo(args []string) int {
	c, rest, err := parseCommand("repo", args)
	if err != nil {
		return commandParseError(err)
	}
	branch, depth := c.cmd.branch, c.cmd.depth
	if code := checkSourceModes(c, nil); code != 0 {
		return code
	}
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

// scanCheckout scans a cloned repository without changing the caller's directory. The checkout's
// source paths remain repository-relative, and acquisition failures enter the incomplete report.
func scanCheckout(ctx context.Context, c commonFlags, o source.CloneOpts) int {
	cleanup := func() {}
	defer func() { cleanup() }()
	c.noAutoConfig = true // ignore the cloned repo's own .prowl.yaml (only an explicit --config is trusted)
	return scanItemStream(ctx, c, func(ctx context.Context, c commonFlags) (<-chan model.Item, error) {
		logx.Info("cloning repository", "url", redactURL(o.URL), "history", o.Full)
		if o.Timeout == 0 {
			o.Timeout = c.timeout
		}
		dir, release, err := source.CloneRepo(ctx, o)
		cleanup = release
		if err != nil {
			logx.Error("clone failed", "url", redactURL(o.URL), "err", err)
			return mapSourcePaths(ctx, nil, nil, model.Item{Source: "code", Path: redactURL(o.URL), Error: err}), nil
		}
		items, err := scanInputAt(ctx, c, []string{dir}, dir)
		if err != nil {
			return mapSourcePaths(ctx, nil, nil, model.Item{Source: "code", Path: redactURL(o.URL), Error: err}), nil
		}
		return mapSourcePaths(ctx, items, func(p string) (string, error) {
			if c.history || c.staged || c.since != "" {
				return p, nil // Git sources already carry repository-relative locators
			}
			return relativeSourcePath(dir, p)
		}), nil
	})
}

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
	if code := c.mlPreflight(); code != 0 {
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
		logx.Info("OCR enabled", "model", firstNonEmpty(c.ocrModel, ocr.DefaultModel),
			"endpoint", redactURL(firstNonEmpty(c.ocrURL, ocr.DefaultURL)),
			"pdf_pages", c.ocrMaxPages, "all_pdf_pages", c.ocrAllPages)
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
				fs, ok := scanOrgRepo(ctx, c, cfg, det, eng, vset, u)
				mu.Lock()
				all = append(all, fs...)
				if ok {
					scanned++
					logx.Info("scanned", "repo", redactURL(u), "findings", len(fs))
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
func scanOrgRepo(ctx context.Context, c commonFlags, cfg *config.Config, det *detect.Detector, eng *rules.Engine, vset *verify.Set, url string) (findings []model.Finding, ok bool) {
	label := repoLabel(url)
	dir, cleanup, err := source.CloneRepo(ctx, source.CloneOpts{URL: url, Full: c.history, Timeout: c.timeout})
	if err != nil {
		logx.Error("clone failed", "url", redactURL(url), "err", err)
		return []model.Finding{orgDiagnostic(label, "repository clone failed; scan results are incomplete")}, false
	}
	defer cleanup()
	var items <-chan model.Item
	if c.history {
		items = source.GitHistoryBlobs(ctx, dir, c.exclude, c.maxSize)
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
	})
	fs := collectFindings(ctx, c, cfg, det, eng, vset, items, c.dedupe)
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
func repoLabel(url string) string { return strings.TrimSuffix(redactURL(url), ".git") }

func cmdDomain(args []string) int {
	c, rest, err := parseCommand("domain", args)
	if err != nil {
		return commandParseError(err)
	}
	if code := rejectUnsupportedOCR(c, "domain"); code != 0 {
		return code
	}
	setupLogging(c)
	if code := c.mlPreflight(); code != 0 {
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
				fs := collectFindings(ctx, c, cfg, det, eng, vset, items, c.dedupe)
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
	eng, err := loadEngine(c)
	if err != nil {
		logx.Error("rule setup failed", "err", err)
		return 2
	}
	ctx, stop := rootContext(c)
	defer stop()
	if err := server.Serve(ctx, addr, server.New(det, eng, cfg.Allowed, maxConc)); err != nil {
		logx.Error("server error", "err", err)
		return 2
	}
	return 0
}

func cmdDoctor(args []string) int {
	c, _, err := parseCommand("doctor", args)
	if err != nil {
		return commandParseError(err)
	}
	if code := rejectUnsupportedOCR(c, "doctor"); code != 0 {
		return code
	}
	setupLogging(c)
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
	c, dirs, err := parseCommand("rules", args)
	if err != nil {
		return commandParseError(err)
	}
	sub, out, source := c.cmd.sub, c.output, c.cmd.source
	tagFilter, sevFilter, ruleFiles := c.tags, c.ruleSeverity, c.rules
	check, allowUnsigned := c.cmd.check, c.cmd.allowUnsigned
	userPos := dirs // positionals as given (rule id / test text for show/test)
	if len(dirs) == 0 {
		dirs = []string{"rules"}
	}
	templatePaths := append(append([]string{}, userPos...), ruleFiles...)
	if len(templatePaths) == 0 && (sub == "list" || sub == "validate" || sub == "stats") {
		var err error
		templatePaths, err = defaultQueryRulePaths()
		if err != nil {
			fmt.Fprintln(os.Stderr, "rule discovery error:", err)
			if sub == "validate" {
				return 1
			}
			return 2
		}
	}

	switch sub {
	case "export":
		data := taxonomy.DefaultYAML()
		// Exported taxonomy contains public detector definitions, not credentials.
		if err := writeArtifactBytes(out, data, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 2
		}
		if out == "" {
			return 0
		}
		fmt.Fprintf(os.Stderr, "exported built-in taxonomy to %s — edit and use with --taxonomy %s\n", out, out)
		return 0

	case "list":
		eng, err := rules.Load(templatePaths...)
		if err != nil {
			fmt.Fprintln(os.Stderr, "rule load error:", err)
			return 2
		}
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
		eng, err := loadRulesForQuery(ruleFiles...)
		if err != nil {
			fmt.Fprintln(os.Stderr, "rule load error:", err)
			return 2
		}
		return renderRuleShow(eng, userPos[0])

	case "test":
		if len(userPos) == 0 {
			fmt.Fprintln(os.Stderr, "usage: prowl rules test <text>   (which rules fire on this string)")
			return 2
		}
		eng, err := loadRulesForQuery(ruleFiles...)
		if err != nil {
			fmt.Fprintln(os.Stderr, "rule load error:", err)
			return 2
		}
		return renderRulesTest(eng, strings.Join(userPos, " "))

	case "search":
		if len(userPos) == 0 {
			fmt.Fprintln(os.Stderr, "usage: prowl rules search <term>   (id / tag / description, built-ins + templates)")
			return 2
		}
		eng, err := loadRulesForQuery(ruleFiles...)
		if err != nil {
			fmt.Fprintln(os.Stderr, "rule load error:", err)
			return 2
		}
		return renderRulesSearch(strings.Join(userPos, " "), eng)

	case "validate":
		issues := rules.ValidateDir(templatePaths...)
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
		eng, loadErr := rules.Load(templatePaths...)
		if loadErr != nil && nerr == 0 {
			fmt.Fprintln(os.Stderr, "rule load error:", loadErr)
			nerr++
		}
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
		eng, err := rules.Load(templatePaths...)
		if err != nil {
			fmt.Fprintln(os.Stderr, "rule load error:", err)
			return 2
		}
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
	c, dirs, err := parseCommand("verifiers", args)
	if err != nil {
		return commandParseError(err)
	}
	sub, source, check, allowUnsigned := c.cmd.sub, c.cmd.source, c.cmd.check, c.cmd.allowUnsigned
	if sub == "update" {
		return updateInto("verifiers", source, installedVerifiersDir(), time.Now().UTC().Format(time.RFC3339), check, allowUnsigned)
	}
	if len(dirs) == 0 {
		var err error
		dirs, err = discoverVerifierDirs(nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, "verifier discovery error:", err)
			if sub == "validate" || sub == "manifest" {
				return 1
			}
			return 2
		}
		if len(dirs) == 0 {
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
			fmt.Fprintln(os.Stderr, "verifier load error:", err)
			return 2
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
	for _, f := range fs {
		if model.IsIncompleteFinding(f) {
			logx.Error("scan results are incomplete — failing closed")
			return 2
		}
	}
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

// matchesAny reports whether s contains any of the (non-empty) substrings.
func matchesAny(s string, subs []string) bool {
	for _, sub := range subs {
		if sub != "" && strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
