package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/ocr"
	"github.com/Lercas/prowl/tool/internal/scan"
	"github.com/Lercas/prowl/tool/internal/source"
)

func cmdScan(args []string) int {
	c, rest, err := parseCommand("scan", args)
	if err != nil {
		return commandParseError(err)
	}
	if code := checkSourceModes(c, rest); code != 0 {
		return code
	}
	warnMissingPaths(rest)
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
		fmt.Fprintln(os.Stderr, "compare does not support stdin")
		return 2
	}
	if c.ocrEnabled {
		fmt.Fprintln(os.Stderr, "compare does not support --ocr")
		return 2
	}
	if c.verify || c.verifyAll || c.verifiedOnly || c.failOnVerified {
		fmt.Fprintln(os.Stderr, "compare does not support provider verification")
		return 2
	}
	if c.mlURL != "" {
		fmt.Fprintln(os.Stderr, "compare requires an in-process model; --ml-url is not supported")
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
	if c.format != "pretty" && c.format != "json" {
		logx.Error("compare supports only pretty or json output")
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

	// With no explicit mode, compare defaults to the current tree even when stdin is not a TTY.
	if len(rest) == 0 && !c.staged && c.since == "" && !c.history {
		rest = []string{"."}
	}

	mlC := c
	mlC.mlEmbed = true
	mlC.verifiedOnly, mlC.maxPerFile = false, 0
	if code := mlC.mlPreflight(); code != 0 {
		return code
	}
	prepared := prepareScan(mlC, scan.Options{Detector: det, Rules: eng, Allow: cfg.Allowed})
	if prepared.mlError != nil {
		logx.Error("ML setup failed", "err", prepared.mlError)
		return 2
	}
	comparison, err := prepared.pipeline.Compare(ctx, func(ctx context.Context) (<-chan model.Item, error) {
		return scanInput(ctx, c, rest)
	})
	if err != nil {
		logx.Error("comparison failed", "err", err)
		writeComparisonFailure(c)
		return 2
	}
	raw, kept := applyReportFilters(c, comparison.Raw), applyReportFilters(c, comparison.Kept)
	if c.dedupe {
		raw, kept = dedupeFingerprints(raw), dedupeFingerprints(kept)
		// Retained values may survive at a different occurrence than the raw dedupe winner.
		retained := map[string]model.Finding{}
		for _, f := range kept {
			retained[f.Fingerprint] = f
		}
		for i, f := range raw {
			if survivor, ok := retained[f.Fingerprint]; ok {
				raw[i] = survivor
			}
		}
	}

	if err := writeComparison(ctx, c, raw, kept); err != nil {
		logx.Error("cannot write comparison", "err", err)
		return 2
	}
	return 0
}

func compareKey(f model.Finding) string {
	return f.Fingerprint + "\x00" + f.Source + "\x00" + f.Path + "\x00" + f.Type + "\x00" + strconv.Itoa(f.Line) + ":" + strconv.Itoa(f.Col) + ":" + strconv.Itoa(f.ByteStart) + ":" + strconv.Itoa(f.ByteEnd)
}

// printCompare renders the regex-baseline -> Prowl funnel and a breakdown of what the ML suppressed.
func printCompare(raw, kept []model.Finding) { fmt.Print(formatCompare(raw, kept)) }

func formatCompare(raw, kept []model.Finding) string {
	var b strings.Builder
	keptSet := make(map[string]int, len(kept))
	for _, f := range kept {
		keptSet[compareKey(f)]++
	}
	byType := map[string]int{}
	var sample []model.Finding
	suppressed := 0
	for _, f := range raw {
		if keptSet[compareKey(f)] > 0 {
			keptSet[compareKey(f)]--
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
	fmt.Fprintf(&b, "\nProwl compare — fixed candidates vs the ML-filtered set\n\n")
	fmt.Fprintf(&b, "  before local L2 (fixed candidates):  %6d findings\n", n)
	fmt.Fprintf(&b, "  after Prowl's ML context filter:     %6d findings\n", m)
	fmt.Fprintf(&b, "  -----------------------------------------------------\n")
	fmt.Fprintf(&b, "  suppressed by ML as not-a-secret:    %6d  (%.0f%%)\n", suppressed, pct)
	fmt.Fprintf(&b, "\n  (Input and candidate discovery run once; counts follow duplicate handling.\n")
	fmt.Fprintf(&b, "   Accuracy and credential validity require separate validation.)\n")
	if suppressed == 0 {
		fmt.Fprintf(&b, "\n  No displayed candidate identities were removed by local L2.\n\n")
		return b.String()
	}
	type tc struct {
		typ string
		n   int
	}
	tcs := make([]tc, 0, len(byType))
	for t, c := range byType {
		tcs = append(tcs, tc{t, c})
	}
	sort.Slice(tcs, func(i, j int) bool {
		if tcs[i].n == tcs[j].n {
			return tcs[i].typ < tcs[j].typ
		}
		return tcs[i].n > tcs[j].n
	})
	fmt.Fprintf(&b, "\n  suppressed by detector type:\n")
	for i, t := range tcs {
		if i >= 8 {
			fmt.Fprintf(&b, "    %6d  … and %d more types\n", 0, len(tcs)-8)
			break
		}
		fmt.Fprintf(&b, "    %6d  %s\n", t.n, logx.SanitizeTerminal(t.typ))
	}
	fmt.Fprintf(&b, "\n  examples Prowl silenced:\n")
	for _, f := range sample {
		// f.Path/Type/Redacted come from a (possibly hostile) scanned repo — strip terminal escapes.
		fmt.Fprintf(&b, "    %s:%d  %s  %s\n", logx.SanitizeTerminal(f.Path), f.Line,
			logx.SanitizeTerminal(f.Type), logx.SanitizeTerminal(f.Redacted))
	}
	fmt.Fprintln(&b)
	return b.String()
}

// checkSourceModes rejects mutually-exclusive scan inputs (--staged / --since / --history / '-' stdin /
// paths) with a clear message instead of letting one silently win.
func checkSourceModes(c commonFlags, rest []string) int {
	if err := stdinModeError(c, rest); err != nil {
		logx.Error(err.Error())
		return 2
	}
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

// stdinModeError validates the label before configuration, reports or input I/O.
func stdinModeError(c commonFlags, rest []string) error {
	if c.crossFile {
		if len(rest) == 0 && !isTTY(os.Stdin) {
			return fmt.Errorf("--cross-file requires explicit local filesystem roots when stdin is piped")
		}
		for _, path := range rest {
			if path == "-" {
				return fmt.Errorf("--cross-file does not support stdin")
			}
		}
	}
	if c.stdinName != "" && (c.staged || c.since != "" || c.history || c.gitTimeline || len(rest) > 1 || (len(rest) == 1 && rest[0] != "-")) {
		return fmt.Errorf("--stdin-name applies to stdin only; it cannot be combined with paths or Git modes")
	}
	return nil
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
	if code := c.scanPreflight(); code != 0 {
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
		c.indexCoverageComplete = func() bool { stats := ocrEngine.Stats(); return stats.Failures == 0 && stats.Skipped == 0 }
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
	eng, err := loadConfiguredEngine(c, cfg)
	if err != nil {
		logx.Error("rule setup failed", "err", err)
		return 2
	}
	if code := detectorPreflight(c, tax, eng); code != 0 {
		return code
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
	code := prepareScan(c, scan.Options{Detector: det, Rules: eng, Verifiers: vset, Allow: cfg.Allowed}).Run(ctx, items)
	return finalizeOCR(ocrEngine, code)
}

// scanInput selects the same source for scan and compare, including Git's staged blob content.
func scanInput(ctx context.Context, c commonFlags, rest []string) (<-chan model.Item, error) {
	return scanInputAt(ctx, c, rest, "")
}

func scanInputAt(ctx context.Context, c commonFlags, rest []string, repoDir string) (<-chan model.Item, error) {
	if err := stdinModeError(c, rest); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.crossFile {
		ctx = source.WithCredentialScopes(ctx)
	}
	switch {
	case c.staged || c.since != "":
		mode, rev := "staged", ""
		if c.since != "" {
			mode, rev = "since", c.since
		}
		if !source.IsGitRepo(repoDir) {
			return nil, fmt.Errorf("--%s needs a git repository, but this is not one", mode)
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
		if c.gitTimeline {
			return source.GitTimelineBlobs(ctx, repoDir, c.exclude, c.maxSize), nil
		}
		return source.GitHistoryBlobs(ctx, repoDir, c.exclude, c.maxSize), nil
	case c.stdinName != "":
		return source.StdinNamed(ctx, c.stdinName, c.maxSize), nil
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

// failClosedIfIncomplete raises a clean exit to non-zero when the scan didn't finish (timeout or
// signal): an incomplete scan can't certify "no secrets". Partial results are still written.
func failClosedIfIncomplete(ctx context.Context, code int) int {
	if ctx.Err() != nil {
		logx.Error("scan did not complete (timeout/interrupt) — failing closed; partial results may miss secrets")
		return 2
	}
	return code
}

// mlPreflight fails closed: if --ml/--ml-model was requested but cannot load (e.g. a bad
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
		if hint := installedModelHint(c.mlModel); hint != "" {
			fmt.Fprintln(os.Stderr, hint)
		}
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

// installedModelHint explains the one cause a user cannot guess from the error: no --ml-model was
// given, yet a model file left in the install directory by an earlier version is picked up
// automatically and no longer matches this version's feature extractor.
func installedModelHint(explicit string) string {
	if explicit != "" {
		return ""
	}
	path := filepath.Join(prowlHome(), "model_binary.json")
	if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
		return ""
	}
	return "prowl: the model was loaded from " + path + ", installed by an earlier version.\n" +
		"       Move that file away to use the model built into this release, or retrain it."
}
