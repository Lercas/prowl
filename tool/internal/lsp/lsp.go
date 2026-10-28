// Package lsp is a minimal Language Server Protocol server: editors connect over stdio and get
// real-time secret diagnostics as you type, powered by the same L1 cascade.
package lsp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Lercas/prowl/tool/internal/checkedio"
	"github.com/Lercas/prowl/tool/internal/config"
	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/forge"
	"github.com/Lercas/prowl/tool/internal/localfile"
	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/resilience"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/saferegex"
	"github.com/Lercas/prowl/tool/internal/scan"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
	"github.com/Lercas/prowl/tool/internal/verify"
	bundledrules "github.com/Lercas/prowl/tool/rules"
)

// maxMessageBytes caps a single JSON-RPC frame so a hostile Content-Length (negative -> makeslice
// panic, or huge -> multi-GB allocation) can't crash or OOM the server.
const maxMessageBytes = 16 << 20 // 16 MiB

// defaultMaxScanBytes mirrors the CLI's --max-size default: a larger document is skipped so a
// multi-MB paste can't block the read loop. Overridden by performance.max_size from .prowl.yaml.
const defaultMaxScanBytes = 10 << 20 // 10 MiB

// debounceWindow coalesces a burst of didChange edits into one scan of the final text, so typing
// doesn't peg the CPU.
const debounceWindow = 200 * time.Millisecond

// engine bundles the detector, rule engine, and allowlist so LSP diagnostics match `prowl scan` for
// the same workspace.
type engine struct {
	det      *detect.Detector
	eng      *rules.Engine
	allow    func(value, path string) bool // cfg.Allowed: allowlisted values/paths/regex/stopwords
	maxBytes int                           // per-document size cap (CLI --max-size parity); <=0 -> no cap
}

// Serve runs the LSP loop on stdin/stdout until the client exits, building the same detector + rule
// engine + allowlist a workspace `prowl scan` would so in-editor diagnostics match the CLI.
func Serve() error {
	return ServeWithBundled(false)
}

// ServeWithBundled selects the release's embedded rules without changing workspace identity/config.
func ServeWithBundled(bundled bool) error {
	e, err := buildWithBundled(bundled)
	if err != nil {
		return err
	}
	return serve(os.Stdin, os.Stdout, e)
}

func serve(input io.Reader, output io.Writer, e *engine) (resultErr error) {
	r := bufio.NewReader(input)
	// Serialize writes so the read loop and debounce scan goroutines don't interleave frame bytes.
	sw := newSafeWriter(bufio.NewWriter(checkedio.NewWriter(output)))
	if closer, ok := input.(io.Closer); ok {
		// A background publication can fail while the read loop is idle. Closing the owned
		// input stream wakes that read so the transport error can terminate the session.
		sw.onFailure = func() { _ = closer.Close() }
	}
	// The debouncer runs scans off the read loop so the loop stays responsive during a scan.
	d := newDebouncer(e, sw, debounceWindow)
	defer func() {
		d.stop()
		// A publication already holding the lifecycle lock can fail while EOF/exit cleanup
		// waits for it. Its final output failure must not be replaced by a successful return.
		if err := sw.Err(); err != nil {
			resultErr = err
		}
	}()
	s := &session{w: sw, e: e, d: d}
	for {
		if err := sw.Err(); err != nil {
			return err
		}
		body, err := readMessage(r)
		if outputErr := sw.Err(); outputErr != nil {
			return outputErr
		}
		if err != nil {
			if errors.Is(err, errBadFrame) {
				logx.Warn("lsp: skipping invalid frame content type")
				respondError(sw, nil, parseError)
				continue // A unique bounded Content-Length was consumed; the next boundary is known.
			}
			if errors.Is(err, io.EOF) {
				return nil // clean EOF between frames
			}
			return err
		}
		exit, err := s.handle(body)
		if outputErr := sw.Err(); outputErr != nil {
			return outputErr
		}
		if exit {
			return err
		}
	}
}

// build assembles the detector, rule engine, and allowlist as a flagless workspace `prowl scan`
// would: auto-discovered .prowl.yaml, its enable/disable/custom/tuning, and ~/.prowl/rules
// templates — so editor findings line up with the CLI.
func build() (*engine, error) {
	return buildWithBundled(false)
}

func buildWithBundled(bundled bool) (*engine, error) {
	cfg, err := config.Discover()
	if err != nil {
		return nil, err
	}
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		return nil, err
	}
	if err := taxonomy.RequireComplete(tax); err != nil {
		return nil, err
	}
	name, err := taxonomy.DiscoverGitleaks()
	if err != nil {
		return nil, err
	}
	if name != "" {
		ext, al, err := taxonomy.LoadAny(name)
		if err != nil {
			return nil, err
		}
		if err := taxonomy.RequireComplete(ext); err != nil {
			return nil, fmt.Errorf("rules %q: %w", name, err)
		}
		tax.Types = append(tax.Types, ext.Types...)
		if al != nil {
			cfg.MergeAllowlist(al.Regexes, al.Paths, al.StopWords)
		}
		logx.Info("lsp: auto-loaded gitleaks config", "file", name, "rules", len(ext.Types))
	}
	// An in-workspace .prowl.yaml is attacker-controlled; warn loudly if it suppresses detection so a
	// malicious config can't silently blind the editor (the LSP takes no flags, so every config is in-repo).
	warnInRepoSuppression(cfg, tax)
	if err := applyConfig(tax, cfg); err != nil {
		return nil, err
	} // Same policy validation as the CLI.
	applyTuning(cfg) // detection thresholds + operational limits, exactly as loadConfig does
	maxBytes := defaultMaxScanBytes
	if cfg.Performance.MaxSize > 0 { // CLI --max-size parity: a .prowl.yaml can raise/lower the cap
		maxBytes = int(cfg.Performance.MaxSize)
	}
	e := &engine{det: detect.New(tax), allow: cfg.Allowed, maxBytes: maxBytes}
	dir, err := installedRulesDir()
	if err != nil {
		return nil, err
	}
	if dir != "" && !bundled {
		e.eng, err = rules.Load(dir)
	} else {
		e.eng, err = rules.LoadEmbedded(bundledrules.Files)
	}
	if err != nil {
		return nil, fmt.Errorf("lsp: selected rule templates failed to load: %w", err)
	}
	logx.Info("lsp: loaded rule templates", "count", e.eng.Len())
	return e, nil
}

// warnInRepoSuppression logs a warning when an auto-discovered (untrusted) .prowl.yaml suppresses
// detection via detectors.disable, allowlist.*, detection/ml tuning, or an enable list that resolves
// to zero detectors. The enable case is LSP-specific: `enable: [bogus]` silently kills the entire
// taxonomy with no other visible signal in an editor. tax is the full taxonomy evaluated before
// applyConfig prunes it, so a real enable list can be told from a bogus one; a defaults-only config
// (empty LoadedFrom) is never flagged.
func warnInRepoSuppression(cfg *config.Config, tax *taxonomy.Taxonomy) {
	if cfg == nil {
		return
	}
	p := cfg.LoadedFrom()
	if p == "" {
		return // built-in defaults, not an in-repo file — nothing to warn about
	}
	allow := len(cfg.Allowlist.Regexes) + len(cfg.Allowlist.Values) + len(cfg.Allowlist.StopWords) + len(cfg.Allowlist.Paths)
	tuning := cfg.Detection.GenericEntropyMin > 0 || cfg.Detection.PlaceholderMaxEntropy > 0 ||
		cfg.Detection.MaxMatchesPerFile > 0 || cfg.Performance.MLThreshold > 0
	enableKillsAll := enableResolvesToZero(cfg, tax)
	if len(cfg.Detectors.Disable) == 0 && allow == 0 && !tuning && !enableKillsAll {
		return // a normal in-repo config (e.g. just `exclude`, or a real enable list) — no warning
	}
	logx.Warn("lsp: in-repo .prowl.yaml suppresses detection — editor diagnostics may be blinded",
		"path", p, "disabled_detectors", len(cfg.Detectors.Disable), "allowlist_rules", allow,
		"detection_tuning", tuning, "enable_kills_all_detectors", enableKillsAll)
}

// enableResolvesToZero reports whether a non-empty detectors.enable list names no known detector —
// a total kill-switch. It reuses config.TypeEnabled (the resolver applyConfig prunes with) so the
// warning and the actual pruning can never disagree. An empty enable list is not a kill-switch.
func enableResolvesToZero(cfg *config.Config, tax *taxonomy.Taxonomy) bool {
	if cfg == nil || len(cfg.Detectors.Enable) == 0 || tax == nil {
		return false
	}
	for _, t := range tax.Types {
		if cfg.TypeEnabled(t.ID) {
			return false // at least one real detector survives — a legitimate enable list
		}
	}
	return true // a non-empty enable list left zero detectors active: total kill-switch
}

// applyTuning applies the config's detection thresholds and operational limits the same way the CLI
// does, so in-editor diagnostics don't diverge from `prowl scan`. These are process-wide and set
// once before any scan; zero/empty values are ignored, preserving the built-in default.
func applyTuning(cfg *config.Config) {
	if cfg == nil {
		return
	}
	detect.ApplyTuning(cfg.Detection.GenericEntropyMin, cfg.Detection.PlaceholderMaxEntropy, cfg.Detection.MaxMatchesPerFile)
	forge.SetMaxPages(cfg.Limits.OrgMaxPages)
	verify.SetConcurrency(cfg.Performance.VerifyConcurrency)
}

// applyConfig filters the taxonomy by the config's enable/disable lists and appends its custom
// detectors — the same transformation the CLI applies, so both build an identical detector.
func applyConfig(tax *taxonomy.Taxonomy, cfg *config.Config) error {
	if cfg == nil {
		return nil
	}
	kept := tax.Types[:0]
	for _, t := range tax.Types {
		if cfg.TypeEnabled(t.ID) {
			kept = append(kept, t)
		}
	}
	tax.Types = kept
	for _, cr := range cfg.Detectors.Custom {
		// saferegex caps an attacker-controlled custom-rule regex from an in-workspace .prowl.yaml (a
		// bare regexp.Compile would let a packed bounded-repetition bomb OOM-kill the editor on open).
		re, err := saferegex.Compile(cr.Regex)
		if err != nil {
			return fmt.Errorf("lsp: custom rule %q has invalid regex: %w", cr.ID, err)
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
	return nil
}

// installedRulesDir returns the installed template dir (~/.prowl/rules, or PROWL_HOME/XDG override)
// if it exists, else "". A broken installed path is fatal, as it is for a flagless CLI scan.
func installedRulesDir() (string, error) {
	var home string
	switch {
	case os.Getenv("PROWL_HOME") != "":
		home = os.Getenv("PROWL_HOME")
	case os.Getenv("XDG_CONFIG_HOME") != "":
		home = filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "prowl")
	default:
		h, err := os.UserHomeDir()
		if err != nil {
			home = ".prowl"
		} else {
			home = filepath.Join(h, ".prowl")
		}
	}
	return localfile.FirstDirectory(filepath.Join(home, "rules"))
}

// dispatch handles a single decoded request/notification. Control and lifecycle messages run
// synchronously; document changes go through the debouncer so a keystroke burst coalesces into one
// off-loop scan.
func dispatch(w *safeWriter, e *engine, d *debouncer, method string, id, params json.RawMessage) {
	switch method {
	case "initialize":
		respond(w, id, map[string]any{
			"capabilities": map[string]any{"textDocumentSync": map[string]any{
				"openClose": true,
				"change":    1, // Full document sync.
				"save":      map[string]any{"includeText": true},
			}},
			"serverInfo": map[string]any{"name": "prowl", "version": "0.1.0"},
		})
	case "textDocument/didOpen":
		// Single event, possibly a large file — publish immediately (the size cap still bounds work).
		if update, ok := openParams(params); ok {
			d.open(update)
		}
	case "textDocument/didChange":
		// Keystrokes: debounce so we scan the final text once, not N times for N keystrokes.
		if update, ok := changeParams(params); ok {
			d.change(update)
		}
	case "textDocument/didSave":
		// A full-text save re-scans promptly; the saved text supersedes any in-flight change scan.
		uri, text, hasText := saveParams(params)
		if hasText {
			d.save(uri, text)
		}
	case "textDocument/didClose":
		// Drop any pending scan and clear markers (an empty set) so a closed file shows no stale diagnostics.
		if uri, ok := closeParams(params); ok {
			d.closeDocument(uri)
		}
	case "shutdown":
		respond(w, id, nil)
	}
}

// debouncer coalesces rapid didChange edits per document and runs each scan off the read loop. Per
// URI it keeps only the latest text and (re)arms a timer; one scan fires per burst, not per keystroke.
type debouncer struct {
	e      *engine
	w      *safeWriter
	window time.Duration

	mu        sync.Mutex
	documents map[string]*documentScan // pointer identity binds callbacks/results to one revision
	opened    map[string]int32         // latest client version in the current open/close lifetime
	stopped   bool
	wg        sync.WaitGroup // admission under mu prevents Add racing with stop's Wait
}

type documentScan struct {
	timer *time.Timer
	text  string // cleared when the scan starts or is superseded
}

func newDebouncer(e *engine, w *safeWriter, window time.Duration) *debouncer {
	return &debouncer{
		e:         e,
		w:         w,
		window:    window,
		documents: make(map[string]*documentScan),
		opened:    make(map[string]int32),
	}
}

// open starts one client-owned lifetime. A duplicate open cannot replace its current snapshot.
func (d *debouncer) open(update documentUpdate) {
	d.mu.Lock()
	_, exists := d.opened[update.uri]
	if d.stopped || exists {
		d.mu.Unlock()
		return
	}
	d.opened[update.uri] = update.version
	revision := d.immediateLocked(update.uri)
	d.mu.Unlock()
	d.scan(update.uri, revision, update.text)
}

// change admits strictly newer versions only. An empty change list advances the version without
// cancelling work for the unchanged text; malformed changes never reach this admission boundary.
func (d *debouncer) change(update documentUpdate) {
	d.mu.Lock()
	defer d.mu.Unlock()
	version, exists := d.opened[update.uri]
	if d.stopped || !exists || update.version <= version {
		return
	}
	d.opened[update.uri] = update.version
	if update.hasText {
		d.scheduleLocked(update.uri, update.text)
	}
}

// Save notifications have no version; within an open lifetime their full text is authoritative.
func (d *debouncer) save(uri, text string) {
	d.mu.Lock()
	_, exists := d.opened[uri]
	if d.stopped || !exists {
		d.mu.Unlock()
		return
	}
	revision := d.immediateLocked(uri)
	d.mu.Unlock()
	d.scan(uri, revision, text)
}

func (d *debouncer) closeDocument(uri string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, exists := d.opened[uri]
	if d.stopped || !exists {
		return
	}
	d.closeLocked(uri)
}

// schedule records the latest text for uri and (re)arms the debounce timer. Repeated calls within the
// window collapse to a single scan of the final text.
func (d *debouncer) schedule(uri, text string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stopped {
		return
	}
	d.scheduleLocked(uri, text)
}

func (d *debouncer) scheduleLocked(uri, text string) {
	d.invalidateLocked(uri)
	revision := &documentScan{text: text}
	d.documents[uri] = revision
	// Reset cannot retract an expired AfterFunc callback already waiting for mu.
	revision.timer = time.AfterFunc(d.window, func() { d.fire(uri, revision) })
}

// fire admits only the revision whose timer fired, even if an older callback is still running.
func (d *debouncer) fire(uri string, revision *documentScan) {
	d.mu.Lock()
	if d.stopped || revision == nil || d.documents[uri] != revision || revision.timer == nil {
		d.mu.Unlock()
		return
	}
	text := revision.text
	revision.text = ""
	revision.timer = nil
	d.wg.Add(1)
	d.mu.Unlock()
	d.scan(uri, revision, text)
}

// immediate supersedes pending and in-flight work before scanning an open/save snapshot.
func (d *debouncer) immediate(uri, text string) {
	d.mu.Lock()
	if d.stopped {
		d.mu.Unlock()
		return
	}
	revision := d.immediateLocked(uri)
	d.mu.Unlock()
	d.scan(uri, revision, text)
}

func (d *debouncer) immediateLocked(uri string) *documentScan {
	d.invalidateLocked(uri)
	revision := &documentScan{}
	d.documents[uri] = revision
	d.wg.Add(1)
	return revision
}

func (d *debouncer) scan(uri string, revision *documentScan, text string) {
	defer d.wg.Done()
	resilience.Guard(
		func() {
			diags := scanDiagnostics(d.e, uri, text)
			d.mu.Lock()
			defer d.mu.Unlock()
			if !d.stopped && d.documents[uri] == revision {
				// Publication and invalidation share mu: no newer event can slip between check and write.
				notify(d.w, "textDocument/publishDiagnostics", map[string]any{"uri": uri, "diagnostics": diags})
			}
		},
		func(any) { logx.Warn("lsp: diagnostics could not be published") },
	)
}

// close invalidates all work for uri before clearing its diagnostics.
func (d *debouncer) close(uri string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stopped {
		return
	}
	d.closeLocked(uri)
}

func (d *debouncer) closeLocked(uri string) {
	delete(d.opened, uri)
	d.invalidateLocked(uri)
	notify(d.w, "textDocument/publishDiagnostics", map[string]any{"uri": uri, "diagnostics": []map[string]any{}})
}

func (d *debouncer) invalidateLocked(uri string) {
	if revision := d.documents[uri]; revision != nil {
		if revision.timer != nil {
			revision.timer.Stop()
		}
		revision.text = ""
		delete(d.documents, uri)
	}
}

// halt rejects new work and suppresses pending/in-flight publications before shutdown is acknowledged.
func (d *debouncer) halt() {
	d.mu.Lock()
	d.stopped = true
	clear(d.opened)
	for uri := range d.documents {
		d.invalidateLocked(uri)
	}
	d.mu.Unlock()
}

// stop also waits for scans already admitted; shutdown itself must not wait for exit or client input.
func (d *debouncer) stop() {
	d.halt()
	d.wg.Wait()
}

// scanDiagnostics converts incomplete work into a resource-scoped warning instead of a clean result.
func scanDiagnostics(e *engine, uri, text string) (diags []map[string]any) {
	resilience.Guard(
		func() { diags = collectDiagnostics(e, uri, text) },
		func(any) {
			// Panic payloads can contain the candidate that was being processed.
			logx.Warn("lsp: scan failed; results are incomplete")
			diags = []map[string]any{incompleteDiagnostic("scan_failed", "Проверка не завершена из-за внутренней ошибки.")}
		},
	)
	return diags
}

func incompleteDiagnostic(code, message string) map[string]any {
	return map[string]any{
		"range": map[string]any{
			"start": map[string]any{"line": 0, "character": 0},
			"end":   map[string]any{"line": 0, "character": 0},
		},
		"severity": 2, "source": "prowl", "code": code, "message": message,
	}
}

// collectDiagnostics shares one candidate budget across both producers. Reaching a limit is
// reported independently of allowlisting and overlap deduplication, as it is in scan.Findings.
func collectDiagnostics(e *engine, uri, text string) []map[string]any {
	diags := []map[string]any{}
	if e.maxBytes > 0 && len(text) > e.maxBytes {
		return []map[string]any{incompleteDiagnostic("document_too_large",
			fmt.Sprintf("Документ не проверен: размер %d байт превышает лимит %d байт.", len(text), e.maxBytes))}
	}
	path := uriToPath(uri) // allowlist path-substring matching needs a filesystem path, not a file:// URI
	// Share final suppression and collision handling with CLI. No verifier or ML is attached here,
	// so typing a document cannot make provider calls or send its contents to a sidecar.
	coverage := model.NewCoverage()
	findings := scan.Findings(model.WithCoverage(context.Background(), coverage), e.det, e.eng, nil, model.Item{Path: path, Text: text, Source: "code"}, e.allow, nil)
	offsets := make([]int, 0, len(findings)*2)
	for _, f := range findings {
		offsets = append(offsets, f.ByteStart, f.ByteEnd)
	}
	positions := offsetPositions(text, offsets)
	for _, f := range findings {
		if model.IsIncompleteFinding(f) {
			diags = append(diags, incompleteDiagnostic(f.Type, "Проверка неполная: "+f.Rationale))
			continue
		}
		if f.ByteEnd <= f.ByteStart {
			continue // truncation markers have no literal source span
		}
		start, end := positions[f.ByteStart], positions[f.ByteEnd]
		diags = append(diags, map[string]any{
			"range": map[string]any{
				"start": map[string]any{"line": start[0], "character": start[1]},
				"end":   map[string]any{"line": end[0], "character": end[1]},
			},
			"severity": ruleLSPSeverity(f.Severity, ""),
			"source":   "prowl",
			"message":  fmt.Sprintf("possible secret: %s (conf %.2f, %s)", f.Type, f.Confidence, f.Stage),
		})
	}
	if complete, _, _ := coverage.Snapshot(); !complete {
		hasIncomplete := false
		for _, f := range findings {
			hasIncomplete = hasIncomplete || model.IsIncompleteFinding(f)
		}
		if !hasIncomplete {
			diags = append(diags, incompleteDiagnostic("scan_incomplete", "Проверка неполная: достигнут лимит или произошла ошибка."))
		}
	}
	return diags
}

// uriToPath converts a file:// URI to a filesystem path (handling percent-encoding) so allowlist
// path rules match as in a CLI scan. Non-file URIs fall through to the raw URI.
func uriToPath(uri string) string {
	if !strings.HasPrefix(uri, "file://") {
		return uri
	}
	u, err := url.Parse(uri)
	if err != nil || u.Path == "" {
		return uri
	}
	return filepath.FromSlash(u.Path)
}

var catLSP = map[string]int{ // 1=Error 2=Warning 3=Info 4=Hint
	"pki": 1, "payment": 1, "db": 1, "cloud": 1, "vcs": 1, "ai": 1,
	"comms": 1, "messaging": 1, "ci": 1, "saas": 1, "observability": 1, "auth": 1,
	"generic": 2,
}

func lspSeverity(cat string, conf float64) int {
	s, ok := catLSP[cat]
	if !ok {
		s = 2
	}
	if conf < 0.7 {
		s = 2 // unverified/generic -> Warning
	}
	return s
}

var sevLSP = map[string]int{ // template severity string -> LSP severity code
	"critical": 1, "high": 1, "medium": 2, "low": 3, "info": 3,
}

// ruleLSPSeverity maps a template hit to an LSP severity: its declared severity if present, else its
// category (same fallback the cascade uses).
func ruleLSPSeverity(sev, cat string) int {
	if s, ok := sevLSP[strings.ToLower(sev)]; ok {
		return s
	}
	return lspSeverity(cat, 0.9)
}

// offsetPos converts a byte offset to a 0-indexed (line, character) LSP position. Per the LSP spec
// the character is a UTF-16 code-unit count from the line start (not bytes), so multibyte UTF-8
// before a secret still highlights the correct span. Astral-plane runes (>0xFFFF) count as 2 units.
func offsetPos(text string, off int) (int, int) {
	if off > len(text) {
		off = len(text)
	}
	line, col := 0, 0
	for i := 0; i < off; {
		r, size := utf8.DecodeRuneInString(text[i:])
		if r == '\n' || r == '\r' {
			line++
			col = 0
			if r == '\r' && i+1 < len(text) && text[i+1] == '\n' {
				i++
			}
			i++
			continue
		}
		if r > 0xFFFF { // encoded as a UTF-16 surrogate pair
			col += 2
		} else {
			col++
		}
		i += size
	}
	return line, col
}

// offsetPositions converts a document's diagnostic endpoints in one forward UTF-8 pass. Calling
// offsetPos for each match would repeatedly scan a minified document from byte zero.
func offsetPositions(text string, offsets []int) map[int][2]int {
	sort.Ints(offsets)
	positions := make(map[int][2]int, len(offsets))
	i, line, col := 0, 0, 0
	for _, off := range offsets {
		bounded := min(max(off, 0), len(text))
		for i < bounded {
			r, size := utf8.DecodeRuneInString(text[i:])
			if r == '\n' || r == '\r' {
				line++
				col = 0
				if r == '\r' && i+1 < len(text) && text[i+1] == '\n' {
					size = 2
				}
			} else if r > 0xffff {
				col += 2
			} else {
				col++
			}
			i += size
		}
		positions[off] = [2]int{line, col}
	}
	return positions
}

// safeWriter serializes JSON-RPC frame writes so concurrent publishers don't interleave bytes and
// desync the client.
type safeWriter struct {
	mu        sync.Mutex
	w         *bufio.Writer
	err       error
	onFailure func() // immutable after the session starts; called once outside mu
}

var errOutput = errors.New("lsp: не удалось записать сообщение")

func newSafeWriter(w *bufio.Writer) *safeWriter { return &safeWriter{w: w} }

func (s *safeWriter) send(v any) {
	s.mu.Lock()
	failed := false
	defer func() {
		if recover() != nil {
			s.err, failed = errOutput, true
		}
		callback := s.onFailure
		s.mu.Unlock()
		if failed && callback != nil {
			callback()
		}
	}()
	if s.err != nil {
		return
	}
	if s.writeLocked(v) != nil {
		// Writer/encoder errors can contain input data. Keep the public failure static.
		s.err, failed = errOutput, true
	}
}

func (s *safeWriter) writeLocked(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(s.w, "Content-Length: %d\r\n\r\n", len(b)); err != nil {
		return err
	}
	if _, err := s.w.Write(b); err != nil {
		return err
	}
	return s.w.Flush()
}

func (s *safeWriter) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func respond(w *safeWriter, id json.RawMessage, result any) {
	w.send(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func notify(w *safeWriter, method string, params any) {
	w.send(map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
}
