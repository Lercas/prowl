// Package lsp is a minimal Language Server Protocol server: editors connect over stdio and get
// real-time secret diagnostics as you type, powered by the same L1 cascade.
package lsp

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Lercas/prowl/tool/internal/config"
	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/forge"
	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/resilience"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/saferegex"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
	"github.com/Lercas/prowl/tool/internal/verify"
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
	e, err := build()
	if err != nil {
		return err
	}
	r := bufio.NewReader(os.Stdin)
	// Serialize writes so the read loop and debounce scan goroutines don't interleave frame bytes.
	sw := newSafeWriter(bufio.NewWriter(os.Stdout))
	// The debouncer runs scans off the read loop so the loop stays responsive during a scan.
	d := newDebouncer(e, sw, debounceWindow)
	defer d.stop()
	for {
		body, err := readMessage(r)
		if err != nil {
			if errors.Is(err, errBadFrame) {
				logx.Warn("lsp: skipping malformed frame", "err", err)
				continue // hostile/garbled header — keep serving rather than disconnect
			}
			return nil // client closed
		}
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if json.Unmarshal(body, &msg) != nil {
			continue
		}
		if msg.Method == "exit" {
			return nil
		}
		// Guard each dispatch so a panic in scanning/diagnostics can't take down the loop.
		resilience.Guard(
			func() { dispatch(sw, e, d, msg.Method, msg.ID, msg.Params) },
			func(rec any) { logx.Warn("lsp: recovered handler panic", "method", msg.Method, "err", rec) },
		)
	}
}

// build assembles the detector, rule engine, and allowlist as a flagless workspace `prowl scan`
// would: auto-discovered .prowl.yaml, its enable/disable/custom/tuning, and ~/.prowl/rules
// templates — so editor findings line up with the CLI.
func build() (*engine, error) {
	cfg := config.Discover() // honor the workspace's own .prowl.yaml (same trust model as `prowl scan`)
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		return nil, err
	}
	// An in-workspace .prowl.yaml is attacker-controlled; warn loudly if it suppresses detection so a
	// malicious config can't silently blind the editor (the LSP takes no flags, so every config is in-repo).
	warnInRepoSuppression(cfg, tax)
	applyConfig(tax, cfg) // disable/enable + custom detectors, exactly as loadDetector does
	applyTuning(cfg)      // detection thresholds + operational limits, exactly as loadConfig does
	maxBytes := defaultMaxScanBytes
	if cfg.Performance.MaxSize > 0 { // CLI --max-size parity: a .prowl.yaml can raise/lower the cap
		maxBytes = int(cfg.Performance.MaxSize)
	}
	e := &engine{det: detect.New(tax), allow: cfg.Allowed, maxBytes: maxBytes}
	if dir := installedRulesDir(); dir != "" {
		eng, err := rules.Load(dir)
		if err != nil {
			logx.Warn("lsp: some rule templates failed to load", "dir", dir, "err", err)
		}
		if eng != nil && eng.Len() > 0 {
			e.eng = eng
			logx.Info("lsp: loaded rule templates", "count", eng.Len(), "dir", dir)
		}
	}
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
func applyConfig(tax *taxonomy.Taxonomy, cfg *config.Config) {
	if cfg == nil {
		return
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
			logx.Warn("lsp: custom rule has bad regex (skipped)", "id", cr.ID, "err", err)
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

// installedRulesDir returns the installed template dir (~/.prowl/rules, or PROWL_HOME/XDG override)
// if it exists, else "" — the same templates a flagless `prowl scan` auto-loads.
func installedRulesDir() string {
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
	dir := filepath.Join(home, "rules")
	if info, err := os.Stat(dir); err == nil && info.IsDir() {
		return dir
	}
	return ""
}

// dispatch handles a single decoded request/notification. Control and lifecycle messages run
// synchronously; document changes go through the debouncer so a keystroke burst coalesces into one
// off-loop scan.
func dispatch(w *safeWriter, e *engine, d *debouncer, method string, id, params json.RawMessage) {
	switch method {
	case "initialize":
		respond(w, id, map[string]any{
			"capabilities": map[string]any{"textDocumentSync": 1}, // 1 = full sync
			"serverInfo":   map[string]any{"name": "prowl", "version": "0.1.0"},
		})
	case "textDocument/didOpen":
		// Single event, possibly a large file — publish immediately (the size cap still bounds work).
		uri, text := openParams(params)
		d.cancel(uri) // drop any pending change scan; the open text is now authoritative
		publish(w, e, uri, text)
	case "textDocument/didChange":
		// Keystrokes: debounce so we scan the final text once, not N times for N keystrokes.
		uri, text := changeParams(params)
		d.schedule(uri, text)
	case "textDocument/didSave":
		// A full-text save re-scans promptly; the saved text supersedes any in-flight change scan.
		uri, text, hasText := saveParams(params)
		if hasText {
			d.cancel(uri)
			publish(w, e, uri, text)
		}
	case "textDocument/didClose":
		// Drop any pending scan and clear markers (an empty set) so a closed file shows no stale diagnostics.
		uri := closeParams(params)
		d.cancel(uri)
		notify(w, "textDocument/publishDiagnostics", map[string]any{"uri": uri, "diagnostics": []map[string]any{}})
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

	mu      sync.Mutex
	timers  map[string]*time.Timer // pending per-doc scan, keyed by URI
	pending map[string]string      // latest text awaiting scan, keyed by URI
	wg      sync.WaitGroup         // tracks in-flight scan goroutines (so stop() can drain them)
}

func newDebouncer(e *engine, w *safeWriter, window time.Duration) *debouncer {
	return &debouncer{
		e:       e,
		w:       w,
		window:  window,
		timers:  make(map[string]*time.Timer),
		pending: make(map[string]string),
	}
}

// schedule records the latest text for uri and (re)arms the debounce timer. Repeated calls within the
// window collapse to a single scan of the final text.
func (d *debouncer) schedule(uri, text string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pending[uri] = text
	if t, ok := d.timers[uri]; ok {
		t.Reset(d.window)
		return
	}
	d.timers[uri] = time.AfterFunc(d.window, func() { d.fire(uri) })
}

// fire scans the latest pending text for uri and publishes. It runs in the timer goroutine (off the
// read loop). Guarded so a scan panic can't crash the process.
func (d *debouncer) fire(uri string) {
	d.mu.Lock()
	text, ok := d.pending[uri]
	delete(d.pending, uri)
	delete(d.timers, uri)
	if !ok { // cancelled between the timer firing and acquiring the lock
		d.mu.Unlock()
		return
	}
	d.wg.Add(1)
	d.mu.Unlock()
	defer d.wg.Done()
	resilience.Guard(
		func() { publish(d.w, d.e, uri, text) },
		func(rec any) { logx.Warn("lsp: recovered scan panic", "uri", uri, "err", rec) },
	)
}

// cancel drops any pending debounced scan for uri (e.g. on close, or when a save/open supersedes it).
func (d *debouncer) cancel(uri string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if t, ok := d.timers[uri]; ok {
		t.Stop()
		delete(d.timers, uri)
	}
	delete(d.pending, uri)
}

// stop halts all pending timers and waits for any in-flight scan to finish. Called on Serve exit.
func (d *debouncer) stop() {
	d.mu.Lock()
	for uri, t := range d.timers {
		t.Stop()
		delete(d.timers, uri)
	}
	d.pending = make(map[string]string)
	d.mu.Unlock()
	d.wg.Wait()
}

// scanDiagnostics scans text with the same detector + rule engine + allowlist the CLI uses and
// returns a diagnostic per surviving finding. Allowlisted findings are suppressed as scan.Run does,
// and a document over the size cap is skipped (--max-size parity).
func scanDiagnostics(e *engine, uri, text string) []map[string]any {
	diags := []map[string]any{}
	if e.maxBytes > 0 && len(text) > e.maxBytes {
		logx.Info("lsp: document over size cap, skipping scan", "uri", uri, "bytes", len(text), "cap", e.maxBytes)
		return diags // matches the CLI skipping a file above --max-size
	}
	path := uriToPath(uri) // allowlist path-substring matching needs a filesystem path, not a file:// URI
	for _, m := range e.det.Scan(text) {
		if e.allow != nil && e.allow(m.Value, path) {
			continue
		}
		sl, sc := offsetPos(text, m.Start)
		el, ec := offsetPos(text, m.End)
		diags = append(diags, map[string]any{
			"range": map[string]any{
				"start": map[string]any{"line": sl, "character": sc},
				"end":   map[string]any{"line": el, "character": ec},
			},
			"severity": lspSeverity(m.Category, m.Confidence),
			"source":   "prowl",
			"message":  fmt.Sprintf("possible secret: %s (conf %.2f, %s)", m.Type, m.Confidence, m.Stage),
		})
	}
	if e.eng != nil { // installed ~/.prowl/rules templates, same as a flagless CLI scan
		for _, h := range e.eng.Match(text) {
			if e.allow != nil && e.allow(h.Value, path) {
				continue
			}
			sl, sc := offsetPos(text, h.Start)
			el, ec := offsetPos(text, h.End)
			diags = append(diags, map[string]any{
				"range": map[string]any{
					"start": map[string]any{"line": sl, "character": sc},
					"end":   map[string]any{"line": el, "character": ec},
				},
				"severity": ruleLSPSeverity(h.Severity, h.Category),
				"source":   "prowl",
				"message":  fmt.Sprintf("possible secret: %s (rule)", h.RuleID),
			})
		}
	}
	return diags
}

// publish scans text and emits a publishDiagnostics notification for uri.
func publish(w *safeWriter, e *engine, uri, text string) {
	diags := scanDiagnostics(e, uri, text)
	notify(w, "textDocument/publishDiagnostics", map[string]any{"uri": uri, "diagnostics": diags})
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
		if r == '\n' {
			line++
			col = 0
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

// errBadFrame signals a malformed Content-Length header; the caller skips the frame
// instead of treating it as a client disconnect.
var errBadFrame = errors.New("lsp: malformed message frame")

// readMessage reads one Content-Length-framed JSON-RPC message, rejecting a negative or oversized
// length so a hostile frame can't panic make() or trigger a multi-GB allocation. A bad frame is
// rejected without draining its claimed byte count (that would swallow following frames up to EOF);
// instead the next ReadString resyncs by matching Content-Length anywhere in a header line, so the
// server keeps answering requests after a malformed frame instead of going silent.
func readMessage(r *bufio.Reader) ([]byte, error) {
	length := -1
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		// Resync-tolerant: accept a Content-Length token even with prior-frame garbage glued to the front.
		low := strings.ToLower(line)
		if i := strings.Index(low, "content-length:"); i >= 0 {
			n, err := strconv.Atoi(strings.TrimSpace(line[i+len("content-length:"):]))
			if err != nil {
				length = -1 // unparseable -> reject below
				continue
			}
			length = n
		}
	}
	if length < 0 || length > maxMessageBytes {
		// Don't drain the claimed count (it would consume the next valid frame); the next ReadString
		// resyncs on the following frame's Content-Length, matched as a substring above.
		return nil, fmt.Errorf("%w: content-length=%d (cap %d)", errBadFrame, length, maxMessageBytes)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// safeWriter serializes JSON-RPC frame writes so concurrent publishers don't interleave bytes and
// desync the client.
type safeWriter struct {
	mu sync.Mutex
	w  *bufio.Writer
}

func newSafeWriter(w *bufio.Writer) *safeWriter { return &safeWriter{w: w} }

func (s *safeWriter) send(v any) {
	b, _ := json.Marshal(v)
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Fprintf(s.w, "Content-Length: %d\r\n\r\n", len(b))
	s.w.Write(b)
	s.w.Flush()
}

func respond(w *safeWriter, id json.RawMessage, result any) {
	w.send(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func notify(w *safeWriter, method string, params any) {
	w.send(map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
}

func openParams(p json.RawMessage) (string, string) {
	var v struct {
		TextDocument struct {
			URI  string `json:"uri"`
			Text string `json:"text"`
		} `json:"textDocument"`
	}
	json.Unmarshal(p, &v)
	return v.TextDocument.URI, v.TextDocument.Text
}

func changeParams(p json.RawMessage) (string, string) {
	var v struct {
		TextDocument struct {
			URI string `json:"uri"`
		} `json:"textDocument"`
		ContentChanges []struct {
			Text string `json:"text"`
		} `json:"contentChanges"`
	}
	json.Unmarshal(p, &v)
	text := ""
	if len(v.ContentChanges) > 0 {
		text = v.ContentChanges[len(v.ContentChanges)-1].Text
	}
	return v.TextDocument.URI, text
}

// closeParams extracts the URI of a didClose notification (used to clear its diagnostics).
func closeParams(p json.RawMessage) string {
	var v struct {
		TextDocument struct {
			URI string `json:"uri"`
		} `json:"textDocument"`
	}
	json.Unmarshal(p, &v)
	return v.TextDocument.URI
}

// saveParams extracts the URI and optional full text of a didSave notification. hasText is false
// when the client omitted the text, in which case the caller keeps the existing diagnostics.
func saveParams(p json.RawMessage) (uri, text string, hasText bool) {
	var v struct {
		TextDocument struct {
			URI string `json:"uri"`
		} `json:"textDocument"`
		Text *string `json:"text"`
	}
	json.Unmarshal(p, &v)
	if v.Text != nil {
		return v.TextDocument.URI, *v.Text, true
	}
	return v.TextDocument.URI, "", false
}
