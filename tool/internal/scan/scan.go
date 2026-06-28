// Package scan orchestrates Source -> Detector -> Findings concurrently.
package scan

import (
	"context"
	"fmt"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/resilience"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
	"github.com/Lercas/prowl/tool/internal/verify"
)

// allowPragmas are inline line-level suppression markers (detect-secrets / gitleaks compatible).
var allowPragmas = []string{"prowl:allow", "pragma: allowlist secret", "gitleaks:allow", "noqa: secret"}

// revealSecrets makes a finding's Redacted field hold the FULL unredacted value (--show-secrets).
// Off by default, so the raw value never leaves the process unless explicitly requested. Set once
// before Run.
var revealSecrets atomic.Bool

// SetRevealSecrets toggles whether findings carry the unredacted secret value (--show-secrets).
func SetRevealSecrets(v bool) { revealSecrets.Store(v) }

func redactValue(raw string) string {
	if revealSecrets.Load() {
		return raw
	}
	return model.Redact(raw)
}

var categorySeverity = map[string]string{
	"pki": "critical", "payment": "critical", "db": "critical",
	"cloud": "high", "vcs": "high", "ai": "high", "comms": "high", "messaging": "high",
	"ci": "high", "saas": "high", "observability": "high", "auth": "high",
	"generic": "medium",
}

func severityFor(category string, conf float64) string {
	s, ok := categorySeverity[category]
	if !ok {
		s = "medium"
	}
	if conf < 0.7 && s == "critical" {
		s = "high"
	}
	return s
}

var sevRank = []string{"low", "medium", "high", "critical"}

func demoteOne(sev string) string {
	for i, s := range sevRank {
		if s == sev && i > 0 {
			return sevRank[i-1]
		}
	}
	return "low"
}

var exampleSegments = map[string]bool{
	"test": true, "tests": true, "spec": true, "specs": true, "__tests__": true,
	"fixtures": true, "fixture": true, "mocks": true, "mock": true,
	"examples": true, "example": true, "testdata": true, "sample": true, "samples": true,
}
var exampleSuffixes = []string{".example", ".sample", ".dist", ".template", ".tpl", ".lock"}
var exampleNameHints = []string{"example", "sample", "dummy", "mock", "fixture", "_test."}

// isExamplePath flags test/fixture/example dirs, *.example/*.sample/*.lock files, and example-ish
// filenames, which mostly hold fake secrets.
func isExamplePath(path string) bool {
	p := strings.ToLower(path)
	for _, s := range exampleSuffixes {
		if strings.HasSuffix(p, s) {
			return true
		}
	}
	for _, seg := range strings.Split(p, "/") {
		if exampleSegments[seg] {
			return true
		}
	}
	base := p
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		base = p[i+1:]
	}
	for _, m := range exampleNameHints {
		if strings.Contains(base, m) {
			return true
		}
	}
	return false
}

// lockfileBasenames are dependency-lock manifests: scanned, but their generic hash-noise findings are
// dropped (see the Findings loop) while a typed credential is still reported. Human-edited manifests
// (go.mod, package.json) are deliberately absent — they hold real tokens.
var lockfileBasenames = map[string]bool{
	"go.sum": true, "package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true,
	"npm-shrinkwrap.json": true, "Cargo.lock": true, "composer.lock": true, "Gemfile.lock": true,
	"poetry.lock": true, "Pipfile.lock": true,
}

func isLockfile(path string) bool {
	base := path
	if i := strings.LastIndexAny(path, "/\\"); i >= 0 {
		base = path[i+1:]
	}
	return lockfileBasenames[base]
}

// lockfileNoiseTypes are the only generic types dropped inside a lockfile: the catch-all matchers that
// fire on package integrity hashes (go.sum h1:…, npm sha512-…). Credential-bearing generics
// (basic_auth_header, generic_password — a user:token@registry URL is a real leak) are kept.
var lockfileNoiseTypes = map[string]bool{
	"generic_high_entropy": true, // \b[A-Za-z0-9+/]{32,}\b — a module/integrity hash in a lockfile
	"generic_api_key":      true, // context-detected key cue, but in a lockfile it's hash/version noise
}

var commentPrefixes = []string{"//", "#", "/*", "* ", "--", "<!--", ";"}

// adjustSeverity demotes low-evidence matches in example/test paths or comments. Checksum matches
// are never demoted; generic ones drop to "low", structured ones drop one step. pathIsFile is false
// for Jira/Confluence (and other non-file sources) whose Path is an issue key / page TITLE, not a
// filesystem path — applying the example/test-path heuristic there would wrongly demote a real secret
// on a page that merely happens to be titled e.g. "Examples".
func adjustSeverity(sev string, m detect.Match, li *lineIndex, path string, pathIsFile bool) string {
	if m.Stage == "L1-checksum" {
		return sev // checksum is proof regardless of location
	}
	if !li.isComment(m.Start) && !(pathIsFile && isExamplePath(path)) {
		return sev
	}
	if taxonomy.GenericLast[m.Type] {
		return "low"
	}
	return demoteOne(sev)
}

// pathIsFilesystem reports whether an item's Path is a real filesystem path (so the example/lockfile
// heuristics apply) vs an opaque locator like a Jira key or Confluence page title. It allow-lists the
// filesystem labels — "code", "file" (docs: .md/.rst/.txt/.adoc, per source.sourceForPath), and the
// empty default — so an unknown/new non-file source defaults to FALSE (no demotion), erring toward a
// false positive rather than demoting/hiding a real secret.
func pathIsFilesystem(source string) bool {
	return source == "" || source == "code" || source == "file"
}

// lineIndex precomputes every line-start offset once, so per-match position lookups (line/col, pragma,
// comment) are O(log lines) binary searches, making a dense-match file O(matches·log lines), not O(matches²).
type lineIndex struct {
	text   string
	starts []int // byte offset of each line's first char; starts[0] == 0
	// pragmaCache/commentCache memoize hasPragma/isComment per line: the whole-line ToLower/TrimSpace
	// runs once per line instead of once per match, collapsing the O(matches·lineLen) single-line time DoS.
	pragmaCache  []int8 // -1 = unknown, 0 = no pragma, 1 = has pragma; len == len(starts)
	commentCache []int8 // -1 = unknown, 0 = not a comment, 1 = comment; len == len(starts)
}

func newLineIndex(text string) *lineIndex {
	starts := make([]int, 1, len(text)/40+1) // starts[0] = 0
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	pc := make([]int8, len(starts))
	cc := make([]int8, len(starts))
	for i := range pc {
		pc[i] = -1 // unknown until first lookup
		cc[i] = -1
	}
	return &lineIndex{text: text, starts: starts, pragmaCache: pc, commentCache: cc}
}

// lineAt returns the 0-based index of the line containing byte pos.
func (li *lineIndex) lineAt(pos int) int {
	if pos > len(li.text) {
		pos = len(li.text)
	}
	i := sort.Search(len(li.starts), func(i int) bool { return li.starts[i] > pos }) - 1
	if i < 0 {
		i = 0
	}
	return i
}

// cols returns the 1-based line and (byte-based) column of pos, matching the previous behavior.
func (li *lineIndex) cols(pos int) (int, int) {
	if pos > len(li.text) {
		pos = len(li.text)
	}
	i := li.lineAt(pos)
	return i + 1, pos - li.starts[i] + 1
}

// bounds returns the [start, end) byte range of the line containing pos (end excludes the newline).
func (li *lineIndex) bounds(pos int) (int, int) {
	i := li.lineAt(pos)
	start := li.starts[i]
	end := len(li.text)
	if i+1 < len(li.starts) {
		end = li.starts[i+1] - 1
	}
	return start, end
}

// hasPragma reports whether the line containing pos carries an inline allow marker. Memoized per line.
func (li *lineIndex) hasPragma(pos int) bool {
	i := li.lineAt(pos)
	if i < len(li.pragmaCache) {
		if c := li.pragmaCache[i]; c >= 0 {
			return c == 1
		}
	}
	s := li.starts[i]
	e := len(li.text)
	if i+1 < len(li.starts) {
		e = li.starts[i+1] - 1
	}
	has := false
	line := strings.ToLower(li.text[s:e])
	for _, p := range allowPragmas {
		if strings.Contains(line, p) {
			has = true
			break
		}
	}
	if i < len(li.pragmaCache) {
		if has {
			li.pragmaCache[i] = 1
		} else {
			li.pragmaCache[i] = 0
		}
	}
	return has
}

// isComment reports whether the line containing pos begins (after whitespace) with a comment marker.
// Memoized per line.
func (li *lineIndex) isComment(pos int) bool {
	i := li.lineAt(pos)
	if i < len(li.commentCache) {
		if c := li.commentCache[i]; c >= 0 {
			return c == 1
		}
	}
	s, e := li.bounds(pos)
	line := strings.TrimSpace(li.text[s:e])
	is := false
	for _, p := range commentPrefixes {
		if strings.HasPrefix(line, p) {
			is = true
			break
		}
	}
	if i < len(li.commentCache) {
		if is {
			li.commentCache[i] = 1
		} else {
			li.commentCache[i] = 0
		}
	}
	return is
}

// Run scans the Item stream with workers goroutines and returns all findings. allow (optional)
// suppresses a match by its raw value+path before redaction. Stops on ctx cancellation with
// partial results.
func Run(ctx context.Context, items <-chan model.Item, det *detect.Detector, eng *rules.Engine, vset *verify.Set, workers int, allow func(value, path string) bool, ml mlscore.Scorer) []model.Finding {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var findings []model.Finding
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range items {
				if ctx.Err() != nil {
					return
				}
				// guard the whole per-item pipeline so one bad item can't crash the worker and abort the scan
				var local []model.Finding
				it := it
				resilience.Guard(
					func() { local = Findings(ctx, det, eng, vset, it, allow, ml) },
					func(r any) { logx.Warn("recovered item-processing panic", "path", it.Path, "err", r) },
				)
				if len(local) == 0 {
					continue
				}
				mu.Lock()
				findings = append(findings, local...)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return findings
}

// Findings scans a single Item under a panic guard and applies the allowlist + inline pragmas.
// Used by both the worker pool and the HTTP server as one self-contained unit of work.
func Findings(ctx context.Context, det *detect.Detector, eng *rules.Engine, vset *verify.Set, it model.Item, allow func(value, path string) bool, ml mlscore.Scorer) []model.Finding {
	var ms []detect.Match
	resilience.Guard(
		func() { ms = det.ScanCtx(ctx, it.Text) },
		func(r any) { logx.Warn("recovered scan panic", "path", it.Path, "err", r) },
	)
	// maxMatches is the global cap shared across both producers (cascade and template engine below).
	// truncated records when either producer hit the cap so the output can carry a truncation marker.
	maxMatches := detect.MaxScanMatches()
	truncated := len(ms) >= maxMatches
	out := make([]model.Finding, 0, len(ms))
	var reqs []mlscore.Record // parallel to out, populated only when the ML stage is active
	dedup := map[string]int{} // value+line key -> index in out, avoids cascade/template double-reporting
	li := newLineIndex(it.Text)
	pathIsFile := pathIsFilesystem(it.Source)
	itemURL, _ := it.Meta["url"].(string)
	for i, m := range ms {
		if i&1023 == 0 && ctx.Err() != nil { // let --timeout / Ctrl-C abort mid-file, not only between files

			break
		}
		if allow != nil && allow(m.Value, it.Path) {
			continue
		}
		if li.hasPragma(m.Start) {
			continue
		}
		// in a lockfile a generic entropy/api-key hit is almost always a package integrity hash; drop
		// only that noise (lockfileNoiseTypes), keeping typed secrets and credential-bearing generics
		if pathIsFile && isLockfile(it.Path) && lockfileNoiseTypes[m.Type] {
			continue
		}
		line, col := li.cols(m.Start)
		sev := adjustSeverity(severityFor(m.Category, m.Confidence), m, li, it.Path, pathIsFile)
		dedup[fmt.Sprintf("%d:%s", line, m.Value)] = len(out) // index of the finding appended next
		ver, why := applyVerify(ctx, vset, m.Type, m.Value, it.Text)
		out = append(out, model.Finding{
			Detector: m.Type, Type: m.Type, Confidence: m.Confidence,
			Severity: sev,
			Source:   it.Source, Path: it.Path, Line: line, Col: col,
			Redacted: redactValue(m.Value), Stage: m.Stage, URL: itemURL,
			Fingerprint: model.ComputeFingerprint(m.Type, it.Path, m.Value),
			Verified:    ver, Rationale: why,
			Context: revealContext(it, m.Start),
		})
		if ml != nil {
			reqs = append(reqs, recordFor(m.Value, it, m.Start))
		}
	}
	// external templates (opt-in via --rules-dir)
	if eng != nil {
		// Bound the engine by the remaining combined budget: the cascade already consumed len(out) of the
		// cap, so MatchN stops early at maxMatches-len(out) and never materializes the full hit slice on a
		// dense file. A non-positive budget means the cascade filled the cap; the engine emits nothing.
		var hits []rules.Hit
		var engTrunc bool
		budget := maxMatches - len(out)
		if budget > 0 {
			resilience.Guard(
				func() { hits, engTrunc = eng.MatchN(it.Text, budget) },
				func(r any) { logx.Warn("recovered rule-engine panic", "path", it.Path, "err", r) },
			)
		} else {
			engTrunc = true
		}
		if engTrunc {
			truncated = true
		}
		for i, h := range hits {
			if i&1023 == 0 && ctx.Err() != nil {
				break
			}
			// backstop the combined cap during accumulation (collisions update in place; distinct hits grow out)
			if len(out) >= maxMatches {
				truncated = true
				break
			}
			if allow != nil && allow(h.Value, it.Path) {
				continue
			}
			// drop unresolved $VAR refs and doc examples/placeholders, as the cascade does, so installed
			// templates don't worsen precision on .env.example/docs
			if detect.IsTemplatePlaceholder(h.Value) || detect.ConnURICredentialIsPlaceholder(h.Value) ||
				detect.IsExampleOrPlaceholder(h.Value) {
				continue
			}
			if li.hasPragma(h.Start) {
				continue
			}
			line, col := li.cols(h.Start)
			key := fmt.Sprintf("%d:%s", line, h.Value)
			idx, collided := dedup[key]
			sev := h.Severity
			if sev == "" {
				sev = severityFor(h.Category, 0.9)
			}
			ver, why := applyVerify(ctx, vset, h.RuleID, h.Value, it.Text)
			f := model.Finding{
				Detector: h.RuleID, Type: h.RuleID, Confidence: 0.9,
				Severity: ruleSeverity(sev, h, li, it.Path, pathIsFile),
				Source:   it.Source, Path: it.Path, Line: line, Col: col,
				Redacted: redactValue(h.Value), Stage: "rule", URL: itemURL,
				Fingerprint: model.ComputeFingerprint(h.RuleID, it.Path, h.Value),
				Verified:    ver, Rationale: why,
				Context: revealContext(it, h.Start),
			}
			// On a collision (same value+line) keep the stronger finding; a specific template supersedes a
			// generic builtin but YIELDS to an earlier template, a stronger finding, or a checksum-proven
			// builtin — a cryptographic L1-checksum hit must never be rewritten by a template's self-declared severity.
			if collided {
				if prev := out[idx]; prev.Stage == "rule" || isChecksumProven(prev) || stronger(prev, f) {
					continue
				}
				out[idx] = f
				if ml != nil {
					reqs[idx] = recordFor(h.Value, it, h.Start)
				}
				continue
			}
			dedup[key] = len(out)
			out = append(out, f)
			if ml != nil {
				reqs = append(reqs, recordFor(h.Value, it, h.Start))
			}
		}
	}
	// The per-item cap bounds a network sidecar; the in-process model scores dense bundles too (where ML
	// earns its keep). The truncation marker is appended AFTER ML so it is never scored.
	if ml != nil && len(out) > 0 && (ml.Local() || len(out) <= mlMaxItemFindings) {
		out = mlFilter(ctx, ml, out, reqs)
	}
	// Surface the global match cap in the machine output: when either producer hit maxMatches a secret
	// past the cap was dropped, so a CI consumer must see results were truncated. report.go lifts this
	// into the JSON/SARIF envelope's `truncated` field.
	if truncated {
		out = append(out, truncationMarker(it))
	}
	return out
}

// ResultsTruncatedType is the synthetic finding Type marking that a file's findings were capped at the
// global match limit, so a consumer knows results are incomplete. It carries no secret material.
const ResultsTruncatedType = "results_truncated"

// truncationMarker builds the synthetic info finding appended when a file hit the global match cap.
func truncationMarker(it model.Item) model.Finding {
	return model.Finding{
		Detector: "scan", Type: ResultsTruncatedType, Severity: "info",
		Source: it.Source, Path: it.Path, Stage: "intake",
		Rationale: fmt.Sprintf("findings for this file were capped at the global match limit (%d); "+
			"some secrets may not be reported", detect.MaxScanMatches()),
	}
}

// mlMaxItemFindings is the per-item candidate count above which an item is treated as a data file
// (ML skipped, the --max-per-file cap takes over).
const mlMaxItemFindings = 200

// recordFor builds the ML scoring record for a candidate: the raw value plus the context the model was
// trained on (surrounding line, best-effort assigned name, path, source).
func recordFor(value string, it model.Item, start int) mlscore.Record {
	line := lineText(it.Text, start)
	if len(value) > 512 { // cap so huge values don't make the scoring POST time out
		value = value[:512]
	}
	return mlscore.Record{
		Value: value,
		Context: mlscore.Context{
			Name:   leadingName(line),
			Line:   line,
			Path:   it.Path,
			Source: it.Source,
		},
	}
}

// revealContext returns the finding's ML context (same line/name recordFor feeds the model) when
// --show-secrets is on, so the JSON carries faithful feedback features. nil otherwise: the line holds
// the raw secret.
func revealContext(it model.Item, start int) *model.FindingContext {
	if !revealSecrets.Load() {
		return nil
	}
	line := lineText(it.Text, start)
	return &model.FindingContext{Name: leadingName(line), Line: line}
}

// lineText returns the (length-capped) source line containing byte offset start.
func lineText(text string, start int) string {
	if start < 0 || start > len(text) {
		return ""
	}
	b := start
	for b > 0 && text[b-1] != '\n' {
		b--
	}
	e := start
	for e < len(text) && text[e] != '\n' {
		e++
	}
	s := text[b:e]
	if len(s) > 400 { // bound the context sent to the model
		s = s[:400]
	}
	return s
}

var reAssignName = regexp.MustCompile(`([A-Za-z_][\w.-]*)\s*[:=]`)

// leadingName extracts a best-effort assigned identifier from a line (e.g. "api_key" from
// `api_key = "..."`), which is one of the context features the model uses.
func leadingName(line string) string {
	if m := reAssignName.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	return ""
}

// mlFilter asks the sidecar to score every candidate and drops the ones it is confident are not
// secrets (score below the threshold), EXCEPT structurally-proven (checksum) hits, which are never
// dropped on a model miss. It fails open: any sidecar error keeps every finding.
func mlFilter(ctx context.Context, ml mlscore.Scorer, out []model.Finding, reqs []mlscore.Record) []model.Finding {
	results, err := ml.Score(ctx, reqs)
	if err != nil {
		logx.Warn("ml scoring failed — keeping all findings (fail-open)", "err", err)
		return out
	}
	if len(results) != len(out) {
		return out
	}
	kept := out[:0]
	for i, f := range out {
		if mlExempt(f) || results[i].Score >= ml.Threshold() {
			kept = append(kept, f)
		}
	}
	return kept
}

// mlExemptTypes carry no "private"/"key" token yet must never be ML-dropped — notably
// gcp_service_account, a "-----BEGIN PRIVATE KEY-----" inside JSON (category "cloud", not "pki").
var mlExemptTypes = map[string]bool{
	"private_key_pem":     true,
	"gcp_service_account": true,
}

// mlExempt shields findings with strong non-ML evidence (a checksum or key/credential-file type) from
// the drop-gate: the model scores a real private key body near zero, which would otherwise delete it.
func mlExempt(f model.Finding) bool {
	if strings.Contains(f.Stage, "checksum") || mlExemptTypes[f.Type] {
		return true
	}
	t := strings.ToLower(f.Type) // key/cert types: rsa-private-key, openssh-key, pgp-block, pkcs8, …
	return (strings.Contains(t, "private") && strings.Contains(t, "key")) ||
		strings.Contains(t, "pem") || strings.Contains(t, "pgp") || strings.Contains(t, "pkcs") ||
		strings.Contains(t, "service_account") || strings.Contains(t, "service-account")
}

func sevIndex(s string) int {
	for i, r := range sevRank {
		if r == s {
			return i
		}
	}
	return -1
}

// isChecksumProven reports whether a finding passed a structural checksum (any "checksum" stage). Such
// a hit is cryptographic proof and outranks a template's self-declared severity in the collision logic.
func isChecksumProven(f model.Finding) bool {
	return strings.Contains(f.Stage, "checksum")
}

// stronger reports whether a is strictly stronger than b (higher severity, then confidence). A full
// tie returns false, so a colliding template (b) wins over an equal builtin (a) — it is more specific.
func stronger(a, b model.Finding) bool {
	if sa, sb := sevIndex(a.Severity), sevIndex(b.Severity); sa != sb {
		return sa > sb
	}
	return a.Confidence > b.Confidence
}

// applyVerify runs the opt-in live-credential check on a raw secret before redaction, returning a
// tri-state pointer (nil = not attempted/inconclusive) and a human rationale.
func applyVerify(ctx context.Context, vset *verify.Set, typeID, raw, context string) (*bool, string) {
	if vset == nil {
		return nil, ""
	}
	r := vset.Verify(ctx, typeID, raw, context, detect.IsExampleOrPlaceholder(raw))
	switch r.Status {
	case verify.Verified:
		t := true
		if r.Note != "" {
			return &t, "verified live: " + r.Note // carries the blast radius (unlocks: …) when mapped
		}
		return &t, "verified live via " + r.Verifier
	case verify.Invalid:
		f := false
		return &f, "provider rejected the credential (" + r.Verifier + ")"
	case verify.Errored:
		return nil, "verification inconclusive: " + r.Note
	default:
		return nil, ""
	}
}

// ruleSeverity demotes a template hit in an example/test path or comment (same policy as the cascade).
// pathIsFile is false for non-file sources (Jira/Confluence) whose Path is a key/title, not a path.
func ruleSeverity(sev string, h rules.Hit, li *lineIndex, path string, pathIsFile bool) string {
	if !li.isComment(h.Start) && !(pathIsFile && isExamplePath(path)) {
		return sev
	}
	return demoteOne(sev)
}
