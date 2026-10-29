// Package scan orchestrates Source -> Detector -> Findings concurrently.
package scan

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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

// imageFileName strips an image finding's "label|layerN:" / "label|image:" prefix so path heuristics see
// the real in-image file path, not the user's image arg. Non-image paths pass through unchanged.
func imageFileName(p string) string {
	bar := strings.Index(p, "|layer")
	if bar < 0 {
		if bar = strings.Index(p, "|image:"); bar < 0 {
			return p
		}
	}
	rest := p[bar+1:] // "layerN:..." or "image:..."
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		return rest[i+1:]
	}
	return p
}

// adjustSeverity demotes low-evidence matches in example/test paths or comments. Checksum matches
// are never demoted; generic ones drop to "low", structured ones drop one step. pathIsFile is false
// for Jira/Confluence (and other non-file sources) whose Path is an issue key / page TITLE, not a
// filesystem path — applying the example/test-path heuristic there would wrongly demote a real secret
// on a page that merely happens to be titled e.g. "Examples".
func adjustSeverity(sev string, m detect.Match, li *lineIndex, path string, pathIsFile bool) string {
	if m.ChecksumValid {
		return sev // A passed checksum retains confidence through source transformations.
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
	text             string
	starts           []int             // byte offset of each line's first char; starts[0] == 0
	utf16Checkpoints []utf16Checkpoint // lazy prefix counts shared by both finding producers
	// pragmaCache/commentCache memoize hasPragma/isComment per line: the whole-line ToLower/TrimSpace
	// runs once per line instead of once per match, collapsing the O(matches·lineLen) single-line time DoS.
	pragmaCache  []int8 // -1 = unknown, 0 = no pragma, 1 = has pragma; len == len(starts)
	commentCache []int8 // -1 = unknown, 0 = not a comment, 1 = comment; len == len(starts)
	pragmaSyntax uint8  // comment families accepted by the source format
}

func newLineIndex(text string) *lineIndex {
	starts := make([]int, 1, len(text)/40+1) // starts[0] = 0
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '\r':
			if i+1 < len(text) && text[i+1] == '\n' {
				i++
			}
			starts = append(starts, i+1)
		case '\n':
			starts = append(starts, i+1)
		}
	}
	pc := make([]int8, len(starts))
	cc := make([]int8, len(starts))
	for i := range pc {
		pc[i] = -1 // unknown until first lookup
		cc[i] = -1
	}
	return &lineIndex{text: text, starts: starts, pragmaCache: pc, commentCache: cc, pragmaSyntax: pragmaAll}
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
		end = li.starts[i+1]
		if end > start && li.text[end-1] == '\n' {
			end--
		}
		if end > start && li.text[end-1] == '\r' {
			end--
		}
	}
	return start, end
}

// hasPragma reports whether the line containing pos carries an inline allow marker. Memoized per line.
func (li *lineIndex) hasPragma(pos int) bool {
	i := li.lineAt(pos)
	if li.pragmaCache[i] < 0 {
		li.initPragmas()
	}
	return li.pragmaCache[i] == 1
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
	RegisterDetectionPolicy(ctx)
	defer noteCancellation(ctx)
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
			for {
				var it model.Item
				select {
				case <-ctx.Done():
					return
				case item, ok := <-items:
					if !ok {
						return
					}
					it = item
				}
				if ctx.Err() != nil {
					return
				}
				// guard the whole per-item pipeline so one bad item can't crash the worker and abort the scan
				var local []model.Finding
				resilience.Guard(
					func() { local = Findings(ctx, det, eng, vset, it, allow, ml) },
					func(r any) {
						model.Note(ctx, "processing_failed", it.Path, true)
						logx.Warn("recovered item-processing panic", "path", it.Path)
						local = []model.Finding{processingError(it, "item processing failed; scan results are incomplete")}
					},
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
	if ctx.Err() != nil {
		findings = append(findings, processingError(model.Item{}, "scan interrupted; results are incomplete"))
	}
	return findings
}

func processingError(it model.Item, reason string) model.Finding {
	return model.Finding{Detector: "scan", Type: "response_truncated", Severity: "info",
		Source: it.Source, Path: it.Path, ArtifactURI: it.ArtifactURI, Stage: "intake", Rationale: reason}
}

// Findings scans a single Item under a panic guard and applies the allowlist + inline pragmas.
// Used by both the worker pool and the HTTP server as one self-contained unit of work.
func Findings(ctx context.Context, det *detect.Detector, eng *rules.Engine, vset *verify.Set, it model.Item, allow func(value, path string) bool, ml mlscore.Scorer) []model.Finding {
	if it.Error != nil {
		model.Note(ctx, "source_error", it.Path, true)
		return []model.Finding{{Detector: "source", Type: "source_error", Severity: "info", Source: it.Source, Path: it.Path, ArtifactURI: it.ArtifactURI, Stage: "intake", Rationale: "source content could not be read; scan results are incomplete"}}
	}
	RegisterDetectionPolicy(ctx)
	defer noteCancellation(ctx)
	if ctx.Err() != nil {
		return []model.Finding{processingError(it, "scan interrupted; results are incomplete")}
	}
	model.CoverageFrom(ctx).Processed(len(it.Text))
	literalDoc := optionsFrom(ctx).literals
	unsafeLiteralFallback := false
	if literalDoc == nil {
		if doc := jsonLiterals(ctx, it); doc != nil {
			return literalFindings(ctx, det, eng, vset, it, allow, ml, doc)
		}
		if doc := tomlLiterals(ctx, it); doc != nil {
			return literalFindings(ctx, det, eng, vset, it, allow, ml, doc)
		}
		if doc := yamlLiterals(ctx, it); doc != nil {
			return literalFindings(ctx, det, eng, vset, it, allow, ml, doc)
		}
		if pathIsFilesystem(it.Source) {
			switch strings.ToLower(filepath.Ext(model.SafeLocator(it.Path))) {
			case ".json", ".toml", ".yaml", ".yml":
				unsafeLiteralFallback = true
			}
		}
	}
	var ms []detect.Match
	truncated := false
	failed := false
	resilience.Guard(
		func() {
			opts := detect.ScanOptions{}
			if pathIsFilesystem(it.Source) {
				opts = DetectionOptions(it.Path)
				if literalDoc == nil {
					opts.PasswordScalars = yamlPasswordScalars(ctx, it)
				}
			}
			if literalDoc != nil {
				opts.PasswordScalars = literalDoc.scalars
			}
			result := det.ScanWithStatus(ctx, it.Text, opts)
			ms = result.Matches
			truncated = result.CandidateLimited
			if result.Base64Limited {
				model.Note(ctx, "base64_limit", it.Path, true)
			}
		},
		func(r any) {
			model.Note(ctx, "detection_failed", it.Path, true)
			failed = true
			logx.Warn("recovered scan panic", "path", it.Path)
		},
	)

	if o := optionsFrom(ctx); o.Semantic && o.SemanticEngine != nil {
		candidates, limited, err := o.SemanticEngine.Discover(ctx, it.Text)
		if err != nil {
			model.Note(ctx, "semantic_failed", it.Path, true)
		}
		if limited {
			model.Note(ctx, "semantic_limit", it.Path, true)
		}
		for _, c := range candidates {
			if detect.IsExampleOrPlaceholder(c.Value) {
				continue
			}
			ms = append(ms, detect.Match{Type: "generic_semantic_secret", Value: c.Value, Start: c.Start, End: c.End, Confidence: .75, Category: "generic", Stage: "semantic-candidate"})
		}

		if failed {
			return []model.Finding{processingError(it, "detector failed; scan results are incomplete")}
		}
	}
	// maxMatches is the global cap shared across both producers (cascade and template engine below).
	// truncated records when either producer hit the cap so the output can carry a truncation marker.
	maxMatches := detect.MaxScanMatches()
	truncated = truncated || len(ms) >= maxMatches
	if len(ms) > maxMatches {
		ms = ms[:maxMatches]
	}
	out := make([]model.Finding, 0, len(ms))
	var reqs []mlscore.Record
	rawByFingerprint := map[string]string{}
	decodedVerification := map[string]string{}
	dedup := map[string]int{} // value+source span -> index in out, avoids cascade/template double-reporting
	li := newSourceLineIndex(it.Text, it.Path)
	hasPragma := li.hasPragma
	if literalDoc != nil {
		hasPragma = func(start int) bool {
			v := literalDoc.locate(start, start)
			if v == nil {
				return false
			}
			original, _ := literalDoc.sourceSpan(v, start, start+1)
			return literalDoc.hasPragma(original)
		}
	}
	pathIsFile := pathIsFilesystem(it.Source)
	codeValues := NewCodeValueFilter(it.Path, it.Text)
	verificationText := it.Text
	candidateRecord := func(value string, start int) mlscore.Record {
		if literalDoc != nil {
			return literalDoc.recordFor(value, it, start)
		}
		return recordFor(value, it, start)
	}
	if original, ok := it.Meta["verification_context"].(string); ok {
		verificationText = original
	}
	itemURL, _ := it.Meta["url"].(string)
	itemInstr, _ := it.Meta["instruction"].(string) // image: the Dockerfile step that built the layer
	if !revealSecrets.Load() {
		itemInstr = ""
	} // build instructions can contain credentials beyond this finding
	examplePath := imageFileName(it.Path) // strip the image label/layer prefix so the arg can't trip isExamplePath
	for i, m := range ms {
		if i&1023 == 0 && ctx.Err() != nil { // let --timeout / Ctrl-C abort mid-file, not only between files

			break
		}
		if literalDoc != nil {
			v := literalDoc.locate(m.Start, m.End)
			if v == nil || v.noPassword && taxonomy.GenericLast[m.Type] || v.uiPassword && m.Type == "generic_password" || !v.raw && m.Type == "generic_password" && m.Stage != "L1-context-pw" && (m.Start != v.preparedStart || m.End != v.preparedEnd) {
				continue // Reject cross-scalar and partial assignments; contextual prose remains a guess.
			}
		}
		if allow != nil && allow(m.Value, it.Path) {
			model.CoverageFrom(ctx).Filtered()
			continue
		}
		if hasPragma(m.Start) {
			model.CoverageFrom(ctx).Filtered()
			continue
		}
		if pathIsFile && taxonomy.GenericLast[m.Type] && m.Stage != "semantic-candidate" && codeValues.NonLiteral(m.Start, m.End) {
			continue
		}
		// in a lockfile a generic entropy/api-key hit is almost always a package integrity hash; drop
		// only that noise (lockfileNoiseTypes), keeping typed secrets and credential-bearing generics
		if pathIsFile && isLockfile(examplePath) && lockfileNoiseTypes[m.Type] {
			continue
		}
		line, col := li.cols(m.Start)
		sev := adjustSeverity(severityFor(m.Category, m.Confidence), m, li, examplePath, pathIsFile)
		key := fmt.Sprintf("%d:%d:%s", m.Start, m.End, m.Value)
		if m.Stage == "semantic-candidate" {
			if _, ok := dedup[key]; ok {
				continue
			}
		}
		dedup[key] = len(out) // index of the finding appended next
		out = append(out, model.Finding{
			Detector: m.Type, Type: m.Type, Confidence: m.Confidence,
			Severity: sev,
			Source:   it.Source, Path: it.Path, Line: line, Col: col,
			UTF16Col: li.utf16Col(m.Start), ArtifactURI: it.ArtifactURI, ImageEntry: it.ImageEntry,
			ByteStart: m.Start, ByteEnd: m.End,
			Redacted: redactValue(m.Value), Stage: m.Stage, URL: itemURL,
			Fingerprint: model.ComputeFingerprint(m.Type, it.Path, m.Value),
			Instruction: itemInstr,
			Context:     revealContext(it, m.Start),
		})
		if strings.HasPrefix(m.Stage, "L1-base64") {
			decodedItem := it
			decodedItem.Text = m.DecodedText
			reqs = append(reqs, recordFor(m.Value, decodedItem, m.DecodedStart))
			out[len(out)-1].Context = revealContext(decodedItem, m.DecodedStart)
			decodedVerification[key] = m.DecodedText
			for j, span := range m.DecodeSpans {
				transform := "base64-decode"
				if j > 0 {
					transform = fmt.Sprintf("base64-decode-layer-%d", j+1)
				}
				sl, sc := li.cols(span.Start)
				out[len(out)-1].Evidence = append(out[len(out)-1].Evidence, model.Evidence{Path: model.SafeLocator(it.Path), Start: span.Start, End: span.End, Line: sl, Col: sc, Transform: transform})
			}
		} else {
			reqs = append(reqs, candidateRecord(m.Value, m.Start))
		}
		if m.Transform != "" {
			out[len(out)-1].Evidence = []model.Evidence{{Path: model.SafeLocator(it.Path), Start: m.Start, End: m.End, Line: line, Col: col, Transform: m.Transform}}
		}
		annotateIdentity(ctx, &out[len(out)-1], m.Value, it)
		rawByFingerprint[out[len(out)-1].Fingerprint] = m.Value
		if m.Stage == "semantic-candidate" {
			out[len(out)-1].Evidence = []model.Evidence{{Path: model.SafeLocator(it.Path), Start: m.Start, End: m.End, Line: line, Col: col, Transform: "literal-semantic-span"}}
			out[len(out)-1].Rationale = "Кандидат локальной модели; точное совпадение с исходным текстом, действительность не подтверждена"
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
				func(r any) {
					model.Note(ctx, "rule_processing_failed", it.Path, true)
					logx.Warn("recovered rule-engine panic", "path", it.Path)
					failed = true
				},
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
			if literalDoc != nil && literalDoc.locate(h.Start, h.End) == nil {
				continue
			}
			// backstop the combined cap during accumulation (collisions update in place; distinct hits grow out)
			if len(out) >= maxMatches {
				truncated = true
				break
			}
			if allow != nil && allow(h.Value, it.Path) {
				model.CoverageFrom(ctx).Filtered()
				continue
			}
			// drop unresolved $VAR refs and doc examples/placeholders, as the cascade does, so installed
			// templates don't worsen precision on .env.example/docs
			if detect.IsTemplatePlaceholder(h.Value) || detect.ConnURICredentialIsPlaceholder(h.Value) ||
				detect.IsExampleOrPlaceholder(h.Value) {
				continue
			}
			if pathIsFile && eng.Bundled() && detect.BindingName(it.Text, h.Start) != "" && codeValues.NonLiteral(h.Start, h.End) {
				continue
			}
			if hasPragma(h.Start) {
				model.CoverageFrom(ctx).Filtered()
				continue
			}
			line, col := li.cols(h.Start)
			key := fmt.Sprintf("%d:%d:%s", h.Start, h.End, h.Value)
			idx, collided := dedup[key]
			sev := h.Severity
			if sev == "" {
				sev = severityFor(h.Category, 0.9)
			}
			f := model.Finding{
				Detector: h.RuleID, Type: h.RuleID, Confidence: 0.9,
				Severity: ruleSeverity(sev, h, li, examplePath, pathIsFile),
				Source:   it.Source, Path: it.Path, Line: line, Col: col,
				UTF16Col: li.utf16Col(h.Start), ArtifactURI: it.ArtifactURI, ImageEntry: it.ImageEntry,
				ByteStart: h.Start, ByteEnd: h.End,
				Redacted: redactValue(h.Value), Stage: "rule", URL: itemURL,
				Fingerprint: model.ComputeFingerprint(h.RuleID, it.Path, h.Value),
				Instruction: itemInstr,
				Context:     revealContext(it, h.Start),
			}
			annotateIdentity(ctx, &f, h.Value, it)
			rawByFingerprint[f.Fingerprint] = h.Value
			// On a collision (same value+span) keep the stronger finding; a specific template supersedes a
			// generic builtin but YIELDS to an earlier template, a stronger finding, or a checksum-proven
			// builtin — a checksum-valid format must never be rewritten by a template's self-declared severity.
			if collided {
				if prev := out[idx]; prev.Stage == "rule" || isChecksumProven(prev) || stronger(prev, f) || (eng.Bundled() && !taxonomy.GenericLast[prev.Type]) {
					continue
				}
				out[idx] = f
				reqs[idx] = candidateRecord(h.Value, h.Start)
				continue
			}
			dedup[key] = len(out)
			out = append(out, f)
			reqs = append(reqs, candidateRecord(h.Value, h.Start))
		}
	}
	verificationContext := func(f model.Finding) string {
		key := fmt.Sprintf("%d:%d:%s", f.ByteStart, f.ByteEnd, rawByFingerprint[f.Fingerprint])
		if decoded, ok := decodedVerification[key]; ok {
			return decoded
		}
		if literalDoc != nil {
			if v := literalDoc.locate(f.ByteStart, f.ByteEnd); v != nil {
				if v.raw {
					return literalDoc.original
				}
				return literalDoc.contexts[v.group]
			}
		}
		return verificationText
	}
	verifyFinding := func(f *model.Finding) {
		unsafeGroup := false
		if literalDoc != nil {
			if v := literalDoc.locate(f.ByteStart, f.ByteEnd); v != nil {
				unsafeGroup = literalDoc.unsafeGroups[v.group]
			}
		}
		if unsafeLiteralFallback || unsafeGroup {
			f.Verification = &model.Verification{Status: "error", Reason: "structured literal could not be established"}
			f.Rationale = "verification inconclusive: structured literal could not be established"
			model.Note(ctx, "verification_unsafe_literal", it.Path, true)
			return
		}
		annotateVerification(ctx, vset, f, rawByFingerprint[f.Fingerprint], verificationContext(*f))
	}
	if optionsFrom(ctx).VerifyAll && vset != nil {
		for i := range out {
			verifyFinding(&out[i])
		}
	}
	// The per-item cap bounds a network sidecar; the in-process model scores dense bundles too (where ML
	// earns its keep). The truncation marker is appended AFTER ML so it is never scored.
	if ml != nil && len(out) > 0 && (ml.Local() || len(out) <= mlMaxItemFindings) {
		out = mlFilter(ctx, ml, out, reqs)
	}
	if vset != nil {
		for i := range out {
			if out[i].Verification == nil {
				verifyFinding(&out[i])
			}
		}
	}
	if failed {
		out = append(out, processingError(it, "rule engine failed; scan results are incomplete"))
	}
	if ctx.Err() != nil {
		out = append(out, processingError(it, "scan interrupted; results are incomplete"))
	}
	// Surface the global match cap in the machine output: when either producer hit maxMatches a secret
	// past the cap was dropped, so a CI consumer must see results were truncated. report.go lifts this
	// into the JSON/SARIF envelope's `truncated` field.
	if truncated {
		out = append(out, truncationMarker(it))
	}
	if optionsFrom(ctx).Reconstruct {
		more := reconstructed(ctx, det, eng, vset, it, allow, ml)
		remaining := maxMatches - len(out)
		if remaining < 0 {
			remaining = 0
		}
		if len(more) > remaining {
			more = more[:remaining]
			model.Note(ctx, "reconstruction_match_limit", it.Path, true)
		}
		out = append(out, more...)
	}
	return out
}

// The release number alone cannot identify detection semantics across candidate builds. Include the
// heuristic revision even for empty scans so old-policy reports cannot certify disappearance.
// RegisterDetectionPolicy also stamps an explicitly empty HTTP batch with its detection semantics.
func RegisterDetectionPolicy(ctx context.Context) {
	model.CoverageFrom(ctx).RegisterScope("detection_policy", "1.4.0", "noise-10")
}

func noteCancellation(ctx context.Context) {
	if ctx.Err() != nil {
		model.Note(ctx, "cancelled", "", true)
	}
}

// ResultsTruncatedType is the synthetic finding Type marking that a file's findings were capped at the
// global match limit, so a consumer knows results are incomplete. It carries no secret material.
const ResultsTruncatedType = "results_truncated"

// truncationMarker builds the synthetic info finding appended when a file hit the global match cap.
func truncationMarker(it model.Item) model.Finding {
	return model.Finding{
		Detector: "scan", Type: ResultsTruncatedType, Severity: "info",
		Source: it.Source, Path: it.Path, ArtifactURI: it.ArtifactURI, Stage: "intake",
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
			Name:   detect.BindingName(it.Text, start),
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
	return &model.FindingContext{Name: detect.BindingName(it.Text, start), Line: line}
}

// lineText returns the (length-capped) source line containing byte offset start.
func lineText(text string, start int) string {
	if start < 0 || start > len(text) {
		return ""
	}
	b := start
	for b > 0 && start-b < 160 && text[b-1] != '\n' && text[b-1] != '\r' {
		b--
	}
	e := start
	for e < len(text) && e-b < 400 && text[e] != '\n' && text[e] != '\r' {
		e++
	}
	return text[b:e]
}

// mlFilter asks the sidecar to score every candidate and drops the ones it is confident are not
// secrets (score below the threshold), EXCEPT provider-confirmed and structurally-proven hits,
// which are never dropped on a model miss. It fails open: any sidecar error keeps every finding.
func mlFilter(ctx context.Context, ml mlscore.Scorer, out []model.Finding, reqs []mlscore.Record) []model.Finding {
	results, err := ml.Score(ctx, reqs)
	if err != nil {
		model.Note(ctx, "ml_scoring_failed", "", true)
		logx.Warn("ml scoring failed — keeping all findings (fail-open)")
		return out
	}
	if len(results) != len(out) {
		model.Note(ctx, "ml_response_invalid", "", true)
		return out
	}
	threshold := ml.Threshold()
	if !mlscore.ValidScore(threshold) {
		model.Note(ctx, "ml_response_invalid", "", true)
		return out
	}
	for _, r := range results {
		if !mlscore.ValidScore(r.Score) {
			model.Note(ctx, "ml_response_invalid", "", true)
			return out
		}
	}
	kept := out[:0]
	for i, f := range out {
		score := results[i].Score
		f.MLScore = &score
		if mlExempt(f) || mlAnchoredEvidence(f, reqs[i]) || results[i].Score >= threshold {
			kept = append(kept, f)
		} else {
			model.CoverageFrom(ctx).Filtered()
		}
	}
	return kept
}

// mlAnchoredEvidence keeps narrowly supported L1 evidence that the legacy model mistakes for prose
// or hashes. It does not mark a finding LIVE, and contextual-password guesses still pass through ML.
func mlAnchoredEvidence(f model.Finding, r mlscore.Record) bool {
	name := strings.ToLower(r.Context.Name)
	if (f.Type == "generic_high_entropy" && f.Stage == "L1-entropy" || f.Type == "generic_api_key" && f.Stage == "L1-regex") && detect.IsSecretBindingName(name) && len(r.Value) >= 32 && len(r.Value) <= 128 && isHexCredential(r.Value) {
		return true
	}
	if f.Type == "generic_password" && f.Stage == "L1-regex" {
		if name == "pass" || name == "pw" || strings.HasSuffix(name, "_pass") || strings.HasSuffix(name, "_pw") || strings.HasSuffix(name, ".pass") || strings.HasSuffix(name, ".pw") {
			return true
		}
		for _, cue := range []string{"password", "passphrase", "passwd", "pwd", "passwort", "kennwort", "contraseña", "wachtwoord", "пароль", "parola", "salasana", "senha"} {
			if strings.HasSuffix(name, cue) {
				return true
			}
		}
	}
	if f.Stage != "rule" {
		return false
	}
	switch f.Type {
	case "assemblyai-api-key", "together-api-key", "linode-api-token":
		provider := strings.Split(f.Type, "-")[0]
		return strings.HasPrefix(name, provider) && (strings.HasSuffix(name, "key") || strings.HasSuffix(name, "token"))
	case "netlify-access-token":
		return strings.HasPrefix(r.Value, "nfp_") && len(r.Value) == 40
	case "sentry-dsn":
		u, err := url.Parse(r.Value)
		if err != nil || u.User == nil {
			return false
		}
		password, present := u.User.Password()
		return present && len(password) == 32 && len(u.User.Username()) == 32
	}
	return false
}

func isHexCredential(value string) bool {
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return value != ""
}

// mlExemptTypes carry no "private"/"key" token yet must never be ML-dropped — notably
// gcp_service_account, a "-----BEGIN PRIVATE KEY-----" inside JSON (category "cloud", not "pki").
var mlExemptTypes = map[string]bool{
	"jwt":                 true, // Parsed JOSE shape is reliable nomination, not authenticity proof.
	"private_key_pem":     true,
	"gcp_service_account": true,
}

// mlExempt shields provider-confirmed hits and findings with strong structural evidence from the
// drop-gate: the model scores a real private key body near zero, which would otherwise delete it.
func mlExempt(f model.Finding) bool {
	if (f.Verified != nil && *f.Verified) || strings.Contains(f.Stage, "checksum") || mlExemptTypes[f.Type] {
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

// isChecksumProven reports whether a finding passed a best-effort format checksum. Such a hit
// outranks a template's self-declared severity; it is not authentication or cryptographic proof.
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

// ruleSeverity demotes a template hit in an example/test path or comment (same policy as the cascade).
// pathIsFile is false for non-file sources (Jira/Confluence) whose Path is a key/title, not a path.
func ruleSeverity(sev string, h rules.Hit, li *lineIndex, path string, pathIsFile bool) string {
	if !li.isComment(h.Start) && !(pathIsFile && isExamplePath(path)) {
		return sev
	}
	return demoteOne(sev)
}

func annotateVerification(ctx context.Context, s *verify.Set, f *model.Finding, raw, text string) {
	r := s.Verify(ctx, f.Type, raw, text, detect.IsExampleOrPlaceholder(raw))
	f.Verification = &model.Verification{Status: string(r.Status), Verifier: r.Verifier, CheckedAt: time.Now().UTC().Format(time.RFC3339), Capabilities: r.Access}
	switch r.Status {
	case verify.Verified:
		v := true
		f.Verified = &v
		f.Rationale = "verified live: " + r.Note
	case verify.Invalid:
		v := false
		f.Verified = &v
		f.Rationale = "provider rejected the credential (" + r.Verifier + ")"
	case verify.Errored:
		model.Note(ctx, "verification_inconclusive", f.Path, true)
		f.Verification.Reason = r.Note
		f.Rationale = "verification inconclusive: " + r.Note
	}
}
