// Package scan orchestrates Source -> Detector -> Findings concurrently.
package scan

import (
	"context"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/publicaudit"
	"github.com/Lercas/prowl/tool/internal/resilience"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
	"github.com/Lercas/prowl/tool/internal/verify"
)

// allowPragmas are inline line-level suppression markers (detect-secrets / gitleaks compatible).
var allowPragmas = []string{"prowl:allow", "pragma: allowlist secret", "gitleaks:allow", "noqa: secret"}

func (p *Pipeline) redactValue(raw string) string {
	if p.options.RevealSecrets {
		return raw
	}
	return model.Redact(raw)
}

var categorySeverity = map[string]string{
	"pki": "critical", "payment": "critical", "db": "critical",
	"cloud": "high", "vcs": "high", "ai": "high", "comms": "high", "messaging": "high",
	"ci": "high", "saas": "high", "observability": "high", "auth": "high",
	"generic": "medium",
	"public":  "info",
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
	text             string
	starts           []int             // byte offset of each line's first char; starts[0] == 0
	utf16Checkpoints []utf16Checkpoint // lazy prefix counts shared by both finding producers
	// pragmaCache/commentCache memoize hasPragma/isComment per line: the whole-line ToLower/TrimSpace
	// runs once per line instead of once per match, collapsing the O(matches·lineLen) single-line time DoS.
	pragmaCache  []int8 // -1 = unknown, 0 = no pragma, 1 = has pragma; len == len(starts)
	commentCache []int8 // -1 = unknown, 0 = not a comment, 1 = comment; len == len(starts)
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
func (p *Pipeline) Run(ctx context.Context, items <-chan model.Item) []model.Finding {
	workers := p.options.Workers
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
					func() { local = p.Findings(ctx, it) },
					func(r any) {
						logx.Warn("recovered item-processing panic", "path", it.Path, "err", r)
						local = []model.Finding{processingError(it, "item processing failed; scan results are incomplete")}
					},
				)
				if len(local) == 0 {
					continue
				}
				if p.options.resultSink != nil {
					p.options.resultSink(local)
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
		Source: it.Source, Path: model.SafeLocator(it.Path), ArtifactURI: it.ArtifactURI, Stage: "intake", Rationale: reason}
}

// Findings scans a single Item under a panic guard and applies the allowlist + inline pragmas.
// Used by both the worker pool and the HTTP server as one self-contained unit of work.
func (p *Pipeline) Findings(ctx context.Context, it model.Item) (result []model.Finding) {
	if it.Error == nil && ctx.Err() == nil {
		model.CoverageFrom(ctx).Processed(len(it.Text))
	}
	coverage := model.NewCoverage()
	options := p.options
	localOptions := false
	if options.PublicAuditor != nil && (reconstructable(it) || firebaseXMLKind(it.Path) != "") && it.Error == nil {
		options.publicBindings = &publicBindings{text: it.Text, path: it.Path}
		localOptions = true
	}
	if options.Reconstruct && reconstructable(it) {
		budget := detect.MaxScanMatches()
		if options.matchLimit > 0 {
			budget = min(budget, options.matchLimit)
		}
		options.candidateBudget = &budget
		localOptions = true
	}
	if localOptions {
		p = New(options)
	}
	result = p.findings(model.WithCoverage(ctx, coverage), it, nil)
	if p.options.Reconstruct && reconstructable(it) && it.Error == nil && ctx.Err() == nil {
		result = p.appendReconstructed(model.WithCoverage(ctx, coverage), it, result)
	}
	complete, _, _ := coverage.Snapshot()
	if complete {
		for _, f := range result {
			if model.IsIncompleteFinding(f) {
				coverage.Note(f.Type, f.Path, true)
			}
		}
	}
	complete, _, diagnostics := coverage.Snapshot()
	for _, d := range diagnostics {
		model.Note(ctx, d.Code, d.Path, d.Incomplete)
	}
	if model.NewResult(nil, coverage).Filtered {
		model.CoverageFrom(ctx).Filtered()
	}
	if !complete && !hasIncompleteFinding(result) {
		result = append(result, processingError(it, "scan could not complete all requested checks; results are incomplete"))
		if record, _ := it.Meta["git_history"].(*model.GitRecord); record != nil {
			record.Graph.Inspected.Store(record.Object, false)
		}
	}
	return result
}

func (p *Pipeline) findings(ctx context.Context, it model.Item, literalDoc *literalDocument) (result []model.Finding) {
	gitRecord, _ := it.Meta["git_history"].(*model.GitRecord)
	if record := gitRecord; record != nil {
		defer func() {
			complete := ctx.Err() == nil
			for i := range result {
				result[i].GitRecord = record
				complete = complete && !model.IsIncompleteFinding(result[i])
			}
			literalPath := record.DisplayPath
			if literalPath == "" {
				literalPath = record.Object.Path
			}
			if it.Path == literalPath {
				record.Graph.Inspected.LoadOrStore(record.Object, complete)
				if !complete {
					record.Graph.Inspected.Store(record.Object, false)
				}
			}
		}()
	}
	det, eng, vset, allow, ml := p.options.Detector, p.options.Rules, p.options.Verifiers, p.options.Allow, p.options.ML
	if ctx.Err() != nil {
		return []model.Finding{processingError(it, "scan interrupted; results are incomplete")}
	}
	if it.Error != nil {
		logx.Warn("source content could not be read", "path", it.Path, "err", it.Error)
		return []model.Finding{{
			Detector: "source", Type: "source_error", Severity: "info",
			Source: it.Source, Path: it.Path, ArtifactURI: it.ArtifactURI, Stage: "intake",
			Rationale: "source content could not be read; scan results are incomplete",
		}}
	}
	if literalDoc == nil && literalFormat(it) != "" {
		if doc := parseLiterals(ctx, it, p.options.PublicAuditor != nil); doc != nil {
			return p.literalFindings(ctx, it, doc)
		}
		// A failed parser cannot establish a value safe for provider submission.
		vset = nil
	}
	var ms []detect.Match
	var payloads []detect.JWTPayloadView
	truncated := false
	failed := false
	resilience.Guard(
		func() {
			opts := detect.ScanOptions{}
			if pathIsFilesystem(it.Source) {
				opts = DetectionOptions(it.Path)
			}
			if literalDoc != nil {
				opts.PasswordScalars = literalDoc.scalars
			}
			opts.PublicKeys = p.options.PublicAuditor != nil
			if eng != nil && eng.Len() > 0 || p.options.ValueFingerprint != nil {
				opts.ObserveJWTPayload = func(view detect.JWTPayloadView) { payloads = append(payloads, view) }
			}
			result := det.ScanWithStatus(ctx, it.Text, opts)
			ms, truncated = result.Matches, result.CandidateLimited || result.Base64Limited
		},
		func(r any) {
			logx.Warn("recovered scan panic", "path", it.Path, "err", r)
			failed = true
		},
	)
	if failed {
		return []model.Finding{processingError(it, "detector failed; scan results are incomplete")}
	}
	if p.options.Semantic {
		if p.options.SemanticEngine == nil {
			model.Note(ctx, "semantic_failed", it.Path, true)
		} else {
			resilience.Guard(func() {
				candidates, limited, err := p.options.SemanticEngine.Discover(ctx, it.Text)
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
					ms = append(ms, detect.Match{Type: "generic_semantic_secret", Value: c.Value, Start: c.Start, End: c.End, Confidence: .75, Category: "generic", Stage: "semantic-candidate", Transform: "literal-semantic-span"})
				}
			}, func(any) { model.Note(ctx, "semantic_failed", it.Path, true) })
		}
	}
	// maxMatches is the global cap shared across both producers (cascade and template engine below).
	// truncated records when either producer hit the cap so the output can carry a truncation marker.
	maxMatches := detect.MaxScanMatches()
	if p.options.matchLimit > 0 && p.options.matchLimit < maxMatches {
		maxMatches = p.options.matchLimit
	}
	if len(ms) > maxMatches {
		ms = ms[:maxMatches]
		truncated = true
	}
	out := make([]model.Finding, 0, len(ms))
	auditor := p.options.PublicAuditor
	var pending []verificationCandidate // parallel to final producer winners, never serialized
	verifyBeforeML := p.options.VerifyAll || p.options.ObserveVerification != nil
	var indexValues []string
	if p.options.ValueFingerprint != nil {
		for _, m := range ms {
			indexValues = append(indexValues, m.Value)
			// Keep observed source spelling private too: normalized values may occur
			// in a filename as percent/HTML/base64 text rather than their logical bytes.
			if m.Start >= 0 && m.End >= m.Start && m.End <= len(it.Text) {
				spelling := it.Text[m.Start:m.End]
				if spelling != m.Value {
					indexValues = append(indexValues, spelling)
				}
			}
		}
		for _, view := range payloads {
			span := view.ContainerSpan()
			indexValues = append(indexValues, view.Text, view.ContainerValue(), it.Text[span.Start:span.End])
		}
	}
	var reqs []mlscore.Record // parallel to out, populated only when the ML stage is active
	dedup := map[string]int{} // value+line key -> index in out, avoids cascade/template double-reporting
	li := newLineIndex(it.Text)
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
	itemURL, _ := it.Meta["url"].(string)
	itemInstr, _ := it.Meta["instruction"].(string) // image: the Dockerfile step that built the layer
	verificationText := it.Text
	if p.options.reconstruction != nil {
		// Companion extraction observes the source, never synthetic decoded text.
		verificationText = p.options.reconstruction.lines.text
	}
	examplePath := imageFileName(it.Path) // strip the image label/layer prefix so the arg can't trip isExamplePath
	for i, m := range ms {
		if i&1023 == 0 && ctx.Err() != nil { // let --timeout / Ctrl-C abort mid-file, not only between files

			break
		}
		if literalDoc != nil && !literalDoc.accepts(m.Type, m.Start, m.End) && !(m.JWTPayload && literalDoc.locate(m.Start, m.End) != nil) {
			continue
		}
		if gitRecord != nil {
			p.observeGitCandidate(gitRecord, m.Type, it.Path, m.Value)
		}
		if allow != nil && allow(m.Value, it.Path) {
			model.CoverageFrom(ctx).Filtered()
			continue
		}
		if !p.options.IgnorePragmas && hasPragma(m.Start) {
			model.CoverageFrom(ctx).Filtered()
			continue
		}
		// A reconstructed string is already proven by the expression parser.
		// Its encoded JWT ranges are not identifiers in the original program.
		provenJWTPayload := m.JWTPayload && p.options.reconstruction != nil
		if pathIsFile && taxonomy.GenericLast[m.Type] && m.Stage != "semantic-candidate" && !provenJWTPayload && codeValues.NonLiteral(m.Start, m.End) {
			model.CoverageFrom(ctx).Filtered()
			continue
		}
		// in a lockfile a generic entropy/api-key hit is almost always a package integrity hash; drop
		// only that noise (lockfileNoiseTypes), keeping typed secrets and credential-bearing generics
		if pathIsFile && isLockfile(examplePath) && lockfileNoiseTypes[m.Type] {
			continue
		}
		line, col := li.cols(m.Start)
		sev := adjustSeverity(severityFor(m.Category, m.Confidence), m, li, examplePath, pathIsFile)
		if m.Stage == "semantic-candidate" {
			if _, exists := dedup[p.findingDedupKey(line, col, m.Value)]; exists {
				continue
			}
		}
		dedup[p.findingDedupKey(line, col, m.Value)] = len(out) // index of the finding appended next
		out = append(out, model.Finding{
			Agent: it.Agent, Detector: m.Type, Type: m.Type, Confidence: m.Confidence,
			Severity: sev,
			Source:   it.Source, Path: it.Path, Line: line, Col: col,
			UTF16Col:  li.utf16Col(m.Start),
			ByteStart: m.Start, ByteEnd: m.End,
			ArtifactURI: it.ArtifactURI,
			Redacted:    p.redactValue(m.Value), Stage: m.Stage, URL: itemURL,
			Fingerprint:      model.ComputeFingerprint(m.Type, publicIdentityPath(it), m.Value),
			ValueFingerprint: p.valueFingerprint(m.Value), IndexPath: p.indexText(publicIdentityPath(it), ""),
			IndexSource: p.indexText(it.Source, ""), IndexType: p.indexText(m.Type, ""), IndexLocationID: p.itemLocationFingerprint(it, line, col),
			Instruction: itemInstr,
			ImageEntry:  it.ImageEntry,
			MobileEntry: it.MobileEntry,
			Context:     p.revealMatchContext(it, m),
		})
		for _, step := range m.ProofSteps() {
			sl, sc := li.cols(step.Start)
			out[len(out)-1].Evidence = append(out[len(out)-1].Evidence, model.Evidence{Path: model.SafeLocator(it.Path), Start: step.Start, End: step.End, Line: sl, Col: sc, Transform: step.Transform})
		}
		if m.Transform != "" {
			out[len(out)-1].Evidence = append(out[len(out)-1].Evidence, model.Evidence{Path: model.SafeLocator(it.Path), Start: m.Start, End: m.End, Line: line, Col: col, Transform: m.Transform})
		}
		if m.Stage == "semantic-candidate" {
			out[len(out)-1].Rationale = "Model candidate with an exact match in the source text; validity is not confirmed"
		}
		if vset != nil || auditor != nil {
			pending = append(pending, verificationCandidate{typ: m.Type, value: m.Value, start: m.Start, end: m.End, jwtPayload: m.JWTPayload, derivedMobile: it.Meta["source_transform"] == "mobile-printable-strings"})
		}
		p.annotateIdentity(ctx, &out[len(out)-1], m.Value, it)
		if ml != nil {
			record := recordForMatch(m, it)
			if literalDoc != nil && m.DecodedText == "" {
				record = literalDoc.recordFor(m.Value, it, m.Start, m.Type)
			}
			reqs = append(reqs, record)
		}
	}
	// external templates (opt-in via --rules-dir)
	if eng != nil {
		// Bound the engine by the remaining combined budget: the cascade already consumed len(out) of the
		// cap, so MatchN stops early at maxMatches-len(out) and never materializes the full hit slice on a
		// dense file. A non-positive budget means the cascade filled the cap; the engine emits nothing.
		var hits []ruleCandidate
		var engTrunc bool
		budget := maxMatches - len(out)
		if budget > 0 {
			resilience.Guard(
				func() {
					hits, engTrunc = p.ruleCandidates(ctx, it, payloads, budget)
				},
				func(r any) {
					logx.Warn("recovered rule-engine panic", "path", it.Path, "err", r)
					failed = true
				},
			)
		} else {
			engTrunc = true
		}
		if engTrunc {
			truncated = true
		}
		if p.options.ValueFingerprint != nil {
			for _, h := range hits {
				indexValues = append(indexValues, h.Value)
			}
		}
		for i, h := range hits {
			if i&1023 == 0 && ctx.Err() != nil {
				break
			}
			if literalDoc != nil && !literalDoc.accepts(h.RuleID, h.Start, h.End) && !(h.payload != nil && literalDoc.locate(h.Start, h.End) != nil) {
				continue
			}
			// backstop the combined cap during accumulation (collisions update in place; distinct hits grow out)
			if len(out) >= maxMatches {
				truncated = true
				break
			}
			if gitRecord != nil {
				p.observeGitCandidate(gitRecord, h.RuleID, it.Path, h.Value)
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
			if !p.options.IgnorePragmas && hasPragma(h.Start) {
				model.CoverageFrom(ctx).Filtered()
				continue
			}
			line, col := li.cols(h.Start)
			key := p.findingDedupKey(line, col, h.Value)
			idx, collided := dedup[key]
			sev := h.Severity
			if sev == "" {
				sev = severityFor(h.Category, 0.9)
			}
			f := model.Finding{
				Agent: it.Agent, Detector: h.RuleID, Type: h.RuleID, Confidence: 0.9,
				Severity: ruleSeverity(sev, h.Hit, li, examplePath, pathIsFile),
				Source:   it.Source, Path: it.Path, Line: line, Col: col,
				UTF16Col:  li.utf16Col(h.Start),
				ByteStart: h.Start, ByteEnd: h.End,
				ArtifactURI: it.ArtifactURI,
				Redacted:    p.redactValue(h.Value), Stage: "rule", URL: itemURL,
				Fingerprint:      model.ComputeFingerprint(h.RuleID, publicIdentityPath(it), h.Value),
				ValueFingerprint: p.valueFingerprint(h.Value), IndexPath: p.indexText(publicIdentityPath(it), ""),
				IndexSource: p.indexText(it.Source, ""), IndexType: p.indexText(h.RuleID, ""), IndexLocationID: p.itemLocationFingerprint(it, line, col),
				Instruction: itemInstr,
				ImageEntry:  it.ImageEntry,
				MobileEntry: it.MobileEntry,
				Context:     p.revealContext(it, h.Start),
			}
			if h.payload != nil {
				f.Stage, f.Context = "rule/jwt-payload", nil
				for _, step := range h.payload.view.DecodeSteps() {
					line, col := li.cols(step.Start)
					f.Evidence = append(f.Evidence, model.Evidence{Path: model.SafeLocator(it.Path), Start: step.Start, End: step.End, Line: line, Col: col, Transform: step.Transform})
				}
			}
			p.annotateIdentity(ctx, &f, h.Value, it)
			// On a collision (same value+line) keep the stronger finding; a specific template supersedes a
			// generic builtin but YIELDS to an earlier template, a stronger finding, or a checksum-proven
			// builtin — a cryptographic L1-checksum hit must never be rewritten by a template's self-declared severity.
			if collided {
				if prev := out[idx]; prev.Stage == "rule" || prev.Stage == "rule/jwt-payload" || isChecksumProven(prev) || stronger(prev, f) || eng.Bundled() && !taxonomy.GenericLast[prev.Type] {
					continue
				}
				out[idx] = f
				if vset != nil || auditor != nil {
					pending[idx] = verificationCandidate{typ: h.RuleID, value: h.Value, start: h.Start, end: h.End, jwtPayload: h.payload != nil}
				}
				if ml != nil {
					reqs[idx] = h.record(it, literalDoc)
				}
				continue
			}
			dedup[key] = len(out)
			out = append(out, f)
			if vset != nil || auditor != nil {
				pending = append(pending, verificationCandidate{typ: h.RuleID, value: h.Value, start: h.Start, end: h.End, jwtPayload: h.payload != nil, derivedMobile: it.Meta["source_transform"] == "mobile-printable-strings"})
			}
			if ml != nil {
				reqs = append(reqs, h.record(it, literalDoc))
			}
		}
	}
	if vset != nil && verifyBeforeML {
		for i := range out {
			pending[i].apply(ctx, vset, literalDoc, verificationText, it.Path, &out[i])
		}
	}
	if literalDoc != nil {
		p.mapLiteralFindings(out, it, literalDoc)
		if p.options.ValueFingerprint != nil {
			for _, v := range literalDoc.values {
				indexValues = append(indexValues, v.value, literalDoc.original[v.start:v.end])
			}
		}
	}
	if p.options.candidateBudget != nil {
		*p.options.candidateBudget -= len(out)
	}
	if p.options.reconstruction != nil {
		p.mapReconstructed(out, it)
		origin := p.options.reconstruction
		span := origin.value.Expression
		indexValues = append(indexValues, origin.lines.text[span.Start:span.End])
		for _, span := range origin.value.Spans {
			indexValues = append(indexValues, origin.lines.text[span.Start:span.End])
		}
	}
	p.sanitizeIndexMetadata(out, indexValues)
	if p.options.ObserveVerification != nil {
		for _, f := range out {
			p.observeVerification(f)
		}
	}
	// The per-item cap bounds a network sidecar; the in-process model scores dense bundles too (where ML
	// earns its keep). The truncation marker is appended AFTER ML so it is never scored.
	if p.options.beforeML != nil && !p.options.beforeML(out) {
		return []model.Finding{processingError(it, "comparison candidate budget exhausted")}
	}
	var selected []int // nil denotes unchanged candidate order on absent/failing ML
	if ml != nil && len(out) > 0 && (ml.Local() || len(out) <= mlMaxItemFindings) {
		out, selected = mlFilterSelected(ctx, ml, out, reqs)
	}
	if vset != nil && !verifyBeforeML {
		for i := range out {
			original := i
			if selected != nil {
				original = selected[i]
			}
			pending[original].apply(ctx, vset, literalDoc, verificationText, it.Path, &out[i])
		}
	}
	if auditor != nil {
		for i := range out {
			original := i
			if selected != nil {
				original = selected[i]
			}
			candidate := pending[original]
			var bindings map[string]string
			if literalDoc == nil && !candidate.derivedMobile && publicaudit.Supports(candidate.typ) {
				bindings = p.options.publicBindings.forCandidate(ctx, candidate, p.options.reconstruction)
			}
			candidate.audit(ctx, auditor, literalDoc, bindings, it.Path, &out[i])
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
	return out
}

// ResultsTruncatedType marks a file whose candidate, decoding or normalization
// limits made completeness uncertain. It carries no secret material.
const ResultsTruncatedType = "results_truncated"

// truncationMarker builds the synthetic info finding appended when a scan limit was reached.
func truncationMarker(it model.Item) model.Finding {
	return model.Finding{
		Detector: "scan", Type: ResultsTruncatedType, Severity: "info",
		Source: it.Source, Path: it.Path, ArtifactURI: it.ArtifactURI, Stage: "intake",
		Rationale: "a candidate, decoding, or normalization limit was reached for this file; some secrets may not be reported",
	}
}

// mlMaxItemFindings is the per-item candidate count above which an item is treated as a data file
// (ML skipped, the --max-per-file cap takes over).
const mlMaxItemFindings = 200

func recordForMatch(m detect.Match, it model.Item) mlscore.Record {
	if m.DecodedText != "" {
		it.Text = m.DecodedText
		m.Start = m.DecodedStart
		m.End = m.DecodedStart + len(m.Value)
	}
	record := recordFor(m.Value, it, m.Start)
	if m.ContextName != "" {
		record.Context.Name = m.ContextName
	}
	if m.LiteralContext {
		record.Context.Line = literalModelLine(m, it.Text, record.Context.Line, record.Value)
	}
	return record
}

// literalModelLine projects only the already disclosed scoring value into the
// existing bounded context. It never decodes or sends additional payload data.
func literalModelLine(m detect.Match, text, original, value string) string {
	if m.Start < 0 || m.End < m.Start || m.End > len(text) {
		return original
	}
	prefix, suffix := original, ""
	lo := max(0, m.Start-400)
	nl := strings.LastIndexByte(text[lo:m.Start], '\n')
	if nl >= 0 || lo == 0 {
		pos := m.Start - (lo + nl + 1)
		if pos <= len(original) {
			prefix = original[:pos]
			end := pos + m.End - m.Start
			if end < len(original) {
				suffix = original[end:]
			}
		}
	}
	if len(prefix) > 128 {
		prefix = prefix[:128]
	}
	line := prefix + strconv.Quote(value) + suffix
	if len(line) > 400 {
		line = line[:400]
	}
	return strings.ToValidUTF8(line, "")
}

func (p *Pipeline) revealMatchContext(it model.Item, m detect.Match) *model.FindingContext {
	if !p.options.RevealSecrets {
		return nil
	}
	record := recordForMatch(m, it)
	context := &model.FindingContext{Name: record.Context.Name, Line: record.Context.Line}
	if m.LiteralContext {
		original := lineText(it.Text, m.Start)
		if original != context.Line {
			context.OriginalLine = original
		}
	}
	return context
}

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
func (p *Pipeline) revealContext(it model.Item, start int) *model.FindingContext {
	if !p.options.RevealSecrets {
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
// secrets (score below the threshold), EXCEPT provider-confirmed and structurally-proven hits,
// which are never dropped on a model miss. It fails open: any sidecar error keeps every finding.
func mlFilter(ctx context.Context, ml mlscore.Scorer, out []model.Finding, reqs []mlscore.Record) []model.Finding {
	kept, _ := mlFilterSelected(ctx, ml, out, reqs)
	return kept
}

func mlFilterSelected(ctx context.Context, ml mlscore.Scorer, out []model.Finding, reqs []mlscore.Record) ([]model.Finding, []int) {
	results, err := ml.Score(ctx, reqs)
	if err != nil {
		logx.Warn("ml scoring failed — keeping all findings (fail-open)", "err", err)
		return out, nil
	}
	if len(results) != len(out) {
		logx.Warn("ml scoring returned an incomplete batch — keeping all findings (fail-open)")
		return out, nil
	}
	threshold := ml.Threshold()
	if !mlscore.ValidScore(threshold) {
		logx.Warn("ml scoring has an invalid threshold — keeping all findings (fail-open)")
		return out, nil
	}
	// Validate the entire batch before reusing out's backing array; a later invalid result must
	// preserve earlier candidates too, regardless of their otherwise-valid low scores.
	for _, result := range results {
		if !mlscore.ValidScore(result.Score) {
			logx.Warn("ml scoring returned an invalid score — keeping all findings (fail-open)")
			return out, nil
		}
	}
	kept := out[:0]
	indices := make([]int, 0, len(out))
	for i, f := range out {
		if mlExempt(f) || results[i].Score >= threshold {
			kept = append(kept, f)
			indices = append(indices, i)
		} else {
			model.CoverageFrom(ctx).Filtered()
		}
	}
	return kept, indices
}

// mlExemptTypes carry no "private"/"key" token yet must never be ML-dropped — notably
// gcp_service_account, a "-----BEGIN PRIVATE KEY-----" inside JSON (category "cloud", not "pki").
var mlExemptTypes = map[string]bool{
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
func applyVerify(ctx context.Context, vset *verify.Set, typeID, raw, context string) (*bool, string, *model.Verification) {
	if vset == nil {
		return nil, "", nil
	}
	r := vset.Verify(ctx, typeID, raw, context, detect.IsExampleOrPlaceholder(raw))
	return verificationResult(r)
}

func verificationResult(r verify.Result) (*bool, string, *model.Verification) {
	detail := verificationMetadata(r)
	switch r.Status {
	case verify.Verified:
		t := true
		if r.Note != "" {
			return &t, "verified live: " + r.Note, detail // carries the blast radius (unlocks: …) when mapped
		}
		return &t, "verified live via " + r.Verifier, detail
	case verify.Invalid:
		f := false
		return &f, "provider rejected the credential (" + r.Verifier + ")", detail
	case verify.Errored:
		return nil, "verification inconclusive: " + r.Note, detail
	default:
		return nil, "", detail
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
