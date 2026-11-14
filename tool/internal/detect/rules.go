package detect

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/Lercas/prowl/tool/internal/ahocorasick"
	"github.com/Lercas/prowl/tool/internal/linewin"
	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

// lowerScratch ASCII-lowercases src into the pooled buffer and returns a zero-copy view. Byte
// positions match src so spans stay valid; the returned string is valid until buf is reused.
func lowerScratch(buf *[]byte, src string) string {
	if len(src) == 0 {
		return ""
	}
	if cap(*buf) < len(src) {
		*buf = make([]byte, len(src))
	}
	dst := (*buf)[:len(src)]
	for i := 0; i < len(src); i++ {
		c := src[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		dst[i] = c
	}
	return unsafe.String(&dst[0], len(src))
}

// hasNonASCII reports whether s contains any byte >= 0x80 (i.e. a multibyte/non-ASCII rune that the
// ASCII lowerScratch can't fold).
func hasNonASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return true
		}
	}
	return false
}

// Match is one L1 detection in a text block.
type Match struct {
	ContextName   string // semantic source label when the value is in a table column
	Type          string
	Value         string
	Start, End    int
	Confidence    float64
	ChecksumValid bool
	Category      string
	Stage         string
	// needsStrong marks a decode candidate with no secret-like name on its line: only a precise typed
	// hit inside it is reported. Internal to the decode stage; never set on a returned Match.
	needsStrong bool
}

// compiledType pairs a secret type with its keyword pre-filter.
type compiledType struct {
	st    taxonomy.SecretType
	kws   []string
	kwIdx []int
	pf    func(structSignals) bool // structural pre-filter, used instead of the keyword check when set
}

// Detector runs the taxonomy L1 layer (regex + checksum + entropy + example filter).
type Detector struct {
	types       []compiledType
	allKW       []string
	ac          *ahocorasick.Matcher
	cueIdx      []int // indices in allKW of the multilingual password cues
	presentPool sync.Pool
	lowerPool   sync.Pool
	genericPwd  bool // taxonomy declares generic_password — gates the contextual-password builtin
	// basicAuth: taxonomy declares basic_auth_header — gates the encoded user:password builtin.
	basicAuth    bool
	basicAuthCat string
	// genericKey: taxonomy declares generic_api_key — gates the named-assignment builtins (named.go).
	genericKey    bool
	genericKeyCat string
	namedWin      *linewin.Set
	// win runs each type's regex over only the lines around its required literals (see linewin);
	// indexed like types. Types it can't prove equivalent keep the whole-text pass.
	win      *linewin.Set
	wantPool sync.Pool
}

// wholeTextOnly disables line-windowed regex evaluation. Tests flip it to assert that windowing
// reports exactly what a whole-text pass does.
var wholeTextOnly atomic.Bool

// New orders types structured-first, generic-last and precomputes keyword pre-filters.
func New(tax *taxonomy.Taxonomy) *Detector {
	order := make([]taxonomy.SecretType, len(tax.Types))
	copy(order, tax.Types)
	sort.SliceStable(order, func(i, j int) bool {
		gi, gj := taxonomy.GenericLast[order[i].ID], taxonomy.GenericLast[order[j].ID]
		if gi != gj {
			return !gi
		}
		return false
	})
	d := &Detector{types: make([]compiledType, len(order))}
	kwID := map[string]int{}
	for i, st := range order {
		kws := keywordsFor(st)
		idx := make([]int, 0, len(kws))
		for _, kw := range kws {
			id, ok := kwID[kw]
			if !ok {
				id = len(d.allKW)
				kwID[kw] = id
				d.allKW = append(d.allKW, kw)
			}
			idx = append(idx, id)
		}
		d.types[i] = compiledType{st: st, kws: kws, kwIdx: idx, pf: structuralPrefilter[st.ID]}
		if st.ID == "generic_password" {
			d.genericPwd = true
		}
		if st.ID == "basic_auth_header" {
			d.basicAuth, d.basicAuthCat = true, st.Category
		}
		if st.ID == "generic_api_key" {
			d.genericKey, d.genericKeyCat = true, st.Category
		}
	}
	// fold password cues into the keyword set so the single AC pass covers them too
	for _, kw := range mlPasswordCues {
		id, ok := kwID[kw]
		if !ok {
			id = len(d.allKW)
			kwID[kw] = id
			d.allKW = append(d.allKW, kw)
		}
		d.cueIdx = append(d.cueIdx, id)
	}
	d.ac = ahocorasick.New(d.allKW)
	d.presentPool = sync.Pool{New: func() any { s := make([]bool, len(d.allKW)); return &s }}
	d.lowerPool = sync.Pool{New: func() any { s := make([]byte, 0, 4096); return &s }}
	res := make([]*regexp.Regexp, len(d.types))
	for i, ct := range d.types {
		if ct.st.ID != "generic_high_entropy" { // served by the byte-scan runs, its regex never runs
			res[i] = ct.st.RE
		}
	}
	d.win = linewin.New(res)
	d.namedWin = linewin.New(namedBuiltins)
	d.wantPool = sync.Pool{New: func() any { s := make([]bool, len(d.types)); return &s }}
	return d
}

// keywordsPresent runs one Aho-Corasick pass flagging every keyword/cue present (allocating).
func (d *Detector) keywordsPresent(lower string) []bool {
	present := make([]bool, len(d.allKW))
	d.ac.MatchInto(lower, present)
	return present
}

func anyPresent(present []bool, idx []int) bool {
	for _, i := range idx {
		if present[i] {
			return true
		}
	}
	return false
}

// MaxScanMatches reports the global per-Scan match cap, exported so the scan orchestrator can bound the
// combined output of both producers (the cascade and the rule-template engine) at the same ceiling.
func MaxScanMatches() int { return maxScanMatches }

// Scan returns non-overlapping highest-confidence matches, including secrets hidden inside base64 blobs.
// It runs the cascade with no cancellation; use ScanCtx to bound a dense file with --timeout/Ctrl-C.
func (d *Detector) Scan(text string) []Match {
	return d.ScanCtx(context.Background(), text)
}

// ScanCtx is Scan with a context that collect's match-building loops check.
func (d *Detector) ScanCtx(ctx context.Context, text string) []Match {
	matches, _ := d.ScanCtxWithStatus(ctx, text)
	return matches
}

// ScanCtxWithStatus also reports whether a candidate limit made scan completeness uncertain.
// The flag survives filtering and overlap deduplication, which can shrink the returned slice.
// Cancellation is represented by ctx.Err(), independently of this candidate-cap flag.
func (d *Detector) ScanCtxWithStatus(ctx context.Context, text string) ([]Match, bool) {
	lb := d.lowerPool.Get().(*[]byte)
	lower := lowerScratch(lb, text)
	pp := d.presentPool.Get().(*[]bool)
	present := *pp
	for i := range present {
		present[i] = false
	}
	sig := d.acAndStructure(lower, present)
	// The ASCII lowerScratch can't fold non-ASCII cues (ПАРОЛЬ, CONTRASEÑA), so when text has any byte
	// >=0x80 also run the AC pass over a Unicode-correct lowercase. Used only for keyword presence, never
	// for slicing spans (its length may differ).
	var uniLower string
	if hasNonASCII(text) {
		uniLower = strings.ToLower(text)
		d.ac.MatchInto(uniLower, present)
	}
	// The cap is global to one Scan and applied AFTER the confidence-first sort, so high-confidence
	// findings survive truncation rather than the 0.55 entropy net filling the budget first. Each producer
	// (collect/contextualPassword and the independent decode-candidate collector) bounds its own output.
	// unmaskBase64 retains at most one decoded winner per outer candidate; the final overlap pass
	// sorts confidence-first and truncates last.
	all, collectCapped := d.collect(ctx, text, lower, uniLower, present, sig)
	// contextualPassword honors the remaining budget internally (one match per cue line)
	cp := d.contextualPassword(text, lower, uniLower, present, maxScanMatches-len(all))
	all = append(all, cp...)
	named, namedCapped := d.namedSecrets(ctx, text, lower, maxScanMatches-len(all))
	all = append(all, named...)
	tables, tableCapped := d.tableSecrets(ctx, text, maxScanMatches-len(all))
	all = append(all, tables...)
	candidateCapped := collectCapped || namedCapped || tableCapped || len(all) >= maxScanMatches
	d.presentPool.Put(pp)
	d.lowerPool.Put(lb) // `lower` views lb and must not be used past here
	// unmaskBase64 is not budget-gated: a base64-embedded structured secret (conf ~0.94) must compete on
	// confidence in the sort below, not be starved by a cap full of 0.55 generic noise.
	b64, base64Capped := d.unmaskBase64(ctx, all)
	all = append(all, b64...)
	// Both alphabets must be decoded whole: the entropy net omits short blobs, '-'/'_' split it,
	// and generic assignment regexes can truncate the value or exhaust their budget first.
	// These independent candidates never become generic findings.
	decodeCandidates, decodeCandidateCapped := base64Candidates(ctx, text, sig.b64decodeRuns)
	decodedMatches, decodedCapped := d.unmaskBase64(ctx, decodeCandidates)
	all = append(all, decodedMatches...)
	authMatches, authCapped := d.encodedBasicAuth(ctx, text, sig.b64decodeRuns, maxScanMatches)
	all = append(all, authMatches...)
	// Secrets written through an escaping, concatenation or YAML block-scalar layer (see views.go).
	viewMatches, viewCapped := d.scanViewsStatus(ctx, text)
	all = append(all, viewMatches...)
	// dedupeOverlapsCap sorts confidence-first, drops overlaps, then truncates to maxScanMatches.
	kept, truncated := dedupeOverlapsCap(all, maxScanMatches)
	truncated = truncated || candidateCapped || base64Capped || decodeCandidateCapped || decodedCapped || authCapped || viewCapped
	if truncated && !collectCapped {
		// surface that a secret past the global cap was dropped (collect() warns when IT hit the cap)
		logx.Warn("detect: scan limits reached — some encoded candidates or matches may not have been inspected")
	}
	return kept, truncated
}

// acAndStructure fuses the Aho-Corasick keyword pass and the structural byte-scan into one loop.
// Lowercasing preserves the b64/digit/dot char classes, so the spans match scanStructure(text).
func (d *Detector) acAndStructure(lower string, present []bool) structSignals {
	next, out := d.ac.Transitions(), d.ac.Outputs()
	var sig structSignals
	var cur int32
	n := len(lower)
	b64start, digitRun, tokStart, tokDots := -1, 0, -1, 0
	urlStart, urlSpecific := -1, false
	decodeStart, decodeAlphabet := -1, byte(0)
	for i := 0; i < n; i++ {
		c := lower[i]
		cur = next[cur<<8|int32(c)]
		for _, id := range out[cur] {
			present[id] = true
		}
		alnum := c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
		if alnum || c == '+' || c == '/' {
			if b64start < 0 {
				b64start = i
			}
		} else {
			if b64start >= 0 && i-b64start >= 32 {
				sig.b64runs = append(sig.b64runs, [2]int{b64start, i})
			}
			b64start = -1
		}
		if alnum || c == '-' || c == '_' {
			if urlStart < 0 {
				urlStart = i
			}
			urlSpecific = urlSpecific || c == '-' || c == '_'
		} else {
			if urlStart >= 0 && i-urlStart >= 32 && urlSpecific {
				sig.b64urlruns = append(sig.b64urlruns, [2]int{urlStart, i})
			}
			urlStart, urlSpecific = -1, false
		}
		if alnum || c == '+' || c == '/' || c == '-' || c == '_' {
			if decodeStart < 0 {
				decodeStart = i
			}
			if c == '+' || c == '/' {
				decodeAlphabet |= 1
			}
			if c == '-' || c == '_' {
				decodeAlphabet |= 2
			}
		} else {
			if decodeStart >= 0 && i-decodeStart >= minBase64CandidateBytes && decodeAlphabet != 3 {
				sig.b64decodeRuns = append(sig.b64decodeRuns, [2]int{decodeStart, i})
			}
			decodeStart, decodeAlphabet = -1, 0
		}
		if c >= '0' && c <= '9' {
			digitRun++
		} else {
			if c == ':' && digitRun >= 8 {
				sig.digitColon = true
			}
			digitRun = 0
		}
		if alnum || c == '_' || c == '-' || c == '.' {
			if tokStart < 0 {
				tokStart, tokDots = i, 0
			}
			if c == '.' {
				tokDots++
			}
		} else {
			if tokStart >= 0 && i-tokStart >= 50 && tokDots >= 2 {
				sig.dottedToken = true
			}
			tokStart = -1
		}
	}
	if b64start >= 0 && n-b64start >= 32 {
		sig.b64runs = append(sig.b64runs, [2]int{b64start, n})
	}
	if urlStart >= 0 && n-urlStart >= 32 && urlSpecific {
		sig.b64urlruns = append(sig.b64urlruns, [2]int{urlStart, n})
	}
	if decodeStart >= 0 && n-decodeStart >= minBase64CandidateBytes && decodeAlphabet != 3 {
		sig.b64decodeRuns = append(sig.b64decodeRuns, [2]int{decodeStart, n})
	}
	if tokStart >= 0 && n-tokStart >= 50 && tokDots >= 2 {
		sig.dottedToken = true
	}
	return sig
}

// extractSpan returns the [start,end) span of the secret value from a FindAllStringSubmatchIndex slice.
// `extract` is the requested 1-based capture group (gitleaks secretGroup); when set and participating its
// span is used, otherwise the engine falls back to capture group 1 if present, else the whole match.
func extractSpan(ix []int, extract int) (start, end int) {
	if extract > 0 {
		if lo := 2 * extract; lo+1 < len(ix) && ix[lo] >= 0 {
			return ix[lo], ix[lo+1]
		}
		// requested group missing/non-participating: fall through to the default below
	}
	if len(ix) >= 4 && ix[2] >= 0 { // prefer capture group 1
		return ix[2], ix[3]
	}
	return ix[0], ix[1]
}

// collect runs the regex/checksum/entropy rules over text, skipping a type's regex when the keyword
// pre-filter finds none of its keywords present.
func (d *Detector) collect(ctx context.Context, text, lower, uniLower string, present []bool, sig structSignals) ([]Match, bool) {
	var all []Match
	capped := false
	// Decide up front which types' regexes will run, so one literal pass can build the line regions
	// for all of them. A text with no pre-filter hit (the common clean file) skips that pass entirely.
	wp := d.wantPool.Get().(*[]bool)
	want, anyWanted := *wp, false
	for i, ct := range d.types {
		switch {
		case ct.st.ID == "generic_high_entropy":
			want[i] = false
		case ct.pf != nil:
			want[i] = ct.pf(sig)
		default:
			want[i] = len(ct.kwIdx) == 0 || anyPresent(present, ct.kwIdx)
		}
		anyWanted = anyWanted || want[i]
	}
	var wins *linewin.Windows
	if anyWanted && !wholeTextOnly.Load() {
		wins = d.win.Prepare(text, lower, uniLower, want)
	}
	defer func() {
		wins.Release()
		d.wantPool.Put(wp)
	}()
	for ti, ct := range d.types {
		// ctx/cap checks bound the match-building loops only; the core O(n) AC + structure scans aren't
		// ctx-interruptible, so a single file is bounded by --max-size and --timeout bounds the whole run.
		if ctx.Err() != nil || len(all) >= maxScanMatches {
			break
		}
		st := ct.st
		// entropy catch-all uses the precomputed byte-scan runs, not an RE2 {32,} pass
		if st.ID == "generic_high_entropy" {
			for n, r := range sig.b64runs {
				if n&4095 == 0 && ctx.Err() != nil {
					break
				}
				if len(all) >= maxScanMatches {
					break
				}
				val := text[r[0]:r[1]]
				if IsExampleOrPlaceholder(val) || ShannonEntropy(val) < genericEntropyMin {
					continue
				}
				if IsHashNotSecret(text, r[0], val) {
					continue
				}
				if IsKnownNonSecretBlob(text, r[0]) {
					continue
				}
				if looksLikeCodePath(val) || (reRecaptchaSiteKey.MatchString(val) && hasRecaptchaCue(text, r[0])) {
					continue
				}
				if !HasSecretNameContext(text, r[0]) { // require a secret-like name nearby
					continue
				}
				all = append(all, Match{Type: st.ID, Value: val, Start: r[0], End: r[1],
					Confidence: 0.55, Category: st.Category, Stage: "L1-entropy"})
			}
			continue
		}
		if !want[ti] {
			continue
		}
		// cap the per-type FindAll so a pathological file can't build a huge slice up front (it isn't ctx-interruptible)
		indices := wins.FindAll(ti, st.RE, text, maxScanMatches+1)
		if len(indices) > maxScanMatches {
			// Filters can discard every extracted candidate, but the bounded regex walk may still
			// have omitted a later real secret. Keep that uncertainty separate from accepted hits.
			capped = true
		}
		for n, ix := range indices {
			if n&4095 == 0 && ctx.Err() != nil {
				break
			}
			if len(all) >= maxScanMatches {
				break
			}
			vs, ve := extractSpan(ix, st.Extract)
			val := text[vs:ve]
			if IsExampleOrPlaceholder(val) {
				continue
			}
			// connection URI whose password segment is an unresolved variable ref is not a literal
			// secret; judge on the credential segment since the reported value is the whole URI
			if (st.ID == "db_connection_string" || st.ID == "basic_auth_header") &&
				(ConnURICredentialIsPlaceholder(val) || looksLikeRegexAuthority(val)) {
				continue
			}
			// generic_api_key captures whatever follows the cue, often an instructional placeholder
			if st.ID == "generic_api_key" && (IsPlaceholderAPIKey(val) || isLicenseKeyShape(val)) {
				continue
			}
			// drop the jwt.io demo token and doc fixtures; real tokens still fire
			if st.ID == "jwt" && IsExampleJWT(val) {
				continue
			}
			if st.ID == "generic_password" {
				if isBcryptHash(val) {
					continue
				}
				// A quoted value (`password = "Winter(2024"`) is the common leak form and may legitimately
				// contain brackets, so the looksLikeIdentifier / bracket-balance heuristics apply only to
				// UNQUOTED values, where `bytes)` / `get_auth_from_url(proxy)` really are swept-up code.
				quoted := vs > 0 && (text[vs-1] == '"' || text[vs-1] == '\'' || text[vs-1] == '`')
				if isVersionOrNumber(val) || hasJSOperator(val) || looksLikeUnicodeEscaped(val) || (!quoted && (looksLikeJSCode(val) || looksLikeIdentifier(val))) {
					continue
				}
				// Look back for a pass/pwd/pw cue, bounded to pwdCueLookback bytes: on a pathological single
				// long line an unbounded line-prefix scan+lowercase is O(vs) per match (O(N^2)). The cue sits
				// in the immediate `name =` prefix, and the window never crosses a newline.
				lo := vs - pwdCueLookback
				if lo < 0 {
					lo = 0
				}
				if nl := strings.LastIndexByte(text[lo:vs], '\n'); nl >= 0 {
					lo += nl + 1
				}
				before := strings.ToLower(text[lo:vs])
				explicit := strings.Contains(before, "pass") || strings.Contains(before, "pwd") || strings.Contains(before, "pw")
				if !explicit && !looksLikePassword(val) {
					continue
				}
			}
			checked, valid := checksumValid(st.ID, val)
			conf, stage := 0.9, "L1-regex"
			switch {
			case checked && valid:
				conf, stage = 0.99, "L1-checksum"
			case checked && !valid:
				// Checksum failed. For a structural type (jwt) that proves it isn't one — drop it. For a
				// prefix-defined token (github ghp_/…) a failed CRC doesn't prove fake (our CRC is
				// best-effort), so gate on entropy and report at reduced confidence instead of dropping.
				if st.ID == "jwt" {
					continue
				}
				if ShannonEntropy(val) < 3.2 {
					continue
				}
				conf = 0.6
			case st.ID == "generic_high_entropy":
				if ShannonEntropy(val) < genericEntropyMin {
					continue
				}
				conf = 0.55
			case st.ID == "github_pat_fine_grained":
				// Fine-grained PATs use a checksum GithubChecksumOK can't verify, so they reach here
				// unchecked. Gate on an entropy floor (~3.2) to drop shaped-but-empty placeholders, and
				// report real tokens at reduced confidence since the checksum is unproven.
				if ShannonEntropy(val) < 3.2 {
					continue
				}
				conf = 0.6
			case taxonomy.GenericLast[st.ID]:
				conf = 0.6
			}
			all = append(all, Match{Type: st.ID, Value: val, Start: vs, End: ve,
				Confidence: conf, ChecksumValid: valid, Category: st.Category, Stage: stage})
		}
	}
	capped = capped || len(all) >= maxScanMatches
	if capped {
		// surface that the dense input was truncated (a secret past the cap is dropped)
		logx.Warn("detect: match cap reached — some findings in this dense input were not collected",
			"cap", maxScanMatches)
	}
	return all, capped
}

// isContextStage marks the builtins that infer a secret from the name around it.
func isContextStage(stage string) bool {
	return stage == "L1-context-pw" || stage == stageContextKey || stage == stageTable || stage == stageComparison || stage == stageCharCode
}

// dedupeOverlapsCap keeps the highest-confidence match per overlapping span, capping the kept count.
// Confidence-first ordering lets a precise token (checksum-valid github_pat_classic, 0.99) win over a
// wider low-confidence run (generic_high_entropy, 0.55) that contains it, even when the run starts earlier.
//
// Candidates are processed in confidence order and `out` is kept sorted by Start. Since kept spans are
// disjoint, a new candidate can only overlap the first kept span at/after it or its predecessor, both
// found by binary search — making the pass O(n log n) instead of O(n^2). Truncating at `cap` therefore
// retains the highest-confidence findings. A negative cap means no cap; the bool reports truncation.
func dedupeOverlapsCap(ms []Match, cap int) (kept []Match, truncated bool) {
	sort.Slice(ms, func(i, j int) bool {
		if ms[i].Confidence != ms[j].Confidence {
			return ms[i].Confidence > ms[j].Confidence
		}
		// A contextual guess must not replace an equally confident exact regex/checksum span with
		// a larger token containing its assignment name. This priority precedes position for all types.
		if ci, cj := isContextStage(ms[i].Stage), isContextStage(ms[j].Stage); ci != cj {
			return !ci
		}
		if ms[i].Start != ms[j].Start {
			return ms[i].Start < ms[j].Start
		}
		if ms[i].End != ms[j].End {
			return ms[i].End > ms[j].End // on ties prefer the wider span
		}
		// Same span and confidence: order by content so the survivor does not depend on sort internals.
		// The shorter value wins — for one span read both raw and through an unescaping view, that is
		// the unescaped secret itself rather than its escaped spelling.
		if ms[i].Type != ms[j].Type {
			return ms[i].Type < ms[j].Type
		}
		if len(ms[i].Value) != len(ms[j].Value) {
			return len(ms[i].Value) < len(ms[j].Value)
		}
		if ms[i].Value != ms[j].Value {
			return ms[i].Value < ms[j].Value
		}
		// Identical contextual candidates retain a proven field label instead
		// of depending on which producer happened to append first.
		if (ms[i].ContextName != "") != (ms[j].ContextName != "") {
			return ms[i].ContextName != ""
		}
		if ms[i].ContextName != ms[j].ContextName {
			return ms[i].ContextName < ms[j].ContextName
		}
		return ms[i].Stage < ms[j].Stage
	})
	out := make([]Match, 0, len(ms)) // kept spans, maintained sorted by Start
	for _, m := range ms {
		if cap >= 0 && len(out) >= cap {
			// budget reached: remaining candidates are <= the confidence already kept, so drop the tail
			truncated = true
			break
		}
		// first kept span with Start >= m.Start
		i := sort.Search(len(out), func(k int) bool { return out[k].Start >= m.Start })
		overlap := false
		if i < len(out) && out[i].Start < m.End { // kept span starting in [m.Start, m.End)
			overlap = true
		} else if i > 0 && m.Start < out[i-1].End { // predecessor extends past m.Start
			overlap = true
		}
		if overlap {
			continue
		}
		out = append(out, Match{}) // grow
		copy(out[i+1:], out[i:])   // shift to keep Start order
		out[i] = m                 // insert at sorted position
	}
	return out, truncated // out is already in positional (Start) order
}
