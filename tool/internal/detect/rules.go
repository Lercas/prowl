package detect

import (
	"context"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"
	"unsafe"

	"github.com/Lercas/prowl/tool/internal/ahocorasick"
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
	Type          string
	Value         string
	Start, End    int
	Confidence    float64
	ChecksumValid bool
	Category      string
	Stage         string
	DecodedText   string // internal decoded context, never serialized as evidence
	DecodedStart  int
	DecodeSpans   []Base64Span // Each decoding layer mapped to original source bytes.
	Transform     string
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
}

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
	return d.ScanWithOptions(ctx, text, ScanOptions{})
}

// ScanOptions selects source grammar without changing the configured taxonomy or match budget.
type ScanOptions struct {
	BarePasswordLiterals bool // .env/YAML/INI/shell permit unquoted scalar credentials
	PasswordScalars      map[int]PasswordScalar
	YAML                 bool
}

// PasswordScalar carries a parser-established value and its original source end.
type PasswordScalar struct {
	Value string
	End   int
	Name  string // Nonempty only for a parser-established credential binding.
}

// ScanWithOptions keeps source grammar explicit; decoding and unknown sources use conservative defaults.
func (d *Detector) ScanWithOptions(ctx context.Context, text string, opts ScanOptions) []Match {
	return d.ScanWithStatus(ctx, text, opts).Matches
}

type ScanResult struct {
	Matches          []Match
	Base64Limited    bool
	CandidateLimited bool
}

// ScanCtxWithStatus reports all candidate and decoding limits.
func (d *Detector) ScanCtxWithStatus(ctx context.Context, text string) ([]Match, bool) {
	r := d.ScanWithStatus(ctx, text, ScanOptions{})
	return r.Matches, r.Base64Limited || r.CandidateLimited
}

// ScanWithStatus exposes decoding limits so callers cannot report a bounded partial scan as clean.
func (d *Detector) ScanWithStatus(ctx context.Context, text string, opts ScanOptions) ScanResult {
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
	// Candidate and decoding budgets remain independent.
	all, collectCapped := d.collectWithOptions(ctx, text, present, sig, opts)
	// contextualPassword honors the remaining budget internally (one match per cue line)
	cp := d.contextualPassword(text, lower, uniLower, present, maxScanMatches-len(all))
	all = append(all, cp...)
	candidateCapped := collectCapped || len(all) >= maxScanMatches
	d.presentPool.Put(pp)
	d.lowerPool.Put(lb) // `lower` views lb and must not be used past here
	b64, limited := d.unmaskBase64(ctx, text)
	all = append(all, b64...)
	// dedupeOverlapsCap sorts confidence-first, drops overlaps, then truncates to maxScanMatches.
	kept, truncated := dedupeOverlapsCap(all, maxScanMatches)
	truncated = truncated || candidateCapped
	if truncated && !collectCapped {
		// surface that a secret past the global cap was dropped (collect() warns when IT hit the cap)
		logx.Warn("detect: match cap reached — some findings in this dense input were not collected",
			"cap", maxScanMatches)
	}
	return ScanResult{Matches: kept, Base64Limited: limited, CandidateLimited: truncated}
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
func (d *Detector) collect(ctx context.Context, text string, present []bool, sig structSignals) ([]Match, bool) {
	return d.collectWithOptions(ctx, text, present, sig, ScanOptions{})
}

func (d *Detector) collectWithOptions(ctx context.Context, text string, present []bool, sig structSignals, opts ScanOptions) ([]Match, bool) {
	var all []Match
	capped := false
	// Parser-established bindings do not depend on a lexical reader understanding escaped quotes,
	// newlines or the first character of a canonical value. Respect the configured taxonomy.
	for _, ct := range d.types {
		if ct.st.ID != "generic_password" {
			continue
		}
		starts := make([]int, 0, len(opts.PasswordScalars))
		for start, scalar := range opts.PasswordScalars {
			if scalar.Name != "" {
				starts = append(starts, start)
			}
		}
		sort.Ints(starts)
		for _, start := range starts {
			if ctx.Err() != nil || len(all) >= maxScanMatches {
				break
			}
			scalar := opts.PasswordScalars[start]
			if start < 0 || scalar.End > len(text) || scalar.End < start || len(scalar.Value) > 4096 || utf8.RuneCountInString(scalar.Value) < 6 ||
				!ct.st.RE.MatchString("\""+scalar.Name+"\": \"V\"") || IsCanonicalPasswordPlaceholder(scalar.Value) || IsEncodedPasswordHash(scalar.Value) || strings.HasPrefix(scalar.Value, "data:") {
				continue
			}
			all = append(all, Match{Type: ct.st.ID, Value: scalar.Value, Start: start, End: scalar.End, Confidence: .6, Category: ct.st.Category, Stage: "L1-regex"})
		}
	}
	for _, ct := range d.types {
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
		if ct.pf != nil {
			if !ct.pf(sig) {
				continue
			}
		} else if len(ct.kwIdx) > 0 && !anyPresent(present, ct.kwIdx) {
			continue
		}
		// cap the per-type FindAll so a pathological file can't build a huge slice up front (it isn't ctx-interruptible)
		indices := st.RE.FindAllStringSubmatchIndex(text, maxScanMatches+1)
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
			if scalar, ok := opts.PasswordScalars[vs]; ok && scalar.Name != "" && st.ID == "generic_password" {
				continue // The complete parser-established value was nominated above.
			}
			// A capped generic regex must not mint an identity for a prefix of a longer credential.
			// The entropy producer can still report its full adjacent run when supported.
			if st.ID == "generic_api_key" && ve < len(text) {
				c := text[ve]
				if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' {
					continue
				}
			}
			quoted := vs > 0 && strings.ContainsRune("\"'`", rune(text[vs-1]))
			literalPassword := st.ID == "generic_password" && BindingName(text, vs) != "" && (quoted || opts.BarePasswordLiterals)
			if literalPassword && opts.YAML && !quoted && vs < len(text) && strings.ContainsRune("*&!|>{[#", rune(text[vs])) {
				continue // collections, references, tags, block indicators and comments are not scalars
			}
			if literalPassword {
				var complete bool
				ve, complete = literalPasswordEnd(text, vs)
				if !complete {
					continue
				}
			} else if st.ID == "generic_password" {
				// Unknown/code sources retain the former single-token grammar. Quoted literals may
				// start with whitespace or punctuation and are instead read as complete scalars above.
				ve = vs
				for count := 0; ve < len(text) && count < 64; count++ {
					r, size := utf8.DecodeRuneInString(text[ve:])
					if strings.ContainsRune("\"' \t\v\f\r\n,;", r) {
						break
					}
					ve += size
				}
			}
			val := text[vs:ve]
			transform := ""
			if literalPassword {
				if scalar, ok := opts.PasswordScalars[vs]; ok && scalar.End >= vs && scalar.End <= len(text) && len(scalar.Value) <= 4096 {
					ve, val = scalar.End, scalar.Value
					transform = "yaml-scalar"
				}
			}
			if st.ID == "generic_password" && utf8.RuneCountInString(val) < 6 {
				continue
			}
			placeholder := IsExampleOrPlaceholder(val)
			if literalPassword {
				placeholder = IsLiteralPasswordPlaceholder(val)
			}
			if placeholder {
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
				// A quoted value (`password = "Winter(2024"`) is the common leak form and may legitimately
				// contain brackets, so the looksLikeIdentifier / bracket-balance heuristics apply only to
				// UNQUOTED values, where `bytes)` / `get_auth_from_url(proxy)` really are swept-up code.
				primitive := !quoted && (val == "string" || val == "String" || val == "boolean" || val == "Boolean" || val == "number" || val == "Number" || val == "object" || val == "Object")
				codeShape := !literalPassword && (primitive || isVersionOrNumber(val) || hasJSOperator(val) || looksLikeUnicodeEscaped(val) || (!quoted && (looksLikeJSCode(val) || looksLikeIdentifier(val))))
				if codeShape || IsEncodedPasswordHash(passwordLiteral(text, vs, ve)) || strings.HasPrefix(val, "data:") {
					continue
				}
				// An explicit credential assignment is sufficient even for a weak lowercase password in
				// any supported language. The bounded adjacent binding also supports multiline JSON.
				explicit := BindingName(text, vs) != ""
				if !explicit && !looksLikePassword(val) {
					continue
				}
			}
			checked, valid := checksumValid(st.ID, val)
			conf, stage := 0.9, "L1-regex"
			switch {
			case st.ID == "jwt":
				if !JWTStructuralOK(val) {
					continue
				}
				stage = "L1-structure" // Parsing is evidence of shape, not checksum/signature proof.
			case checked && valid:
				conf, stage = 0.99, "L1-checksum"
			case checked && !valid:
				// For a prefix-defined token (github ghp_/…) a failed CRC doesn't prove fake (our CRC is
				// best-effort), so gate on entropy and report at reduced confidence instead of dropping.
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
				Confidence: conf, ChecksumValid: valid, Category: st.Category, Stage: stage, Transform: transform})
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

// dedupeOverlapsCap keeps the highest-confidence match per overlapping span, capping the kept count.
// Confidence-first ordering lets a precise token (checksum-valid github_pat_classic, 0.99) win over a
// wider low-confidence run (generic_high_entropy, 0.55) that contains it, even when the run starts earlier.
//
// A compressed prefix-max tree answers whether any kept span starting before m.End ends after
// m.Start. Append-only output avoids linear insertion shifts on mixed-confidence dense inputs.
// Sorting and overlap checks are O(n log n). Different decoded values may share one outer span.
// A negative cap means no cap; the bool reports truncation.
func dedupeOverlapsCap(ms []Match, cap int) (kept []Match, truncated bool) {
	sort.Slice(ms, func(i, j int) bool {
		if ms[i].Confidence != ms[j].Confidence {
			return ms[i].Confidence > ms[j].Confidence
		}
		// A contextual guess must not replace an equally confident exact regex/checksum span with
		// a larger token containing its assignment name. This priority precedes position for all types.
		if ci, cj := ms[i].Stage == "L1-context-pw", ms[j].Stage == "L1-context-pw"; ci != cj {
			return !ci
		}
		if ms[i].Start != ms[j].Start {
			return ms[i].Start < ms[j].Start
		}
		return ms[i].End > ms[j].End // on ties prefer the wider span
	})
	starts := make([]int, len(ms))
	for i, m := range ms {
		starts[i] = m.Start
	}
	sort.Ints(starts)
	unique := starts[:0]
	for _, start := range starts {
		if len(unique) == 0 || unique[len(unique)-1] != start {
			unique = append(unique, start)
		}
	}
	maxEnd := make([]int, len(unique)+1)
	rawMaxEnd := make([]int, len(unique)+1)
	out := make([]Match, 0, len(ms))
	type decodedKey struct {
		start, end int
		value      string
	}
	decodedValues := map[decodedKey]bool{}
	for _, m := range ms {
		if cap >= 0 && len(out) >= cap {
			// budget reached: remaining candidates are <= the confidence already kept, so drop the tail
			truncated = true
			break
		}
		latestEnd := 0
		rawLatestEnd := 0
		for i := sort.SearchInts(unique, m.End); i > 0; i -= i & -i {
			latestEnd = max(latestEnd, maxEnd[i])
			rawLatestEnd = max(rawLatestEnd, rawMaxEnd[i])
		}
		decoded := strings.HasPrefix(m.Stage, "L1-base64")
		if decoded {
			key := decodedKey{m.Start, m.End, m.Value}
			if rawLatestEnd > m.Start || decodedValues[key] {
				continue
			}
			decodedValues[key] = true
		} else if latestEnd > m.Start {
			continue
		}
		for i := sort.SearchInts(unique, m.Start) + 1; i < len(maxEnd); i += i & -i {
			maxEnd[i] = max(maxEnd[i], m.End)
			if !decoded {
				rawMaxEnd[i] = max(rawMaxEnd[i], m.End)
			}
		}
		out = append(out, m)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out, truncated
}
