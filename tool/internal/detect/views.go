package detect

import (
	"context"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

// A view is a rewritten copy of the parts of a text where a secret is present but not in the literal
// form the rules expect:
//
//   - escaped quoting — JSON inside a JSON string (`{\"password\":\"x\"}`), `\/`, `\uXXXX`, `\xNN`;
//   - string concatenation — `"AKIA…" + "…"`, also across a line break;
//   - YAML block scalars — `password: |` / `key: >-` with the value on the next line;
//   - markdown emphasis around an assignment — `**Password:** x`, "`api_key`: `x`" — the usual shape of
//     credentials pasted into tickets, wiki pages and chat.
//
// Construct discovery scans the source; only bounded neighbourhoods are copied.
// Matches found in the view are mapped back to the original bytes. Exhausting
// either bookkeeping or output budgets marks the scan incomplete.

const (
	viewContext       = 256     // bytes kept on each side of a rewritten construct (the cue lookback)
	maxViewBytes      = 1 << 20 // strict per-Scan cap; exhaustion marks the scan incomplete
	maxViewConstructs = 4096    // bounds region/rewrite bookkeeping before assembly
)

// rewrite replaces text[pos:end) by repl in the view.
type rewrite struct {
	pos, end int
	repl     string
	join     bool // a removed concatenation: what it joins was never one literal in the source
}

type view struct {
	constructs int // consumed discovery budget, before neighbourhood merging
	text       string
	start, end []int32 // per view byte: the original [start,end) it came from
	edits      []int   // view offsets where a rewrite happened, ascending
	joins      []int   // subset of edits that are concatenation joins
	cuts       []int   // view offsets of region edges that fall mid-line in the original
}

func isHexByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func hexVal(c byte) rune {
	switch {
	case c >= '0' && c <= '9':
		return rune(c - '0')
	case c >= 'a' && c <= 'f':
		return rune(c-'a') + 10
	}
	return rune(c-'A') + 10
}

// unescapeAt decodes the escape sequence starting at text[i] == '\\'. n is the number of source
// bytes consumed; n == 0 means "not an escape this layer rewrites".
func unescapeAt(text string, i int) (out string, n int) {
	if i+1 >= len(text) {
		return "", 0
	}
	switch c := text[i+1]; c {
	case '"', '\'', '/', '\\':
		return text[i+1 : i+2], 2
	case 'u':
		if i+6 <= len(text) && isHexByte(text[i+2]) && isHexByte(text[i+3]) && isHexByte(text[i+4]) && isHexByte(text[i+5]) {
			r := hexVal(text[i+2])<<12 | hexVal(text[i+3])<<8 | hexVal(text[i+4])<<4 | hexVal(text[i+5])
			if r >= 0x20 && r != 0x7f && utf8.ValidRune(r) {
				return string(r), 6
			}
		}
	case 'x':
		if i+4 <= len(text) && isHexByte(text[i+2]) && isHexByte(text[i+3]) {
			if r := hexVal(text[i+2])<<4 | hexVal(text[i+3]); r >= 0x20 && r < 0x7f {
				return string(r), 4
			}
		}
	}
	return "", 0
}

func isB64Byte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=' || c == '-' || c == '_'
}

func skipBlanksBack(text string, i int) int {
	for i >= 0 && (text[i] == ' ' || text[i] == '\t') {
		i--
	}
	return i
}

func skipBlanks(text string, i int) int {
	for i < len(text) && (text[i] == ' ' || text[i] == '\t') {
		i++
	}
	return i
}

// concatAt recognises `"…" + "…"` around the '+' at text[i] (same quote on both sides, at most one
// line break on either side) and returns the span from the closing to the opening quote, inclusive.
func concatAt(text string, i int) (lo, hi int, ok bool) {
	l := skipBlanksBack(text, i-1)
	if l >= 0 && text[l] == '\n' {
		l--
		if l >= 0 && text[l] == '\r' {
			l--
		}
		l = skipBlanksBack(text, l)
	}
	if l < 1 {
		return 0, 0, false
	}
	q := text[l]
	if q != '"' && q != '\'' && q != '`' {
		return 0, 0, false
	}
	r := skipBlanks(text, i+1)
	if r < len(text) && text[r] == '\r' {
		r++
	}
	if r < len(text) && text[r] == '\n' {
		r = skipBlanks(text, r+1)
	}
	if r+1 >= len(text) || text[r] != q {
		return 0, 0, false
	}
	return l, r + 1, true
}

// blockScalarAt recognises a YAML block scalar indicator at text[i] ('|' or '>') that follows a
// `key:` and is followed by an indented value line. It returns the span from just after the colon to
// the first byte of the value.
func blockScalarAt(text string, i int) (lo, hi int, ok bool) {
	c := skipBlanksBack(text, i-1)
	if c < 1 || text[c] != ':' {
		return 0, 0, false
	}
	k := text[c-1]
	if !(k >= 'a' && k <= 'z' || k >= 'A' && k <= 'Z' || k >= '0' && k <= '9' || k == '_' || k == '-' || k == '"' || k == '\'') {
		return 0, 0, false
	}
	j := i + 1
	for n := 0; n < 2 && j < len(text) && (text[j] == '+' || text[j] == '-' || text[j] >= '1' && text[j] <= '9'); n++ {
		j++
	}
	j = skipBlanks(text, j)
	if j < len(text) && text[j] == '\r' {
		j++
	}
	if j >= len(text) || text[j] != '\n' {
		return 0, 0, false
	}
	v := skipBlanks(text, j+1)
	if v == j+1 || v >= len(text) || text[v] == '\n' || text[v] == '\r' || text[v] == '#' {
		return 0, 0, false
	}
	return c + 1, v, true
}

// markupAt recognises markdown emphasis glued to the assignment sign at text[i] (':' or '='): bold
// markers or a backtick directly before it, and after it (past one optional space) bold markers or a
// backticked value. Each returned span is removed from the view.
func markupAt(text string, i int) (spans [][2]int) {
	// exactly two stars: a longer run is a mask (`user:***@host`) or a rule, not emphasis
	switch {
	case i >= 2 && text[i-1] == '*' && text[i-2] == '*' && (i < 3 || text[i-3] != '*'):
		spans = append(spans, [2]int{i - 2, i})
	case i >= 1 && text[i-1] == '`':
		spans = append(spans, [2]int{i - 1, i})
	}
	j := i + 1
	if j < len(text) && text[j] == ' ' {
		j++
	}
	switch {
	case j+1 < len(text) && text[j] == '*' && text[j+1] == '*' && (j+2 >= len(text) || text[j+2] != '*'):
		spans = append(spans, [2]int{j, j + 2})
	case j < len(text) && text[j] == '`':
		// a backticked value: drop both ticks, but only when it closes on the same line nearby
		if k := strings.IndexAny(text[j+1:min(len(text), j+1+viewContext)], "`\n"); k > 0 && text[j+1+k] == '`' {
			spans = append(spans, [2]int{j, j + 1}, [2]int{j + 1 + k, j + 2 + k})
		}
	}
	return spans
}

// buildView finds the constructs and assembles the view, or returns nil when the text has none.
func buildView(text string) *view {
	v, _ := buildViewStatus(context.Background(), text)
	return v
}

func buildViewStatus(ctx context.Context, text string) (*view, bool) {
	return buildViewBudget(ctx, text, false, maxViewBytes, maxViewConstructs)
}

func buildViewBudget(ctx context.Context, text string, encodingOnly bool, byteBudget, constructBudget int) (*view, bool) {
	if ctx.Err() != nil {
		return nil, false
	}
	if uint64(len(text)) > 1<<31-1 {
		return nil, true // source offset tables use int32
	}
	limited := false
	var rewrites []rewrite
	var regions [][2]int
	// around adds the neighbourhood of [lo,hi): viewContext bytes each side, kept within the lines
	// that hold lo and hi.
	around := func(lo, hi int) {
		if len(regions) >= constructBudget {
			limited = true
			return
		}
		ls, le := max(0, lo-viewContext), min(len(text), hi+viewContext)
		if nl := strings.LastIndexByte(text[ls:lo], '\n'); nl >= 0 {
			ls += nl + 1
		}
		if nl := strings.IndexByte(text[hi:le], '\n'); nl >= 0 {
			le = hi + nl
		}
		regions = append(regions, [2]int{ls, le})
	}
	if encodingOnly {
		for i := strings.IndexAny(text, "%&"); i >= 0; {
			if limited || ctx.Err() != nil {
				break
			}
			step := 1
			if out, n := textEncodingAt(text, i); n > 0 {
				rewrites = append(rewrites, rewrite{pos: i, end: i + n, repl: out})
				around(i, i+n)
				step = n
			}
			next := strings.IndexAny(text[i+step:], "%&")
			if next < 0 {
				break
			}
			i += step + next
		}
	} else {
		for i := strings.IndexByte(text, '\\'); i >= 0 && i+1 < len(text); {
			if limited || ctx.Err() != nil {
				break
			}
			step := 1
			switch text[i+1] {
			case '\\':
				step = 2 // an escaped backslash is rewritten only inside a region another construct opens
			case '"', '\'', 'u', 'x':
				if _, n := unescapeAt(text, i); n > 0 {
					around(i, i+n)
					step = n
				}
			case '/':
				// `\/` inside a token (a JSON-escaped base64 or URL-safe secret), not a path separator
				if i > 0 && i+2 < len(text) && isB64Byte(text[i-1]) && isB64Byte(text[i+2]) {
					around(i, i+2)
					step = 2
				}
			}
			next := strings.IndexByte(text[i+step:], '\\')
			if next < 0 {
				break
			}
			i += step + next
		}
		for i := strings.IndexByte(text, '+'); i >= 0; {
			if limited || ctx.Err() != nil {
				break
			}
			if lo, hi, ok := concatAt(text, i); ok {
				rewrites = append(rewrites, rewrite{pos: lo, end: hi, join: true})
				around(lo, hi)
			}
			next := strings.IndexByte(text[i+1:], '+')
			if next < 0 {
				break
			}
			i += 1 + next
		}
		for i := strings.IndexAny(text, "|>"); i >= 0; {
			if limited || ctx.Err() != nil {
				break
			}
			if lo, hi, ok := blockScalarAt(text, i); ok {
				rewrites = append(rewrites, rewrite{pos: lo, end: hi, repl: " "})
				around(lo, hi)
			}
			next := strings.IndexAny(text[i+1:], "|>")
			if next < 0 {
				break
			}
			i += 1 + next
		}
		if strings.Contains(text, "**") || strings.IndexByte(text, '`') >= 0 {
			for i := strings.IndexAny(text, ":="); i >= 0; {
				if limited || ctx.Err() != nil {
					break
				}
				for _, sp := range markupAt(text, i) {
					rw := rewrite{pos: sp[0], end: sp[1]}
					// Inline value wrappers remain token boundaries; deleting
					// them must not glue a credential to following code syntax.
					if sp[0] > i && sp[1]-sp[0] == 1 && text[sp[0]] == '`' {
						rw.repl = " "
					}
					rewrites = append(rewrites, rw)
					around(sp[0], sp[1])
				}
				next := strings.IndexAny(text[i+1:], ":=")
				if next < 0 {
					break
				}
				i += 1 + next
			}
		}
	}
	return assembleView(ctx, text, rewrites, regions, byteBudget, len(regions), limited)
}

// assembleView shares source mapping and output bounds across normalization forms.
func assembleView(ctx context.Context, text string, rewrites []rewrite, regions [][2]int, byteBudget, constructs int, limited bool) (*view, bool) {
	if len(regions) == 0 {
		return nil, limited
	}
	sort.Slice(regions, func(a, b int) bool { return regions[a][0] < regions[b][0] })
	sort.Slice(rewrites, func(a, b int) bool { return rewrites[a].pos < rewrites[b].pos })

	v := &view{constructs: constructs}
	var b strings.Builder
	emit := func(s string, from, to int) bool {
		if len(s) > byteBudget-b.Len() {
			limited = true
			v.cuts = append(v.cuts, b.Len())
			return false
		}
		b.WriteString(s)
		for range len(s) {
			v.start = append(v.start, int32(from)) //nolint:gosec // texts are bounded by --max-size
			v.end = append(v.end, int32(to))       //nolint:gosec
		}
		return true
	}
	ri := 0
assemble:
	for n := 0; n < len(regions); {
		if ctx.Err() != nil {
			return nil, limited
		}
		lo, hi := regions[n][0], regions[n][1]
		for n++; n < len(regions) && regions[n][0] <= hi; n++ { // merge overlapping neighbourhoods
			if regions[n][1] > hi {
				hi = regions[n][1]
			}
		}
		if lo > 0 && text[lo-1] != '\n' {
			v.cuts = append(v.cuts, b.Len())
		}
		for i := lo; i < hi; {
			if i&4095 == 0 && ctx.Err() != nil {
				return nil, limited
			}
			for ri < len(rewrites) && rewrites[ri].pos < i {
				ri++
			}
			if ri < len(rewrites) && rewrites[ri].pos == i && rewrites[ri].end <= hi {
				rw := rewrites[ri]
				v.edits = append(v.edits, b.Len())
				if rw.join {
					v.joins = append(v.joins, b.Len())
				}
				if !emit(rw.repl, rw.pos, rw.end) {
					break assemble
				}
				i = rw.end
				continue
			}
			if text[i] == '\\' {
				if out, k := unescapeAt(text, i); k > 0 && i+k <= hi {
					v.edits = append(v.edits, b.Len())
					if !emit(out, i, i+k) {
						break assemble
					}
					i += k
					continue
				}
			}
			if !emit(text[i:i+1], i, i+1) {
				break assemble
			}
			i++
		}
		if hi < len(text) && text[hi] != '\n' {
			v.cuts = append(v.cuts, b.Len())
		}
		if !emit("\n", hi, hi) { // region separator: keeps neighbourhoods on separate lines
			break
		}
	}
	v.text = b.String()
	return v, limited
}

// anyIn reports whether the ascending list has an element in [lo, hi].
func anyIn(list []int, lo, hi int) bool {
	i := sort.SearchInts(list, lo)
	return i < len(list) && list[i] <= hi
}

// scanViews runs the rules over the rewritten view of text and maps what they find back to the
// original bytes. A match is kept only when a rewrite sits in its value or in the cue before it —
// otherwise the plain scan saw exactly the same bytes and already decided.
func (d *Detector) scanViews(ctx context.Context, text string) []Match {
	matches, _ := d.scanViewsStatus(ctx, text)
	return matches
}

func (d *Detector) scanViewsStatus(ctx context.Context, text string) ([]Match, bool) {
	v, limited := buildViewStatus(ctx, text)
	out, collectLimited := d.scanMappedView(ctx, text, v, false)
	remainingBytes, remainingConstructs := maxViewBytes, maxViewConstructs
	if v != nil {
		remainingBytes -= len(v.text)
		remainingConstructs -= v.constructs
	}
	encoded, encodedLimited := buildViewBudget(ctx, text, true, remainingBytes, remainingConstructs)
	extra, extraLimited := d.scanMappedView(ctx, text, encoded, true)
	if encoded != nil {
		remainingBytes -= len(encoded.text)
		remainingConstructs -= encoded.constructs
	}
	numeric, numericLimited := d.charCodeSecrets(ctx, text, remainingBytes, remainingConstructs)
	out = append(out, extra...)
	return append(out, numeric...), limited || collectLimited || encodedLimited || extraLimited || numericLimited
}

func (d *Detector) scanMappedView(ctx context.Context, text string, v *view, typedOnly bool) ([]Match, bool) {
	if v == nil || ctx.Err() != nil {
		return nil, false
	}
	matches, collectLimited := d.collect(ctx, v.text, "", "", d.keywordsPresent(strings.ToLower(v.text)), scanStructure(v.text, 32))
	var out []Match
	for _, m := range matches {
		if typedOnly && (taxonomy.GenericLast[m.Type] || m.Confidence < 0.9) {
			continue
		}
		if m.End <= m.Start || m.End > len(v.text) {
			continue
		}
		cue := max(0, m.Start-viewContext)
		if nl := strings.LastIndexByte(v.text[cue:m.Start], '\n'); nl >= 0 {
			cue += nl + 1
		}
		if !anyIn(v.edits, cue, m.End-1) {
			continue
		}
		// A region edge in the middle of an original line acts like a text boundary the source does
		// not have: a value touching it may be a fragment of a longer token.
		if anyIn(v.cuts, m.Start, m.Start) || anyIn(v.cuts, m.End, m.End) {
			continue
		}
		if anyIn(v.joins, cue, m.End) {
			// Joined literals are an inference about the program, not text that exists: only a
			// precise typed secret is convincing enough, and at reduced confidence.
			if taxonomy.GenericLast[m.Type] {
				continue
			}
			m.Confidence *= 0.95
		}
		if typedOnly {
			m.Confidence *= 0.95
		}
		m.Start, m.End = int(v.start[m.Start]), int(v.end[m.End-1])
		out = append(out, m)
	}
	return out, collectLimited
}
