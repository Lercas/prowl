// Package linewin runs a regex over proven literal-anchored regions instead of
// the whole text, with results identical to a whole-text run.
//
// For each regex, Analyze proves a required literal set and at least one region
// bound from the parsed syntax tree, or declines:
//
//  1. required literals or guarded delimiters — every match contains at least one;
//  2. a finite byte width, a separator budget, or a finite line-gap bound.
//
// At scan time one Aho-Corasick pass locates the literals. Finite match widths or
// non-consuming separators allow byte-bounded windows even on minified lines.
// Otherwise a window uses the literal's line plus `gaps` neighboring non-blank lines.
// Regexes that cannot be proven (no usable anchor or region bound) keep the
// whole-text path, so adopting the package never changes what is reported.
package linewin

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxGaps    = 6  // wider than this and windows stop paying for themselves
	maxLitSet  = 64 // cap on a required-literal set (and on cross products while building one)
	minLitLen  = 2  // a 1-byte literal occurs on nearly every line
	maxClassEx = 4  // enumerate a char class as literals only when it is this small
)

// Lit is one required literal. When Fold is set S is lowercase and matches case-insensitively.
type Lit struct {
	S    string
	Fold bool
}

// Plan is the proof for one regex.
type Plan struct {
	Lits     []Lit
	triggers []structuralTrigger
	// Gaps is how many neighbouring non-blank lines (each side) a match may reach from a literal's line.
	Gaps int
	// EdgeCheck is set when the regex uses \A / \z / non-multiline ^ $: those assertions also hold at a
	// window edge, so a match touching an edge is re-checked against the whole text.
	EdgeCheck bool
	// nonASCII: some literal has a byte >= 0x80, so locating it needs a Unicode-lowered haystack.
	nonASCII bool
	// foldS / foldK: a case-insensitive literal contains 's' / 'k', which also match U+017F (ſ) and
	// U+212A (K) — runes an ASCII-lowered literal search can't see.
	foldS, foldK bool
	// Byte windows use a finite match width or a bound on ASCII separator
	// bytes that can be consumed outside unbounded repetitions.
	maxBytes  int
	cuts      [128]bool
	hasCuts   bool
	cutBudget int  // finite skeleton may consume at most this many separator bytes
	lineSafe  bool // false: an unsuccessful byte proof must use the whole text
}

// Analyze returns the windowing plan for re, or nil when windowed matching can't be proven equivalent.
func Analyze(re *regexp.Regexp) *Plan {
	if re == nil {
		return nil
	}
	tree, err := syntax.Parse(re.String(), syntax.Perl)
	if err != nil {
		return nil
	}
	p := &Plan{}
	gaps, ok := gapsOf(tree, p)
	p.lineSafe = ok && gaps <= maxGaps
	if p.lineSafe {
		p.Gaps = gaps
	}
	info := litsOf(tree)
	lits := info.best()
	if len(lits) == 0 {
		p.triggers = structuralTriggers(tree)
		if len(p.triggers) == 0 {
			return nil
		}
		for _, trigger := range p.triggers {
			lits = append(lits, trigger.lit)
		}
	}
	for i := range lits {
		if lits[i].Fold {
			lits[i].S = safeFoldPiece(lits[i].S)
		}
		l := lits[i]
		if (len(l.S) < minLitLen && len(p.triggers) == 0) || strings.IndexByte(l.S, '\n') >= 0 {
			return nil // too short to filter, or spans lines (no single "line of the literal")
		}
		for j := 0; j < len(l.S); j++ {
			switch c := l.S[j]; {
			case c >= utf8.RuneSelf:
				p.nonASCII = true
			case l.Fold && c == 's':
				p.foldS = true
			case l.Fold && c == 'k':
				p.foldK = true
			}
		}
	}
	p.Lits = dedupe(lits)
	p.prepareByteWindows(tree)
	if !p.lineSafe && p.maxBytes == 0 && !p.hasCuts {
		return nil
	}
	return p
}

// safeFoldPiece returns the longest piece of a lowercase case-insensitive literal that a lowercased
// haystack is guaranteed to contain wherever the regex matches. A rune whose case-folding orbit holds
// a member that does not lowercase to it (Greek final sigma, the Cyrillic Extended-C letters) would be
// missed, so the literal is cut there; a piece of a required literal is itself required. ASCII runes
// are kept: their only such partners are U+017F and U+212A, which Prepare looks for in the text.
func safeFoldPiece(s string) string {
	best, start := "", 0
	flush := func(end int) {
		if end-start > len(best) {
			best = s[start:end]
		}
	}
	for i, r := range s {
		if r < utf8.RuneSelf || foldSafe(r) {
			continue
		}
		flush(i)
		start = i + utf8.RuneLen(r)
	}
	flush(len(s))
	return best
}

func foldSafe(r rune) bool {
	low := unicode.ToLower(r)
	for m := unicode.SimpleFold(r); m != r; m = unicode.SimpleFold(m) {
		if unicode.ToLower(m) != low || utf8.RuneLen(m) != utf8.RuneLen(low) {
			return false
		}
	}
	return utf8.RuneLen(r) == utf8.RuneLen(low)
}

// isBlankRune reports whether r is one of the bytes the window builder treats as blank.
func isBlankRune(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\f' || r == '\v'
}

// classHasNL / classAllBlank inspect a char class given as [lo, hi] rune pairs.
func classHasNL(rs []rune) bool {
	for i := 0; i+1 < len(rs); i += 2 {
		if rs[i] <= '\n' && '\n' <= rs[i+1] {
			return true
		}
	}
	return false
}

func classAllBlank(rs []rune) bool {
	for i := 0; i+1 < len(rs); i += 2 {
		if rs[i+1]-rs[i] > 8 {
			return false
		}
		for r := rs[i]; r <= rs[i+1]; r++ {
			if !isBlankRune(r) {
				return false
			}
		}
	}
	return true
}

// blankOnly reports whether re can only ever consume blank bytes (e.g. \s, [ \t\n]).
func blankOnly(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpCharClass:
		return classAllBlank(re.Rune)
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if !isBlankRune(r) {
				return false
			}
		}
		return true
	case syntax.OpCapture, syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat:
		return blankOnly(re.Sub[0])
	case syntax.OpConcat, syntax.OpAlternate:
		for _, s := range re.Sub {
			if !blankOnly(s) {
				return false
			}
		}
		return true
	case syntax.OpEmptyMatch:
		return true
	}
	return false
}

// gapsOf bounds the number of window extensions needed to cover any match of re. One extension skips
// a run of blank lines and takes the next non-blank line, so it covers either a single consumed
// newline or an entire blank-only repetition such as \s*. ok=false means no finite bound exists.
func gapsOf(re *syntax.Regexp, p *Plan) (int, bool) {
	switch re.Op {
	case syntax.OpNoMatch, syntax.OpEmptyMatch, syntax.OpAnyCharNotNL,
		syntax.OpBeginLine, syntax.OpEndLine, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return 0, true
	case syntax.OpBeginText, syntax.OpEndText:
		p.EdgeCheck = true
		return 0, true
	case syntax.OpLiteral:
		n := 0
		for _, r := range re.Rune {
			if r == '\n' {
				n++
			}
		}
		return n, true
	case syntax.OpCharClass:
		if classHasNL(re.Rune) {
			return 1, true
		}
		return 0, true
	case syntax.OpAnyChar:
		return 1, true
	case syntax.OpCapture, syntax.OpQuest:
		return gapsOf(re.Sub[0], p)
	case syntax.OpStar, syntax.OpPlus:
		g, ok := gapsOf(re.Sub[0], p)
		if !ok {
			return 0, false
		}
		if g == 0 {
			return 0, true
		}
		if blankOnly(re.Sub[0]) {
			return 1, true // the whole repetition is one blank run
		}
		return 0, false
	case syntax.OpRepeat:
		g, ok := gapsOf(re.Sub[0], p)
		if !ok {
			return 0, false
		}
		if g == 0 {
			return 0, true
		}
		if blankOnly(re.Sub[0]) {
			return 1, true
		}
		if re.Max < 0 || g*re.Max > maxGaps {
			return 0, false
		}
		return g * re.Max, true
	case syntax.OpConcat:
		sum := 0
		for _, s := range re.Sub {
			g, ok := gapsOf(s, p)
			if !ok {
				return 0, false
			}
			sum += g
		}
		return sum, true
	case syntax.OpAlternate:
		max := 0
		for _, s := range re.Sub {
			g, ok := gapsOf(s, p)
			if !ok {
				return 0, false
			}
			if g > max {
				max = g
			}
		}
		return max, true
	}
	return 0, false
}

// litInfo is the literal knowledge about a sub-expression: exact is the complete finite set of strings
// it can match (nil when not finite or too large); req is a set of which every match contains one.
type litInfo struct {
	exact []Lit
	req   []Lit
}

// usable reports whether a set works as a pre-filter: non-empty and every member long enough.
func usable(set []Lit) bool {
	if len(set) == 0 || len(set) > maxLitSet {
		return false
	}
	for _, l := range set {
		if len(l.S) < minLitLen {
			return false
		}
	}
	return true
}

func minLen(set []Lit) int {
	m := -1
	for _, l := range set {
		if m < 0 || len(l.S) < m {
			m = len(l.S)
		}
	}
	return m
}

// better prefers the set whose shortest member is longest (rarer hits), then the smaller set.
func better(a, b []Lit) []Lit {
	ua, ub := usable(a), usable(b)
	switch {
	case !ua && !ub:
		return nil
	case !ub:
		return a
	case !ua:
		return b
	}
	if la, lb := minLen(a), minLen(b); la != lb {
		if la > lb {
			return a
		}
		return b
	}
	if len(b) < len(a) {
		return b
	}
	return a
}

func (i litInfo) best() []Lit { return dedupe(better(i.req, i.exact)) }

func dedupe(set []Lit) []Lit {
	seen := make(map[Lit]bool, len(set))
	out := set[:0:0]
	for _, l := range set {
		if !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	return out
}

// cross concatenates every member of a with every member of b. A case-insensitive part makes the
// product case-insensitive (a weaker, still sound, requirement).
func cross(a, b []Lit) []Lit {
	if len(a)*len(b) > maxLitSet {
		return nil
	}
	out := make([]Lit, 0, len(a)*len(b))
	for _, x := range a {
		for _, y := range b {
			l := Lit{S: x.S + y.S, Fold: x.Fold || y.Fold}
			if l.Fold {
				l.S = strings.ToLower(l.S)
			}
			out = append(out, l)
		}
	}
	return out
}

var emptySet = []Lit{{}}

func litsOf(re *syntax.Regexp) litInfo {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return litInfo{exact: emptySet}
	case syntax.OpLiteral:
		l := Lit{S: string(re.Rune)}
		if re.Flags&syntax.FoldCase != 0 {
			l = Lit{S: strings.ToLower(l.S), Fold: true}
		}
		return litInfo{exact: []Lit{l}}
	case syntax.OpCharClass:
		n := 0
		for i := 0; i+1 < len(re.Rune); i += 2 {
			n += int(re.Rune[i+1]-re.Rune[i]) + 1
			if n > maxClassEx {
				return litInfo{}
			}
		}
		set := make([]Lit, 0, n)
		for i := 0; i+1 < len(re.Rune); i += 2 {
			for r := re.Rune[i]; r <= re.Rune[i+1]; r++ {
				set = append(set, Lit{S: string(r)})
			}
		}
		return litInfo{exact: set}
	case syntax.OpCapture:
		return litsOf(re.Sub[0])
	case syntax.OpQuest:
		sub := litsOf(re.Sub[0])
		if sub.exact == nil || len(sub.exact)+1 > maxLitSet {
			return litInfo{}
		}
		return litInfo{exact: append(append([]Lit{}, sub.exact...), Lit{})}
	case syntax.OpPlus:
		return litInfo{req: litsOf(re.Sub[0]).best()}
	case syntax.OpRepeat:
		if re.Min < 1 {
			return litInfo{}
		}
		sub := litsOf(re.Sub[0])
		if re.Min == 1 && re.Max == 1 {
			return sub
		}
		return litInfo{req: sub.best()}
	case syntax.OpConcat:
		var req []Lit
		cur := emptySet // exact set of the current run of consecutive finite parts
		allExact := true
		for _, s := range re.Sub {
			sub := litsOf(s)
			if sub.exact != nil {
				if next := cross(cur, sub.exact); next != nil {
					cur = next
					continue
				}
				// the product grew too large: close the run and start a new one at this part
				req = better(req, cur)
				cur, allExact = sub.exact, false
				continue
			}
			req = better(req, cur)
			req = better(req, sub.req)
			cur, allExact = emptySet, false
		}
		if allExact {
			return litInfo{exact: cur}
		}
		return litInfo{req: better(req, cur)}
	case syntax.OpAlternate:
		var exact, req []Lit
		exactOK, reqOK := true, true
		for _, s := range re.Sub {
			sub := litsOf(s)
			if exactOK && sub.exact != nil && len(exact)+len(sub.exact) <= maxLitSet {
				exact = append(exact, sub.exact...)
			} else {
				exactOK = false
			}
			if b := sub.best(); reqOK && len(b) > 0 && len(req)+len(b) <= maxLitSet {
				req = append(req, b...)
			} else {
				reqOK = false
			}
		}
		out := litInfo{}
		if exactOK {
			out.exact = exact
		}
		if reqOK {
			out.req = req
		}
		return out
	}
	return litInfo{}
}
