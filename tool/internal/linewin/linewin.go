package linewin

import (
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
	"unsafe"

	"github.com/Lercas/prowl/tool/internal/ahocorasick"
)

// owner ties one Aho-Corasick pattern to a regex that requires it.
type owner struct {
	guard    *runGuard
	re       int32
	exact    string // non-empty: the occurrence must equal this byte-for-byte (case-sensitive literal)
	nonASCII bool   // only the Unicode-lowered pass can find every occurrence
}

// Set is the compiled windowing index for a list of regexes. Read-only and goroutine-safe after New.
type Set struct {
	plans    []*Plan
	ac       *ahocorasick.Matcher
	patLen   []int
	owners   [][]owner
	nonASCII bool // some plan needs the Unicode-lowered haystack
	pool     sync.Pool
}

// New analyses every regex (nil entries allowed) and builds one literal index over all provable ones.
func New(res []*regexp.Regexp) *Set {
	s := &Set{plans: make([]*Plan, len(res))}
	ids := map[string]int{}
	var pats []string
	for i, re := range res {
		p := Analyze(re)
		if p == nil {
			continue
		}
		s.plans[i] = p
		s.nonASCII = s.nonASCII || p.nonASCII
		for _, l := range p.Lits {
			pat := strings.ToLower(l.S)
			id, ok := ids[pat]
			if !ok {
				id = len(pats)
				ids[pat] = id
				pats = append(pats, pat)
				s.patLen = append(s.patLen, len(pat))
				s.owners = append(s.owners, nil)
			}
			o := owner{re: int32(i), nonASCII: !isASCII(l.S)} //nolint:gosec // regex lists are far below MaxInt32
			if !l.Fold {
				o.exact = l.S
			}
			if len(p.triggers) == 0 {
				s.owners[id] = append(s.owners[id], o)
			} else {
				for j := range p.triggers {
					if p.triggers[j].lit == l {
						o.guard = &p.triggers[j].guard
						s.owners[id] = append(s.owners[id], o)
					}
				}
			}
		}
	}
	if len(pats) > 0 {
		s.ac = ahocorasick.New(pats)
	}
	s.pool = sync.Pool{New: func() any { return &Windows{} }}
	return s
}

// Len is the number of regexes the set was built from.
func (s *Set) Len() int { return len(s.plans) }

// Plan returns the proof for regex i, or nil when it always runs on the whole text.
func (s *Set) Plan(i int) *Plan { return s.plans[i] }

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// Windows holds, for one text, the regions each regex has to look at. A nil *Windows means
// "whole text for everything", so callers can use it unconditionally.
type Windows struct {
	set   *Set
	text  string
	wins  [][][2]int // per regex: sorted, disjoint [start,end) regions
	state []winState
	lower []byte
}

type winState struct {
	coveredUntil int // literal starts before this offset are covered by a complete line/separator region
	coveredFrom  int
	byteWork     int  // bounds aggregate separator searches before reverting to a whole-text regex
	full         bool // regions unusable for this regex — run on the whole text
	wanted       bool
	byteEdges    bool // artificial byte boundaries require checking every touching match
}

// Prepare locates the required literals of the wanted regexes in text and builds their regions.
// asciiLower is text with A-Z lowered (same length); pass "" to have it computed. uniLower is
// strings.ToLower(text) when the caller already has it, else "". want selects which regexes will be
// run for this text (nil = all). Release the result when done.
func (s *Set) Prepare(text, asciiLower, uniLower string, want []bool) *Windows {
	if s == nil || s.ac == nil || len(text) == 0 {
		return nil
	}
	nonASCII := !isASCII(text)
	// U+017F (long s) and U+212A (Kelvin sign) case-fold to the ASCII letters s and k: a case-insensitive
	// regex matches them where an ASCII-lowered literal search would not look, so a regex with such a
	// literal takes the whole text.
	longS := nonASCII && strings.Contains(text, "\u017f")
	kelvin := nonASCII && strings.Contains(text, "\u212a")
	w := s.pool.Get().(*Windows)
	w.set, w.text = s, text
	if cap(w.wins) < len(s.plans) {
		w.wins = make([][][2]int, len(s.plans))
		w.state = make([]winState, len(s.plans))
	}
	w.wins, w.state = w.wins[:len(s.plans)], w.state[:len(s.plans)]
	anyWanted := false
	for i := range w.state {
		w.wins[i] = w.wins[i][:0]
		p := s.plans[i]
		wanted := p != nil && (want == nil || want[i])
		full := !wanted || (longS && p.foldS) || (kelvin && p.foldK)
		w.state[i] = winState{wanted: wanted, full: full}
		anyWanted = anyWanted || !full
	}
	if !anyWanted {
		w.Release()
		return nil
	}
	if asciiLower == "" {
		asciiLower = w.lowerASCII(text)
	}
	w.locate(asciiLower, false)
	if nonASCII && s.nonASCII {
		// Offsets in strings.ToLower(text) are only meaningful when lowering keeps every rune's length.
		if lowerAligned(text) {
			if uniLower == "" {
				uniLower = strings.ToLower(text)
			}
			w.locate(uniLower, true)
		} else {
			w.dropNonASCII()
		}
	}
	// The second pass appends out of order; restore the sorted, disjoint invariant.
	for i := range w.wins {
		if st := &w.state[i]; st.wanted && !st.full {
			w.wins[i] = normalize(w.wins[i])
			total := 0
			for _, r := range w.wins[i] {
				total += r[1] - r[0]
			}
			if total > len(text)/2 {
				st.full = true // regions cover most of the text: one whole-text pass is cheaper
			}
		}
	}
	return w
}

// lowerAligned reports whether strings.ToLower(text) keeps every byte offset: no invalid UTF-8 (which
// lowering replaces with a 3-byte U+FFFD) and no rune whose lowercase form has a different length.
func lowerAligned(text string) bool {
	for i := 0; i < len(text); {
		if text[i] < utf8.RuneSelf {
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(text[i:])
		if r == utf8.RuneError && size == 1 {
			return false
		}
		if utf8.RuneLen(unicode.ToLower(r)) != size {
			return false
		}
		i += size
	}
	return true
}

// Release returns w to its pool. w must not be used afterwards; safe on nil.
func (w *Windows) Release() {
	if w == nil {
		return
	}
	w.text = ""
	w.set.pool.Put(w)
}

func (w *Windows) lowerASCII(src string) string {
	if cap(w.lower) < len(src) {
		w.lower = make([]byte, len(src))
	}
	dst := w.lower[:len(src)]
	for i := 0; i < len(src); i++ {
		c := src[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		dst[i] = c
	}
	return unsafe.String(&dst[0], len(dst))
}

// dropNonASCII sends every regex with a non-ASCII literal to the whole-text path.
func (w *Windows) dropNonASCII() {
	for i, p := range w.set.plans {
		if p != nil && p.nonASCII {
			w.state[i].full = true
		}
	}
}

// locate runs the literal automaton over a lowered haystack. unicodePass marks the second pass over
// strings.ToLower(text), which finds non-ASCII literals whatever their case in the text.
func (w *Windows) locate(hay string, unicodePass bool) {
	s, text := w.set, w.text
	next, out := s.ac.Transitions(), s.ac.Outputs()
	var cur int32
	for i := 0; i < len(hay); i++ {
		cur = next[cur<<8|int32(hay[i])]
		for _, id := range out[cur] {
			end := i + 1
			start := end - s.patLen[id]
			for _, o := range s.owners[id] {
				st := &w.state[o.re]
				if st.full {
					continue
				}
				if unicodePass && !o.nonASCII {
					continue // ASCII literals were all found by the first pass
				}
				if o.exact != "" && text[start:end] != o.exact {
					continue
				}
				if !unicodePass && start >= st.coveredFrom && start < st.coveredUntil {
					continue // complete line or separator-delimited segment already covered
				}
				if o.guard != nil && !o.guard.matches(text, start) {
					continue
				}
				w.add(int(o.re), start, end, unicodePass)
			}
		}
	}
}

// add records the region for a literal occurrence at [start,end).
func (w *Windows) add(re, start, end int, unordered bool) {
	text := w.text
	plan := w.set.plans[re]
	st := &w.state[re]
	region, bounded := plan.byteWindow(text, start, end)
	st.byteWork += region.work
	if st.byteWork > 2*len(text) || (!bounded && !plan.lineSafe) {
		st.full = true
		return
	}
	ws, we := region.lo, region.hi
	if bounded {
		st.byteEdges = true
		if !unordered {
			st.coveredFrom, st.coveredUntil = region.coveredFrom, region.coveredUntil
		}
	} else {
		ws, we = lineStart(text, start), lineEnd(text, end)
		if !unordered {
			st.coveredFrom = ws
			st.coveredUntil = we
		}
		for g := 0; g < plan.Gaps; g++ {
			ws = prevLine(text, ws)
			we = nextLine(text, we)
		}
	}
	wins := w.wins[re]
	if n := len(wins); n > 0 && !unordered && ws <= wins[n-1][1]+1 {
		wins[n-1][0] = min(wins[n-1][0], ws)
		if we > wins[n-1][1] {
			wins[n-1][1] = we
		}
		return
	}
	w.wins[re] = append(wins, [2]int{ws, we})
}

// normalize sorts regions and merges overlapping or adjacent ones.
func normalize(wins [][2]int) [][2]int {
	sorted := true
	for i := 1; i < len(wins); i++ {
		if wins[i][0] <= wins[i-1][1]+1 {
			sorted = false
			break
		}
	}
	if sorted {
		return wins
	}
	sort.Slice(wins, func(i, j int) bool { return wins[i][0] < wins[j][0] })
	out := wins[:1]
	for _, r := range wins[1:] {
		last := &out[len(out)-1]
		if r[0] <= last[1]+1 {
			if r[1] > last[1] {
				last[1] = r[1]
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

func isBlank(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}

// lineStart is the offset just after the last '\n' before pos (0 if none).
func lineStart(text string, pos int) int {
	return strings.LastIndexByte(text[:pos], '\n') + 1
}

// lineEnd is the offset of the first '\n' at or after pos (len(text) if none).
func lineEnd(text string, pos int) int {
	if i := strings.IndexByte(text[pos:], '\n'); i >= 0 {
		return pos + i
	}
	return len(text)
}

// prevLine extends a region start (a line start) back over any blank lines to the start of the
// nearest non-blank line above.
func prevLine(text string, ws int) int {
	p := ws - 1
	for p >= 0 && isBlank(text[p]) {
		p--
	}
	if p < 0 {
		return 0
	}
	return lineStart(text, p)
}

// nextLine extends a region end (a '\n' offset or len) forward over any blank lines to the end of
// the nearest non-blank line below.
func nextLine(text string, we int) int {
	p := we
	for p < len(text) && isBlank(text[p]) {
		p++
	}
	if p == len(text) {
		return p
	}
	return lineEnd(text, p)
}

// FindAll is re.FindAllStringSubmatchIndex(text, n) for regex i of the set, evaluated only over the
// regions prepared for it. Offsets are relative to the whole text.
func (w *Windows) FindAll(i int, re *regexp.Regexp, text string, n int) [][]int {
	if w == nil || w.state[i].full {
		return re.FindAllStringSubmatchIndex(text, n)
	}
	edge := w.set.plans[i].EdgeCheck || w.state[i].byteEdges
	var out [][]int
	for _, r := range w.wins[i] {
		want := -1
		if n >= 0 {
			if want = n - len(out); want <= 0 {
				break
			}
		}
		for _, m := range re.FindAllStringSubmatchIndex(text[r[0]:r[1]], want) {
			if edge && ((m[0] == 0 && r[0] > 0) || (m[1] == r[1]-r[0] && r[1] < len(text))) {
				// \A/\z also hold at a region edge; a match touching one may not exist in the whole text
				return re.FindAllStringSubmatchIndex(text, n)
			}
			for k := range m {
				if m[k] >= 0 {
					m[k] += r[0]
				}
			}
			out = append(out, m)
		}
	}
	return out
}

// Match is re.MatchString(text) for regex i of the set, evaluated only over its prepared regions.
func (w *Windows) Match(i int, re *regexp.Regexp, text string) bool {
	if w == nil || w.state[i].full {
		return re.MatchString(text)
	}
	edge := w.set.plans[i].EdgeCheck || w.state[i].byteEdges
	for _, r := range w.wins[i] {
		m := re.FindStringIndex(text[r[0]:r[1]])
		if m == nil {
			continue
		}
		if edge && ((m[0] == 0 && r[0] > 0) || (m[1] == r[1]-r[0] && r[1] < len(text))) {
			return re.MatchString(text)
		}
		return true
	}
	return false
}
