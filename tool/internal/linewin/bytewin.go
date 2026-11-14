package linewin

import (
	"regexp/syntax"
	"unicode"
	"unicode/utf8"
)

const maxByteWindow = 8 << 10
const maxMatchBytes = (maxByteWindow - 16) / 2

func (p *Plan) prepareByteWindows(tree *syntax.Regexp) {
	p.maxBytes, _ = matchBytes(tree)
	var consumed [128]bool
	consumedASCII(tree, &consumed)
	for c, used := range consumed {
		p.cuts[c] = !used
		p.hasCuts = p.hasCuts || !used
	}
}

// matchBytes proves a finite upper bound on bytes consumed by a match. The
// bound includes every alternative and case-fold partner, not just captures.
func matchBytes(tree *syntax.Regexp) (int, bool) {
	var size int
	switch tree.Op {
	case syntax.OpNoMatch, syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return 0, true
	case syntax.OpLiteral:
		for _, r := range tree.Rune {
			if tree.Flags&syntax.FoldCase != 0 {
				size += utf8.UTFMax
			} else {
				size += utf8.RuneLen(r)
			}
		}
	case syntax.OpCharClass:
		for _, r := range tree.Rune {
			size = max(size, utf8.RuneLen(r))
		}
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		size = utf8.UTFMax
	case syntax.OpCapture, syntax.OpQuest:
		return matchBytes(tree.Sub[0])
	case syntax.OpStar, syntax.OpPlus, syntax.OpRepeat:
		child, finite := matchBytes(tree.Sub[0])
		if finite && child == 0 {
			return 0, true
		}
		if !finite || tree.Op != syntax.OpRepeat || tree.Max < 0 || child > maxMatchBytes/max(1, tree.Max) {
			return 0, false
		}
		size = child * tree.Max
	case syntax.OpConcat, syntax.OpAlternate:
		for _, sub := range tree.Sub {
			child, finite := matchBytes(sub)
			if !finite {
				return 0, false
			}
			if tree.Op == syntax.OpConcat {
				size += child
			} else {
				size = max(size, child)
			}
			if size > maxMatchBytes {
				return 0, false
			}
		}
	default:
		return 0, false
	}
	if size > maxMatchBytes {
		return 0, false
	}
	return size, true
}

// The union of consuming runes is deliberately conservative. An ASCII byte
// absent from this union cannot lie inside any match, even for greedy repeats.
func consumedASCII(tree *syntax.Regexp, used *[128]bool) {
	switch tree.Op {
	case syntax.OpLiteral:
		for _, r := range tree.Rune {
			if r < 128 {
				used[r] = true
			}
			if tree.Flags&syntax.FoldCase != 0 {
				for fold := unicode.SimpleFold(r); fold != r; fold = unicode.SimpleFold(fold) {
					if fold < 128 {
						used[fold] = true
					}
				}
			}
		}
	case syntax.OpCharClass:
		for i := 0; i+1 < len(tree.Rune); i += 2 {
			for r := max(0, tree.Rune[i]); r <= min(127, tree.Rune[i+1]); r++ {
				used[r] = true
			}
		}
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		for c := range used {
			if tree.Op == syntax.OpAnyChar || c != '\n' {
				used[c] = true
			}
		}
	}
	for _, sub := range tree.Sub {
		consumedASCII(sub, used)
	}
}

// byteWindow includes real neighboring context. Finite-width matches fit
// around their required literal; otherwise both sides must reach an actual
// non-consuming separator or the file boundary within the size budget.
// covered is a literal-start skip boundary, valid only for separator windows.
func (p *Plan) byteWindow(text string, start, end int) (lo, hi, covered int, ok bool) {
	if p.maxBytes > 0 {
		padding := p.maxBytes - (end - start) + utf8.UTFMax
		if padding < utf8.UTFMax {
			return 0, 0, 0, false
		}
		lo, hi = max(0, start-padding), min(len(text), end+padding)
		lo = runeBoundaryBefore(text, lo)
		if before := runeBoundaryBefore(text, hi); before < hi {
			_, size := utf8.DecodeRuneInString(text[before:])
			hi = before + size
		}
		return lo, hi, 0, hi-lo <= maxByteWindow
	}
	if !p.hasCuts || end-start >= maxByteWindow-2 {
		return 0, 0, 0, false
	}
	radius := (maxByteWindow-(end-start))/2 - 1
	lo = start
	for lo > 0 && start-lo < radius {
		lo--
		if c := text[lo]; c < 128 && p.cuts[c] {
			break
		}
	}
	if lo > 0 && (text[lo] >= 128 || !p.cuts[text[lo]]) {
		return 0, 0, 0, false
	}
	hi = end
	for hi < len(text) && hi-end < radius {
		c := text[hi]
		hi++
		if c < 128 && p.cuts[c] {
			return lo, hi, hi - 1, true
		}
	}
	if hi < len(text) {
		return 0, 0, 0, false
	}
	return lo, hi, hi, true
}

// A bounded look-behind distinguishes a split valid rune from invalid bytes,
// which Go regexes consume individually as RuneError. It never skips an
// unbounded run of malformed continuation bytes.
func runeBoundaryBefore(text string, pos int) int {
	for start := max(0, pos-utf8.UTFMax+1); start < pos; start++ {
		_, size := utf8.DecodeRuneInString(text[start:])
		if start+size > pos {
			return start
		}
	}
	return pos
}
