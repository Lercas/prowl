package detect

import (
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
	"unicode"
)

// asciiRegexGate recognizes a superset of the original language after ASCII
// lowercasing. It only rejects impossible matches; extraction always uses the
// original regexp, preserving captures, priorities and Longest mode.
func asciiRegexGate(original *regexp.Regexp) *regexp.Regexp {
	if original == nil || len(original.String()) > 16384 || !strings.Contains(original.String(), "(?i") {
		return nil
	}
	tree, err := syntax.Parse(original.String(), syntax.Perl)
	if err != nil {
		return nil
	}
	var project func(*syntax.Regexp) *syntax.Regexp
	project = func(node *syntax.Regexp) *syntax.Regexp {
		fold := node.Flags&syntax.FoldCase != 0
		for i, child := range node.Sub {
			node.Sub[i] = project(child)
		}
		if node.Op == syntax.OpCapture {
			return node.Sub[0]
		}
		node.Flags &^= syntax.FoldCase
		switch node.Op {
		case syntax.OpLiteral:
			var pieces []*syntax.Regexp
			for _, r := range node.Rune {
				runes := []rune{asciiLowerRune(r)}
				if fold {
					for candidate := unicode.SimpleFold(r); candidate != r; candidate = unicode.SimpleFold(candidate) {
						runes = append(runes, asciiLowerRune(candidate))
					}
				}
				sort.Slice(runes, func(i, j int) bool { return runes[i] < runes[j] })
				var ranges []rune
				for i, r := range runes {
					if i == 0 || r != runes[i-1] {
						ranges = append(ranges, r, r)
					}
				}
				pieces = append(pieces, &syntax.Regexp{Op: syntax.OpCharClass, Rune: ranges})
			}
			return &syntax.Regexp{Op: syntax.OpConcat, Sub: pieces}
		case syntax.OpCharClass:
			contains := func(r rune) bool {
				for i := 0; i < len(node.Rune); i += 2 {
					if node.Rune[i] <= r && r <= node.Rune[i+1] {
						return true
					}
				}
				return false
			}
			var accepted [128]bool
			for r := rune(0); r < 128; r++ {
				ok := contains(r)
				if fold {
					for next := unicode.SimpleFold(r); !ok && next != r; next = unicode.SimpleFold(next) {
						ok = contains(next)
					}
				}
				if ok {
					lower := r
					if lower >= 'A' && lower <= 'Z' {
						lower += 'a' - 'A'
					}
					accepted[lower] = true
				}
			}
			originalRanges := node.Rune
			node.Rune = nil
			for r := rune(0); r < 128; r++ {
				if accepted[r] {
					end := r
					for end+1 < 128 && accepted[end+1] {
						end++
					}
					node.Rune = append(node.Rune, r, end)
					r = end
				}
			}
			// The parser expands folded character classes before returning them.
			// ASCII lowering leaves every non-ASCII rune unchanged, including
			// long s, Kelvin sign, Unicode classes and invalid UTF-8 replacements.
			for i := 0; i < len(originalRanges); i += 2 {
				if originalRanges[i+1] >= 128 {
					node.Rune = append(node.Rune, max(128, originalRanges[i]), originalRanges[i+1])
				}
			}
			// syntax's printer expects adjacent intervals to be merged, notably
			// when the ASCII interval ending at 127 meets a Unicode interval.
			merged := node.Rune[:0]
			for i := 0; i < len(node.Rune); i += 2 {
				if len(merged) > 0 && node.Rune[i] <= merged[len(merged)-1]+1 {
					merged[len(merged)-1] = max(merged[len(merged)-1], node.Rune[i+1])
				} else {
					merged = append(merged, node.Rune[i], node.Rune[i+1])
				}
			}
			node.Rune = merged
			if len(node.Rune) == 0 {
				node.Op = syntax.OpNoMatch
			}
		}
		return node
	}
	gate, err := regexp.Compile(project(tree).String())
	if err != nil {
		return nil
	}
	return gate
}

func asciiLowerRune(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + 'a' - 'A'
	}
	return r
}

var namedASCIIGates = func() []*regexp.Regexp {
	result := make([]*regexp.Regexp, len(namedBuiltins))
	for i, re := range namedBuiltins {
		result[i] = asciiRegexGate(re)
	}
	return result
}()
