package detect

import (
	"regexp"
	"regexp/syntax"
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
			for i, r := range node.Rune {
				if fold {
					for candidate := unicode.SimpleFold(r); candidate != r; candidate = unicode.SimpleFold(candidate) {
						if candidate < 128 {
							r = candidate
							break
						}
					}
				}
				if r >= 'A' && r <= 'Z' {
					r += 'a' - 'A'
				}
				node.Rune[i] = r
			}
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

var namedASCIIGates = func() []*regexp.Regexp {
	result := make([]*regexp.Regexp, len(namedBuiltins))
	for i, re := range namedBuiltins {
		result[i] = asciiRegexGate(re)
	}
	return result
}()
