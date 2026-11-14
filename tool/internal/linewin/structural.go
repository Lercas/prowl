package linewin

import "regexp/syntax"

// A structural trigger is a mandatory delimiter immediately after a long ASCII
// class run. The delimiter shares the literal index; its guard rejects ordinary
// punctuation before building a regex window. Every accepted proof guarantees
// that every match contains at least one of its guarded delimiters.
type structuralTrigger struct {
	lit   Lit
	guard runGuard
}

type runGuard struct {
	mask [128]bool
	min  int
}

func (g *runGuard) matches(text string, end int) bool {
	if end < g.min {
		return false
	}
	for i := end - 1; i >= end-g.min; i-- {
		if text[i] >= 128 || !g.mask[text[i]] {
			return false
		}
	}
	return true
}

func structuralTriggers(re *syntax.Regexp) []structuralTrigger {
	switch re.Op {
	case syntax.OpCapture, syntax.OpPlus:
		return structuralTriggers(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min > 0 {
			return structuralTriggers(re.Sub[0])
		}
	case syntax.OpAlternate:
		var out []structuralTrigger
		for _, sub := range re.Sub {
			triggers := structuralTriggers(sub)
			if len(triggers) == 0 || len(out)+len(triggers) > maxLitSet {
				return nil
			}
			out = append(out, triggers...)
		}
		return out
	case syntax.OpConcat:
		for i, sub := range re.Sub {
			if i > 0 {
				guard, ok := suffixRun(re.Sub[i-1])
				if delimiter, found := prefixDelimiter(sub); ok && found {
					return []structuralTrigger{{lit: Lit{S: string(delimiter)}, guard: guard}}
				}
			}
			if triggers := structuralTriggers(sub); len(triggers) > 0 {
				return triggers
			}
		}
	}
	return nil
}

func suffixRun(re *syntax.Regexp) (runGuard, bool) {
	for re.Op == syntax.OpCapture || re.Op == syntax.OpConcat {
		re = re.Sub[len(re.Sub)-1]
	}
	if re.Op != syntax.OpRepeat || re.Min < 8 {
		return runGuard{}, false
	}
	count := min(re.Min, 64) // a weaker bounded suffix remains mandatory
	re = re.Sub[0]
	for re.Op == syntax.OpCapture {
		re = re.Sub[0]
	}
	if re.Op != syntax.OpCharClass {
		return runGuard{}, false
	}
	g := runGuard{min: count}
	for i := 0; i+1 < len(re.Rune); i += 2 {
		if re.Rune[i] < 0 || re.Rune[i+1] >= 128 {
			return runGuard{}, false
		}
		for r := re.Rune[i]; r <= re.Rune[i+1]; r++ {
			g.mask[r] = true
		}
	}
	return g, true
}

func prefixDelimiter(re *syntax.Regexp) (byte, bool) {
	for re.Op == syntax.OpCapture || re.Op == syntax.OpConcat {
		re = re.Sub[0]
	}
	if re.Op == syntax.OpLiteral && len(re.Rune) > 0 {
		switch r := re.Rune[0]; r {
		case ':', '.', '-', '@', '/', '=':
			return byte(r), true
		}
	}
	return 0, false
}
