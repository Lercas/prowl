// Package saferegex compiles attacker-controlled regex sources with guards against regex-bombs:
// oversized patterns and absurdly-bounded repetitions ({n}/{n,m}) that would otherwise burn
// multiple GB of RAM / seconds of CPU inside the stdlib compiler.
//
// It is a leaf package with NO internal/ imports, so every untrusted-content loader (rules,
// taxonomy, config) can import it without an import cycle.
package saferegex

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Limits guarding compilation of untrusted (attacker-supplied) regex sources. A giant pattern or one
// with an absurd bounded-repetition count can otherwise burn CPU/RAM during regexp compilation.
const (
	// MaxRegexLen is the per-regex source byte cap. The largest real provider regex (AWS/GitHub/etc.)
	// is well under 4 KB, so this never rejects a legitimate detector.
	MaxRegexLen = 4 * 1024
	// MaxRepetition caps a single {n}/{n,m} bound. Go's regexp already rejects any bound above 1000,
	// so this matches Go's real limit. The largest bound in the shipped rule set is exactly 1000,
	// which still compiles (the check is strictly greater).
	MaxRepetition = 1000
	// MaxRepetitionTotal caps the SUM of all bounded-repetition counts in one regex. A 4KB regex can
	// pack hundreds of sub-1000 groups (e.g. ~585 x a{1000}); each bounded group costs ~tens of ms to
	// compile, so the aggregate must be bounded too. The largest sum in any shipped regex is 1000, so
	// 10000 leaves ample headroom for real rules while rejecting a packed adversarial pattern.
	MaxRepetitionTotal = 10000
)

// Compile rejects oversized or absurdly-bounded regex sources (which could blow up compile-time
// CPU/RAM) before handing the pattern to the stdlib compiler. It bounds both the largest single
// repetition count AND the aggregate cost (sum of all bounds), since a 4KB regex can pack hundreds
// of individually-legal bounded groups whose combined compile time is still large.
func Compile(pattern string) (*regexp.Regexp, error) {
	if len(pattern) > MaxRegexLen {
		return nil, fmt.Errorf("regex too long (%d bytes > %d limit)", len(pattern), MaxRegexLen)
	}
	maxBound, totalBound := repetitionBounds(pattern)
	if maxBound > MaxRepetition {
		return nil, fmt.Errorf("repetition bound %d exceeds %d limit", maxBound, MaxRepetition)
	}
	if totalBound > MaxRepetitionTotal {
		return nil, fmt.Errorf("total repetition cost %d exceeds %d limit", totalBound, MaxRepetitionTotal)
	}
	return regexp.Compile(pattern)
}

// repetitionBounds scans an (unescaped) regex source and returns the largest single {n}/{n,m}
// repetition count and the SUM of the per-group bounds, so both an absurd single bound (a{99999999})
// and a pile of bounded groups (many a{1000}) can be rejected before compilation. Per group the
// larger of n/m is used (it drives compile cost). A \{ is a literal brace and ignored.
func repetitionBounds(rx string) (maxBound, totalBound int) {
	for i := 0; i < len(rx); i++ {
		switch rx[i] {
		case '\\': // skip the escaped char (so \{ is literal, not a quantifier)
			i++
		case '{':
			j := i + 1
			for j < len(rx) && rx[j] != '}' {
				j++
			}
			if j >= len(rx) {
				return maxBound, totalBound // unterminated brace: let the compiler decide
			}
			groupMax := 0
			for _, num := range strings.Split(rx[i+1:j], ",") {
				num = strings.TrimSpace(num)
				if num == "" {
					continue
				}
				if v, err := strconv.Atoi(num); err == nil && v > groupMax {
					groupMax = v
				}
			}
			if groupMax > maxBound {
				maxBound = groupMax
			}
			totalBound += groupMax
			i = j
		}
	}
	return maxBound, totalBound
}
