package saferegex

import (
	"strings"
	"testing"
)

// TestCompileNormal: real provider-shaped regexes (well under the limits) compile and match.
func TestCompileNormal(t *testing.T) {
	cases := []struct {
		pat, in string
	}{
		{`AKIA[0-9A-Z]{16}`, "AKIAIOSFODNN7EXAMPLE"},
		{`ghp_[0-9A-Za-z]{36}`, "ghp_16C7e42F292c6912E7710c838347Ae178B4a"},
		{`-----BEGIN [A-Z ]+PRIVATE KEY-----`, "-----BEGIN RSA PRIVATE KEY-----"},
	}
	for _, c := range cases {
		re, err := Compile(c.pat)
		if err != nil {
			t.Fatalf("Compile(%q) unexpected error: %v", c.pat, err)
		}
		if !re.MatchString(c.in) {
			t.Errorf("Compile(%q) did not match %q", c.pat, c.in)
		}
	}
}

// TestCompileRejectsHugeBound: a single absurd repetition bound is refused fast (no OOM).
func TestCompileRejectsHugeBound(t *testing.T) {
	if _, err := Compile(`a{1000000000}`); err == nil {
		t.Fatal("expected error for a{1000000000}, got nil")
	}
}

// TestCompileRejectsOverLen: a pattern past MaxRegexLen is refused without compiling.
func TestCompileRejectsOverLen(t *testing.T) {
	big := strings.Repeat("a", MaxRegexLen+1)
	if _, err := Compile(big); err == nil {
		t.Fatalf("expected error for a %d-byte regex, got nil", len(big))
	}
}

// TestCompileRejectsPackedBounds: many individually-legal bounds whose SUM exceeds the total cap
// are refused (the 50 KB-alternation-style packed-bomb vector).
func TestCompileRejectsPackedBounds(t *testing.T) {
	// 20 groups of a{1000} = total 20000 > MaxRepetitionTotal (10000); each bound (1000) is itself
	// at the single-bound limit, so only the total cap rejects this.
	pat := strings.Repeat("a{1000}", 20)
	if _, err := Compile(pat); err == nil {
		t.Fatal("expected error for packed a{1000}x20, got nil")
	}
}

// TestCompileAtBoundaryStillCompiles: a single a{1000} (== MaxRepetition, the largest shipped bound)
// is accepted, proving the guard doesn't over-correct on real rules.
func TestCompileAtBoundaryStillCompiles(t *testing.T) {
	if _, err := Compile(`a{1000}`); err != nil {
		t.Fatalf("a{1000} should compile (== MaxRepetition), got %v", err)
	}
}

// TestEscapedBraceIsLiteral: a \{ is a literal brace, not a quantifier, and must not be scanned as a
// repetition bound.
func TestEscapedBraceIsLiteral(t *testing.T) {
	if _, err := Compile(`a\{1000000000\}`); err != nil {
		t.Fatalf(`a\{...\} should compile (literal braces), got %v`, err)
	}
}
