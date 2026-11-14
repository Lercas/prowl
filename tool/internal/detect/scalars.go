package detect

import (
	"context"
	"sort"
	"strings"
	"unicode/utf8"
)

// PasswordScalar is a parser-established binding within a canonical view.
// End and the map key identify exactly Value, excluding presentation quotes.
type PasswordScalar struct {
	Name, Value string
	End         int
}

// ScanWithScalars preserves parser-established values without asking a lexical
// regex to interpret embedded quotes, newlines or template-looking data.
func (d *Detector) ScanWithScalars(ctx context.Context, text string, scalars map[int]PasswordScalar) ([]Match, bool) {
	return d.scanCtxWithScalars(ctx, text, scalars)
}

func (d *Detector) scalarMatches(ctx context.Context, text string, matches []Match, scalars map[int]PasswordScalar) ([]Match, bool) {
	// A truncated lexical password must not displace the complete scalar in the
	// confidence-first overlap pass. Other types still compete on actual evidence.
	kept := matches[:0]
	for _, m := range matches {
		if m.Type == "generic_password" {
			// Loose contextual guesses cannot establish a parser binding. The
			// taxonomy-gated nomination below replaces every password candidate.
			continue
		}
		kept = append(kept, m)
	}
	starts := make([]int, 0, len(scalars))
	for start, v := range scalars {
		if v.Name != "" {
			starts = append(starts, start)
		}
	}
	sort.Ints(starts)
	for _, ct := range d.types {
		if ct.st.ID != "generic_password" {
			continue
		}
		for _, start := range starts {
			if ctx.Err() != nil {
				return kept, true
			}
			if len(kept) >= maxScanMatches {
				return kept, true
			}
			v := scalars[start]
			if start < 0 || v.End < start || v.End > len(text) || text[start:v.End] != v.Value ||
				len(v.Name) > 4096 || len(v.Value) > 4096 || utf8.RuneCountInString(v.Value) < 6 ||
				!ct.st.RE.MatchString("\""+v.Name+"\": \"Qx7vN8\"") || IsCanonicalPasswordPlaceholder(v.Value) ||
				IsEncodedPasswordHash(v.Value) || strings.HasPrefix(v.Value, "data:") {
				continue
			}
			kept = append(kept, Match{Type: ct.st.ID, Value: v.Value, Start: start, End: v.End,
				Confidence: .6, Category: ct.st.Category, Stage: "L1-regex", ContextName: v.Name})
		}
	}
	return kept, false
}
