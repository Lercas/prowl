package detect

import (
	"context"
	"sort"
	"strings"
	"unicode/utf8"
)

// PasswordScalar is a parser-established binding within a canonical view.
// End and the map key identify exactly Value, excluding presentation quotes.
// Raw preserves lexical candidates in comments and other presentation data.
type PasswordScalar struct {
	Name, Value string
	End         int
	Raw         bool
	Prose       bool // allow cues inside this value, never in its synthetic field presentation
}

// ScanWithScalars preserves parser-established values without asking a lexical
// regex to interpret embedded quotes, newlines or template-looking data.
func (d *Detector) ScanWithScalars(ctx context.Context, text string, scalars map[int]PasswordScalar) ([]Match, bool) {
	return d.scanCtxWithScalars(ctx, text, scalars)
}

func (d *Detector) scalarMatches(ctx context.Context, text string, matches []Match, scalars map[int]PasswordScalar) ([]Match, bool) {
	var rawStarts []int
	for start, v := range scalars {
		if v.Raw {
			rawStarts = append(rawStarts, start)
		}
	}
	sort.Ints(rawStarts)
	// A truncated lexical password must not displace the complete scalar in the
	// confidence-first overlap pass. Other types still compete on actual evidence.
	kept := matches[:0]
	for _, m := range matches {
		if m.Type == "generic_password" {
			i := sort.Search(len(rawStarts), func(i int) bool { return rawStarts[i] > m.Start }) - 1
			if i >= 0 && m.End <= scalars[rawStarts[i]].End {
				kept = append(kept, m)
			}
			// Loose contextual guesses cannot establish a parser binding. The
			// taxonomy-gated nomination below replaces every password candidate.
			continue
		}
		kept = append(kept, m)
	}
	starts := make([]int, 0, len(scalars))
	for start, v := range scalars {
		if (v.Name != "" || v.Prose) && !v.Raw {
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
			if v.Prose && start >= 0 && v.End >= start && v.End <= len(text) && text[start:v.End] == v.Value && len(v.Value) <= 4096 && containsFoldedPasswordCue(v.Value) {
				lb := d.lowerPool.Get().(*[]byte)
				lower := lowerScratch(lb, v.Value)
				var uniLower string
				if hasNonASCII(v.Value) {
					uniLower = strings.ToLower(v.Value)
				}
				prose := d.contextualPassword(v.Value, lower, uniLower, nil, maxScanMatches-len(kept))
				d.lowerPool.Put(lb)
				for _, m := range prose {
					m.Start, m.End = m.Start+start, m.End+start
					kept = append(kept, m)
				}
				if len(kept) >= maxScanMatches {
					return kept, true
				}
			}
			if start < 0 || v.End < start || v.End > len(text) || text[start:v.End] != v.Value ||
				len(v.Name) > 4096 || len(v.Value) > 4096 || (utf8.RuneCountInString(v.Value) < 6 && !d.shortPasswordAllowed(v.Name, v.Value)) ||
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
