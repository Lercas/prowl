package detect

import (
	"context"
	"strings"
)

// Public application keys are audit subjects only under an explicit scan option.
// Boundaries reject overlong values whole instead of manufacturing a prefix key.
func publicKeyCandidates(ctx context.Context, text string) ([]Match, bool) {
	const prefix = "sb_publishable_"
	var out []Match
	for cursor := 0; cursor < len(text) && ctx.Err() == nil; {
		i := strings.Index(text[cursor:], prefix)
		if i < 0 {
			break
		}
		start := cursor + i
		end := start + len(prefix)
		for end < len(text) && publicKeyByte(text[end]) {
			end++
		}
		cursor = end
		if start > 0 && publicKeyByte(text[start-1]) || end-start < len(prefix)+20 || end-start > len(prefix)+128 {
			continue
		}
		if len(out) >= maxScanMatches {
			return out, true
		}
		out = append(out, Match{Type: "supabase-publishable-key", Value: text[start:end], Start: start, End: end, Confidence: 1, Category: "public", Stage: "public-audit-subject"})
	}
	return out, false
}

func publicKeyByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}
