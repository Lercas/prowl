package detect

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

const (
	minBase64CandidateBytes = 16
	maxBase64CandidateBytes = 8192
)

// unmaskBase64 finds structured secrets hidden inside base64 blobs. Findings report the outer blob
// position; generic hits inside are dropped.
func (d *Detector) unmaskBase64(ctx context.Context, candidates []Match) ([]Match, bool) {
	var out []Match
	capped := false
	for _, c := range candidates {
		if ctx.Err() != nil {
			break
		}
		if len(c.Value) < minBase64CandidateBytes || len(c.Value) > maxBase64CandidateBytes {
			continue
		}
		dec, ok := tryB64Decode(c.Value)
		if !ok || !printableText(dec) {
			continue
		}
		decoded := string(dec)
		matches, limited := d.collect(ctx, decoded, "", "", d.keywordsPresent(strings.ToLower(decoded)), scanStructure(decoded, 32))
		capped = capped || limited
		// All decoded findings use the same outer span, so only its highest-confidence
		// typed match can survive the final overlap pass. Choose that winner here instead
		// of retaining candidates * decoded matches entries until the global sort.
		var best Match
		found := false
		for _, m := range matches {
			if taxonomy.GenericLast[m.Type] {
				continue
			}
			if !found || m.Confidence > best.Confidence {
				best, found = m, true
			}
		}
		if found {
			best.Start, best.End = c.Start, c.End
			best.Confidence *= 0.95
			best.Stage = "L1-base64"
			out = append(out, best)
		}
	}
	return out, capped
}

// base64Candidates retains whole standard/URL blobs for typed decoding only. Keep the entropy net's
// context and non-secret filters, without changing its existing generic finding spans. Short encoded
// access keys must be eligible even when no generic rule collects their outer value.
func base64Candidates(ctx context.Context, text string, runs [][2]int) ([]Match, bool) {
	var candidates []Match
	for _, r := range runs {
		if ctx.Err() != nil {
			break
		}
		val := text[r[0]:r[1]]
		if len(val) < minBase64CandidateBytes || len(val) > maxBase64CandidateBytes || !HasSecretNameContext(text, r[0]) ||
			IsKnownNonSecretBlob(text, r[0]) || IsExampleOrPlaceholder(val) ||
			ShannonEntropy(val) < genericEntropyMin || IsHashNotSecret(text, r[0], val) ||
			looksLikeCodePath(val) || (reRecaptchaSiteKey.MatchString(val) && hasRecaptchaCue(text, r[0])) {
			continue
		}
		// Opaque entropy noise must not consume the independent decode-candidate budget. Only
		// canonical, printable blobs can contain the typed text rules inspected by unmaskBase64.
		decoded, ok := tryB64Decode(val)
		if !ok || !printableText(decoded) {
			continue
		}
		if len(candidates) >= maxScanMatches {
			return candidates, true
		}
		candidates = append(candidates, Match{Value: val, Start: r[0], End: r[1]})
	}
	return candidates, false
}

// tryB64Decode handles padded/unpadded std and url alphabets (candidate spans strip '=' padding).
func tryB64Decode(s string) ([]byte, bool) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if dec, err := enc.DecodeString(s); err == nil {
			return dec, true
		}
	}
	return nil, false
}

func printableText(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c == 0 {
			return false
		}
		if c >= 0x20 && c < 0x7f || c == '\n' || c == '\r' || c == '\t' {
			printable++
		}
	}
	return float64(printable)/float64(len(b)) > 0.85
}
