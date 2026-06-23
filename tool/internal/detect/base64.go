package detect

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

// unmaskBase64 finds structured secrets hidden inside base64 blobs, reusing the high-entropy
// candidates from collect(). Findings report the outer blob position; generic hits inside are dropped.
func (d *Detector) unmaskBase64(ctx context.Context, candidates []Match) []Match {
	var out []Match
	for _, c := range candidates {
		if len(c.Value) < 40 || len(c.Value) > 8192 {
			continue
		}
		dec, ok := tryB64Decode(c.Value)
		if !ok || !printableText(dec) {
			continue
		}
		decoded := string(dec)
		for _, m := range d.collect(ctx, decoded, d.keywordsPresent(strings.ToLower(decoded)), scanStructure(decoded, 32)) {
			if taxonomy.GenericLast[m.Type] {
				continue
			}
			out = append(out, Match{
				Type: m.Type, Value: m.Value, Start: c.Start, End: c.End,
				Confidence: m.Confidence * 0.95, ChecksumValid: m.ChecksumValid,
				Category: m.Category, Stage: "L1-base64",
			})
		}
	}
	return out
}

// tryB64Decode handles padded/unpadded std and url alphabets (the entropy regex strips '=' padding).
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
