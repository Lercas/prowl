package detect

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

const maxBase64Blob = 8192
const maxBase64Work = 8 << 20
const maxBase64Depth = 4

type Base64Span struct{ Start, End int }

// A decoded byte belongs to a complete four-character encoding quantum. Compose these intervals
// through the bounded parent chain; no coordinate ever refers to an invented decoded document.
type base64Frame struct {
	parent     *base64Frame
	start, end int
}

func (f *base64Frame) sourceSpan(start, end int) (int, int) {
	if f == nil {
		return start, end
	}
	left := f.start + start/3*4
	right := min(f.end, f.start+(end+2)/3*4)
	return f.parent.sourceSpan(left, right)
}

// unmaskBase64 scans maximal encoded runs independently of generic entropy findings. A decoded
// value must still pass a typed detector; arbitrary prose does not become a generic secret.
// All layers share one byte/output budget and a fixed depth; decoded data never creates generics.
func (d *Detector) unmaskBase64(ctx context.Context, text string) ([]Match, bool) {
	var out []Match
	work, limited := 0, false
	candidates := 0
	exhausted := false
	var walk func(string, *base64Frame, int, []Base64Span)
	walk = func(text string, parent *base64Frame, depth int, chain []Base64Span) {
		for i := 0; i < len(text); {
			if ctx.Err() != nil || exhausted {
				return
			}
			if !base64Byte(text[i]) {
				i++
				continue
			}
			start := i
			for i < len(text) && base64Byte(text[i]) {
				i++
				if i&4095 == 0 && ctx.Err() != nil {
					return
				}
			}
			for i < len(text) && text[i] == '=' {
				i++
			}
			end := i
			if end-start < minBase64CandidateBytes {
				continue
			}
			if end-start > maxBase64Blob {
				limited = true
				continue
			}
			if depth == 0 && (IsKnownNonSecretBlob(text, start) || strings.EqualFold(BindingName(text, start), "blob")) {
				continue
			}
			if work+end-start > maxBase64Work || len(out) >= maxScanMatches {
				limited, exhausted = true, true
				return
			}
			work += end - start
			dec, ok := tryB64Decode(text[start:end])
			if !ok || !printableText(dec) {
				continue
			}
			if candidates >= maxScanMatches {
				limited, exhausted = true, true
				return
			}
			candidates++
			if depth >= maxBase64Depth {
				limited = true
				continue
			}
			decoded := string(dec)
			left, right := parent.sourceSpan(start, end)
			proof := append(append([]Base64Span(nil), chain...), Base64Span{left, right})
			frame := &base64Frame{parent: parent, start: start, end: end}
			matches, capped := d.collect(ctx, decoded, d.keywordsPresent(strings.ToLower(decoded)), scanStructure(decoded, 32))
			limited = limited || capped
			for _, m := range matches {
				if taxonomy.GenericLast[m.Type] {
					continue
				}
				if len(out) >= maxScanMatches {
					limited, exhausted = true, true
					return
				}
				stage := "L1-base64"
				if m.ChecksumValid {
					stage += "-checksum"
				}
				left, right := frame.sourceSpan(m.Start, m.End)
				out = append(out, Match{
					Type: m.Type, Value: m.Value, Start: left, End: right,
					Confidence: m.Confidence * 0.95, ChecksumValid: m.ChecksumValid,
					Category: m.Category, Stage: stage, DecodedText: decoded, DecodedStart: m.Start, DecodeSpans: proof,
				})
			}
			walk(decoded, frame, depth+1, proof)

		}
	}
	walk(text, nil, 0, nil)
	return out, limited
}

const (
	minBase64CandidateBytes = 16
	maxBase64CandidateBytes = 8192
)

// unmaskBase64 finds structured secrets hidden inside base64 blobs. Findings report the outer blob
// position; generic hits inside are dropped.
func (d *Detector) unmaskBase64Candidates(ctx context.Context, candidates []Match) ([]Match, bool) {
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
		matches, limited := d.collect(ctx, decoded, d.keywordsPresent(strings.ToLower(decoded)), scanStructure(decoded, 32))
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

func base64Byte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
		c == '+' || c == '/' || c == '-' || c == '_'
}

// tryB64Decode handles padded/unpadded standard and URL alphabets, rejecting noncanonical pad bits.
func tryB64Decode(s string) ([]byte, bool) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if dec, err := enc.Strict().DecodeString(s); err == nil {
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
