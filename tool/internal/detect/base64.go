package detect

import (
	"context"
	"encoding/base64"
)

const (
	minBase64CandidateBytes = 16
	maxBase64CandidateBytes = 8192
	// Each non-linear sweep retains only bounded decoded contexts for
	// verification. Repeated compressed blobs must not multiply retained RAM.
	maxNonLinearContextBytes = 32 << 20
)

// unmaskBase64 finds structured secrets hidden inside encoded blobs: base64 or hex, optionally
// compressed, optionally nested (see decodeBlob / bestDecoded). Findings report the outer blob
// position; generic hits inside are dropped.
func (d *Detector) unmaskBase64(ctx context.Context, candidates []Match) ([]Match, bool) {
	return d.unmaskBlobs(ctx, candidates, false, false)
}

func (d *Detector) unmaskNonLinear(ctx context.Context, candidates []Match) ([]Match, bool) {
	return d.unmaskNonLinearContext(ctx, candidates, false)
}

func (d *Detector) unmaskNonLinearContext(ctx context.Context, candidates []Match, capture bool) ([]Match, bool) {
	return d.unmaskBlobs(ctx, candidates, true, capture)
}

func (d *Detector) unmaskBlobs(ctx context.Context, candidates []Match, nonLinearOnly, capture bool) ([]Match, bool) {
	var out []Match
	capped := false
	contextBytes := 0
	for _, c := range candidates {
		if ctx.Err() != nil {
			break
		}
		if len(c.Value) < minBase64CandidateBytes || len(c.Value) > maxBase64CandidateBytes {
			continue
		}
		decoded, ok, decodeLimited := decodeBlobStatus(c.Value)
		capped = capped || decodeLimited
		if !ok {
			continue
		}
		// All decoded findings use the same outer span, so only its highest-confidence
		// typed match can survive the final overlap pass. Choose that winner here instead
		// of retaining candidates * decoded matches entries until the global sort.
		var best Match
		var found, limited bool
		if capture {
			remaining := maxNestedBlobs
			best, found, limited = d.bestDecodedContextBudget(ctx, decoded, 1, &remaining, true)
		} else {
			best, found, limited = d.bestDecoded(ctx, decoded, 1)
		}
		capped = capped || limited
		if found && c.needsStrong && best.Confidence < 0.9 {
			// No secret-like name vouches for this blob, so only a precise typed hit may speak for it.
			found = false
		}
		if found {
			// Linear Base64 occurrences are mapped independently, including padding and inner spans.
			if nonLinearOnly && !best.decodedNonLinear && !nonLinearBlob(c.Value) {
				continue
			}
			if capture {
				verificationText, _ := best.VerificationContext()
				if len(verificationText) > maxNonLinearContextBytes-contextBytes {
					capped = true
					break
				}
				contextBytes += len(verificationText)
			}
			best.decodedNonLinear = nonLinearOnly || best.decodedNonLinear || nonLinearBlob(c.Value)
			best.Start, best.End = c.Start, c.End
			best.Confidence *= 0.95
			best.Stage = "L1-base64"
			if best.ChecksumValid {
				best.Stage += "-checksum"
			}
			out = append(out, best)
		}
	}
	return out, capped
}

// base64Candidates retains whole encoded blobs (base64 std/URL, hex) for typed decoding only, without
// changing the entropy net's generic finding spans. Short encoded access keys must be eligible even
// when no generic rule collects their outer value.
//
// The gate is the decode itself: only a blob that decodes to printable text can hold anything the
// typed rules look for, so opaque entropy noise never consumes the candidate budget. A blob with a
// secret-like name on its line is a full candidate; one without is kept too, but marked needsStrong
// so unmaskBase64 accepts only a precise typed hit from it (a ConfigMap value, a cookie, a CI
// variable named "payload" carry encoded credentials just as often as one named "secret").
func base64Candidates(ctx context.Context, text string, runs [][2]int) ([]Match, bool) {
	var candidates []Match
	capped := false
	for _, r := range runs {
		if ctx.Err() != nil {
			break
		}
		val := text[r[0]:r[1]]
		if len(val) < minBase64CandidateBytes || len(val) > maxBase64CandidateBytes {
			continue
		}
		if !(len(val) >= minHexBlobBytes && isHex(val)) && !b64PrefixLooksLikeText(val) {
			continue
		}
		_, ok, limited := decodeBlobStatus(val)
		capped = capped || limited
		if !ok {
			continue
		}
		if IsKnownNonSecretBlob(text, r[0]) || IsExampleOrPlaceholder(val) {
			continue
		}
		named := HasSecretNameContext(text, r[0])
		if named && (ShannonEntropy(val) < genericEntropyMin || IsHashNotSecret(text, r[0], val) ||
			looksLikeCodePath(val) || (reRecaptchaSiteKey.MatchString(val) && hasRecaptchaCue(text, r[0]))) {
			// the entropy net's own non-secret verdicts still hold, but only cost the name's vouching
			named = false
		}
		if len(candidates) >= maxScanMatches {
			return candidates, true
		}
		candidates = append(candidates, Match{Value: val, Start: r[0], End: r[1], needsStrong: !named})
	}
	return candidates, capped
}

// tryB64Decode handles padded/unpadded std and url alphabets (candidate spans strip '=' padding).
func tryB64Decode(s string) ([]byte, bool) {
	enc := base64Encoding(s)
	if enc == nil {
		return nil, false
	}
	dec, err := enc.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return dec, true
}

var strictStdB64 = base64.StdEncoding.Strict()
var strictRawStdB64 = base64.RawStdEncoding.Strict()
var strictURLB64 = base64.URLEncoding.Strict()
var strictRawURLB64 = base64.RawURLEncoding.Strict()

// Select exactly the alphabet/padding accepted by the former four-decoder loop.
// Decode ignores CR/LF, so they must not participate in the length checks.
func base64Encoding(s string) *base64.Encoding {
	standard, url, padding, count := false, false, 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\r' || c == '\n' {
			continue
		}
		count++
		if c == '=' {
			padding++
			if padding > 2 {
				return nil
			}
			continue
		}
		if padding > 0 {
			return nil
		}
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '+' || c == '/':
			standard = true
		case c == '-' || c == '_':
			url = true
		default:
			return nil
		}
	}
	if standard && url || padding > 0 && count%4 != 0 || padding == 0 && count%4 == 1 {
		return nil
	}
	if padding > 0 {
		if url {
			return strictURLB64
		}
		return strictStdB64
	}
	if url {
		return strictRawURLB64
	}
	return strictRawStdB64
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
