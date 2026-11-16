package detect

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"strings"

	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

const (
	// maxDecodeDepth bounds how many encoding layers are peeled (base64 of base64 of gzip ...).
	maxDecodeDepth = 3
	// maxInflateBytes bounds a decompressed payload, so a small blob can't expand without limit.
	maxInflateBytes = 256 << 10
	// maxNestedBlobs bounds how many inner blobs one decoded layer may fan out to.
	maxNestedBlobs = 32
	// minHexBlobBytes is the shortest hex run decoded as text (16 decoded bytes).
	minHexBlobBytes = 32
)

// decodeBlob turns an encoded blob into the text it carries: hex or base64 (std/url, padded or not),
// then gzip/zlib when the decoded bytes are a compressed stream. ok is false unless the result is
// printable text — opaque binary (hashes, keys, images) never reaches the regex layer.
func decodeBlobStatus(s string) (string, bool, bool) {
	var dec []byte
	if len(s) >= minHexBlobBytes && len(s)%2 == 0 && isHex(s) {
		if b, err := hex.DecodeString(s); err == nil && printableText(b) {
			return string(b), true, false
		}
	}
	dec, ok := tryB64Decode(s)
	if !ok {
		return "", false, false
	}
	inflated, compressed, limited := inflateStatus(dec)
	if compressed {
		dec = inflated
	}
	if !printableText(dec) {
		// Reject opaque bytes as text, but keep uncertainty about an uninspected
		// compressed tail: a binary-looking prefix cannot prove it contains no text.
		return "", false, limited
	}
	return string(dec), true, limited
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// inflate decompresses gzip/zlib within maxInflateBytes. Available output is retained,
// while the status API preserves uncertainty about damaged or oversized streams.
func inflate(b []byte) ([]byte, bool) {
	out, ok, _ := inflateStatus(b)
	return out, ok
}

func inflateStatus(b []byte) ([]byte, bool, bool) {
	return inflateStatusLimit(b, maxInflateBytes)
}

func inflateStatusLimit(b []byte, limit int) ([]byte, bool, bool) {
	if len(b) < 6 {
		return nil, false, false
	}
	var r io.ReadCloser
	switch {
	case b[0] == 0x1f && b[1] == 0x8b:
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, false, false
		}
		r = zr
	case b[0]&0x0f == 8 && (uint(b[0])<<8|uint(b[1]))%31 == 0:
		zr, err := zlib.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, false, false
		}
		r = zr
	default:
		return nil, false, false
	}
	out, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	closeErr := r.Close()
	// A plausible header followed only by invalid data is not evidence of a
	// compressed document. Random provider tokens can have those bytes too.
	oversized := len(out) > limit
	// Even a short or low-entropy prefix can come from a real damaged stream.
	// Entropy and printability must not turn an integrity failure into a clean scan.
	// A validated empty deflate stream with a bad checksum is also evidence of
	// damage; in gzip it can stop inspection before a later member holding text.
	checksumFailure := errors.Is(err, gzip.ErrChecksum) || errors.Is(err, zlib.ErrChecksum)
	damaged := (len(out) > 0 || checksumFailure) && (err != nil || closeErr != nil)
	limited := oversized || damaged
	if len(out) > limit {
		out = out[:limit]
	}
	return out, true, limited
}

// b64PrefixLooksLikeText cheaply rejects a base64 run whose first decoded bytes are not text, before
// paying for a full decode. It only ever says "no" to input printableText would also reject on those
// bytes, or to a compressed stream's header (which is let through).
func b64PrefixLooksLikeText(s string) bool {
	var quad [16]byte
	n := 0
	for i := 0; i < len(s) && n < len(quad); i++ {
		c := s[i]
		var v byte
		switch {
		case c >= 'A' && c <= 'Z':
			v = c - 'A'
		case c >= 'a' && c <= 'z':
			v = c - 'a' + 26
		case c >= '0' && c <= '9':
			v = c - '0' + 52
		case c == '+' || c == '-':
			v = 62
		case c == '/' || c == '_':
			v = 63
		default:
			return false
		}
		quad[n] = v
		n++
	}
	if n < len(quad) {
		return true // too short to judge: let the full decode decide
	}
	var out [12]byte
	for i := 0; i < 4; i++ {
		q := quad[i*4:]
		out[i*3] = q[0]<<2 | q[1]>>4
		out[i*3+1] = q[1]<<4 | q[2]>>2
		out[i*3+2] = q[2]<<6 | q[3]
	}
	if out[0] == 0x1f && out[1] == 0x8b || out[0]&0x0f == 8 && (uint(out[0])<<8|uint(out[1]))%31 == 0 {
		return true // gzip / zlib header
	}
	high := 0
	for _, c := range out {
		switch {
		case c == 0 || c == 0x7f || c < 0x20 && c != '\n' && c != '\r' && c != '\t':
			return false
		case c >= 0x80:
			high++
		}
	}
	return high <= 6 // UTF-8 text is fine; mostly-high bytes are binary
}

// bestDecoded scans one decoded layer and returns its highest-confidence typed match. When the layer
// holds no typed secret itself it peels the encoded blobs inside it, up to maxDecodeDepth.
func (d *Detector) bestDecoded(ctx context.Context, decoded string, depth int) (best Match, found, capped bool) {
	remaining := maxNestedBlobs
	return d.bestDecodedBudget(ctx, decoded, depth, &remaining)
}

func (d *Detector) bestDecodedBudget(ctx context.Context, decoded string, depth int, remaining *int) (best Match, found, capped bool) {
	return d.bestDecodedContextBudget(ctx, decoded, depth, remaining, false)
}

func (d *Detector) bestDecodedContextBudget(ctx context.Context, decoded string, depth int, remaining *int, capture bool) (best Match, found, capped bool) {
	if ctx.Err() != nil {
		return best, false, false
	}
	matches, limited := d.collect(ctx, decoded, "", "", d.keywordsPresent(strings.ToLower(decoded)), scanStructure(decoded, 32))
	capped = limited
	for _, m := range matches {
		if taxonomy.GenericLast[m.Type] {
			continue
		}
		if !found || m.Confidence > best.Confidence {
			if context, _ := m.VerificationContext(); capture && context == "" {
				m.verificationText, m.verificationStart = decoded, m.Start
			}
			best, found = m, true
		}
	}
	if found || depth >= maxDecodeDepth {
		return best, found, capped
	}
	for _, r := range scanStructure(decoded, 32).b64decodeRuns {
		if ctx.Err() != nil {
			break
		}
		val := decoded[r[0]:r[1]]
		if len(val) < minBase64CandidateBytes || len(val) > maxBase64CandidateBytes {
			continue
		}
		if *remaining <= 0 {
			capped = true
			break
		}
		*remaining--
		inner, ok, limited := decodeBlobStatus(val)
		capped = capped || limited
		if !ok {
			continue
		}
		m, ok, limited := d.bestDecodedContextBudget(ctx, inner, depth+1, remaining, capture)
		capped = capped || limited
		if ok && nonLinearBlob(val) {
			m.decodedNonLinear = true
		}
		if ok && (!found || m.Confidence > best.Confidence) {
			best, found = m, true
		}
	}
	return best, found, capped
}

// Compressed bytes have no linear mapping into plaintext; hex uses another encoding quantum.
func nonLinearBlob(value string) bool {
	if len(value) >= minHexBlobBytes && len(value)%2 == 0 && isHex(value) {
		return true
	}
	b, ok := tryB64Decode(value)
	return ok && len(b) >= 2 && (b[0] == 0x1f && b[1] == 0x8b || b[0]&0x0f == 8 && (uint(b[0])<<8|uint(b[1]))%31 == 0)
}

// encodedBasicAuth reports base64 `user:password` pairs stored under an auth key — the form Docker's
// config.json ("auth": "..."), Kubernetes dockerconfigjson and .npmrc (_auth=...) use. The decoded
// pair matches no typed rule, so without this they are invisible; the key name supplies the context.
func (d *Detector) encodedBasicAuth(ctx context.Context, text string, runs [][2]int, budget int) ([]Match, bool) {
	if !d.basicAuth || budget <= 0 {
		return nil, false
	}
	var out []Match
	for _, r := range runs {
		if ctx.Err() != nil {
			break
		}
		val := text[r[0]:r[1]]
		if len(val) < minBase64CandidateBytes || len(val) > 512 || !authKeyBefore(text, r[0]) {
			continue
		}
		dec, ok := tryB64Decode(val)
		if !ok || !printableText(dec) {
			continue
		}
		user, pass, ok := strings.Cut(string(dec), ":")
		if !ok || !isBasicAuthUser(user) || !isBasicAuthPassword(pass) || IsExampleOrPlaceholder(pass) {
			continue
		}
		if len(out) >= budget {
			return out, true
		}
		out = append(out, Match{Type: "basic_auth_header", Value: val, Start: r[0], End: r[1],
			Confidence: 0.6 * 0.95, Category: d.basicAuthCat, Stage: "L1-base64"})
	}
	return out, false
}

// authKeyBefore reports whether the text just before start is an assignment to a key named exactly
// auth or _auth (`"auth": "`, `auth: `, `_auth=`), as opposed to any name merely containing "auth".
func authKeyBefore(text string, start int) bool {
	before := strings.TrimRight(lineBeforeRaw(text, start), "\"' \t")
	if !strings.HasSuffix(before, ":") && !strings.HasSuffix(before, "=") {
		return false
	}
	before = strings.ToLower(before)
	before = strings.TrimRight(before[:len(before)-1], "\"' \t")
	if !strings.HasSuffix(before, "auth") {
		return false
	}
	rest := strings.TrimSuffix(before[:len(before)-len("auth")], "_")
	if rest == "" {
		return true
	}
	c := rest[len(rest)-1]
	return !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.')
}

func isBasicAuthUser(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '.' || c == '_' || c == '-' || c == '@' || c == '+') {
			return false
		}
	}
	return true
}

func isBasicAuthPassword(s string) bool {
	if len(s) < 6 || len(s) > 256 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return false
		}
	}
	return true
}
