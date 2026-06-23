package detect

import (
	"encoding/base64"
	"hash/crc32"
	"regexp"
	"strings"
)

// GitHub token checksum alphabet: CRC32(body) base62-encoded digits-first. Best-effort and unverified
// (the CRC variant is reverse-engineered) — a pass boosts confidence, a fail is inconclusive; detection
// never gates on it.
const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// b62crc32 base62-encodes CRC32(body) and returns the last width chars, left-padded.
func b62crc32(body string, width int) string {
	num := crc32.ChecksumIEEE([]byte(body))
	if num == 0 {
		return strings.Repeat(base62[0:1], width)
	}
	var out []byte
	for num > 0 {
		out = append(out, base62[int(num%62)])
		num /= 62
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	s := string(out)
	if len(s) > width {
		s = s[len(s)-width:]
	}
	for len(s) < width {
		s = base62[0:1] + s
	}
	return s
}

var reGithubTok = regexp.MustCompile(`^(gh[opusr]_|github_pat_)([A-Za-z0-9_]+)$`)

// GithubChecksumOK verifies the trailing 6-char base62 CRC32 checksum GitHub tokens carry.
func GithubChecksumOK(token string) bool {
	m := reGithubTok.FindStringSubmatch(token)
	if m == nil {
		return false
	}
	rest := m[2]
	if len(rest) < 7 {
		return false
	}
	body, cs := rest[:len(rest)-6], rest[len(rest)-6:]
	return b62crc32(body, 6) == cs
}

// JWTStructuralOK checks 3 base64url segments whose header decodes to JSON with an "alg".
func JWTStructuralOK(token string) bool {
	if !strings.HasPrefix(token, "eyJ") {
		return false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	dec, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	return strings.Contains(string(dec), `"alg"`)
}

// checksumValid dispatches per type id.
func checksumValid(typeID, value string) (checked, valid bool) {
	switch typeID {
	// Classic ghp_/gho_/… tokens carry a trailing CRC32 checksum. Fine-grained github_pat_ tokens use a
	// scheme GithubChecksumOK can't compute, so they're left unchecked and gated on entropy in collect().
	case "github_pat_classic", "github_token_oauth":
		return true, GithubChecksumOK(value)
	case "jwt":
		return true, JWTStructuralOK(value)
	}
	return false, false
}
