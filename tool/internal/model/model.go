// Package model holds the language-independent data contracts of the scanner.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// Item is a unit of content from a Source (a file, a Jira ticket, a Confluence page).
type Item struct {
	Text   string
	Source string // code | jira | confluence | slack | log
	Path   string
	Meta   map[string]any
}

// Finding is a single detected secret.
type Finding struct {
	Detector   string  `json:"detector"`
	Type       string  `json:"type"`
	Confidence float64 `json:"confidence"`
	Severity   string  `json:"severity"`
	Source     string  `json:"source"`
	Path       string  `json:"path"`
	Line       int     `json:"line"`
	Col        int     `json:"col"`
	Redacted   string  `json:"redacted"`
	Stage      string  `json:"stage"`
	Verified   *bool   `json:"verified,omitempty"`
	Rationale  string  `json:"rationale,omitempty"`
	// Fingerprint is a stable per-secret identity (sha256 over type|path|RAW value), set once at
	// scan time before redaction. Baselining keys on this so two distinct secrets that share their
	// first/last 4 chars (e.g. all AWS keys start AKIA) don't collide to one fingerprint.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// ComputeFingerprint derives a finding's stable identity from the FULL raw secret value (not the
// redacted form), so distinct secrets never collide. Line/col are intentionally excluded so the
// fingerprint survives the secret moving lines.
func ComputeFingerprint(typ, path, raw string) string {
	if raw == "" {
		return "" // no stable identity without the secret value; the caller falls back to the legacy key
	}
	// NUL-separate the fields so a delimiter inside a path can't collide two distinct findings.
	h := sha256.Sum256([]byte(typ + "\x00" + path + "\x00" + raw))
	return hex.EncodeToString(h[:])
}

// SeverityOrder ranks severities for the exit-code gate.
var SeverityOrder = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// Redact masks the middle of a secret for safe reporting. PEM/multiline private-key blocks are
// redacted by RedactKey instead, since first4+last4 of such a value is the boilerplate
// "----****----" — identical for every key and identifying nothing.
func Redact(v string) string {
	if k, ok := RedactKey(v); ok {
		return k
	}
	return redactPlain(v)
}

// redactPlain keeps the first/last `keep` chars and masks a bounded middle. Suitable for
// single-token secrets (API keys, passwords) where the head/tail aid recognition.
func redactPlain(v string) string {
	const keep = 4
	if len(v) <= 2*keep {
		return strings.Repeat("*", len(v))
	}
	mid := len(v) - 2*keep
	if mid > 8 {
		mid = 8
	}
	return v[:keep] + strings.Repeat("*", mid) + v[len(v)-keep:]
}

// pemBegin matches the boilerplate header of a PEM private-key block and captures the key type
// (e.g. "RSA PRIVATE KEY", "OPENSSH PRIVATE KEY"). Anchored so it only fires on a leading header.
var pemBegin = regexp.MustCompile(`^-----BEGIN ([A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?)-----`)

// RedactKey produces a safe redaction for a PEM private-key value and reports whether v was
// PEM-shaped. first4+last4 of a PEM is pure boilerplate ("----****----"): identical for every key
// and identifying nothing. Instead we surface the key TYPE from the BEGIN line (RSA / EC / OPENSSH /
// …) plus a short one-way hash of the matched value, so a reader sees what kind of key leaked and
// distinct match values produce distinct hashes — while no key material is revealed (the type line
// is public boilerplate and sha256 is irreversible).
//
// NOTE: callers that only have the BEGIN header (the regex match is the header line) get a hash that
// varies by key *type/header*, not by key *body*. For per-finding distinction the report instead
// keys on Finding.Fingerprint, which is hashed over the value+path at scan time. The raw key is never
// reconstructable from either.
func RedactKey(v string) (string, bool) {
	m := pemBegin.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return "", false
	}
	sum := sha256.Sum256([]byte(v))
	keyType := strings.TrimSpace(m[1])
	// e.g. "RSA PRIVATE KEY [sha256:1a2b3c4d]"
	return keyType + " [sha256:" + hex.EncodeToString(sum[:])[:8] + "]", true
}

// IsPEMKey reports whether a redacted value is a PEM key label produced by RedactKey (i.e. the
// original secret was a PEM private-key block). The report uses this to give such rows a
// per-finding distinguisher from the fingerprint.
func IsPEMKey(redacted string) bool {
	return strings.Contains(redacted, "PRIVATE KEY [sha256:")
}
