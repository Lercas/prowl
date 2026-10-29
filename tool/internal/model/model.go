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
	// ArtifactURI identifies a source-declared locator independently of the display path.
	ArtifactURI string `json:"-"`
	// Error marks unreadable source content; it must not be treated as a clean empty item.
	Error error
	// ImageEntry identifies the physical TAR entry when a layer repeats a file path.
	ImageEntry int
}

// IsIncompleteFinding identifies scan diagnostics that filtering must not hide as accepted secrets.
func IsIncompleteFinding(f Finding) bool {
	switch f.Type {
	case "results_truncated", "response_truncated", "item_too_large", "source_error":
		return true
	default:
		return false
	}
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
	// ByteStart/ByteEnd are local source offsets for editor diagnostics; never serialized in reports.
	ByteStart int `json:"-"`
	ByteEnd   int `json:"-"`
	// UTF16Col is derived from the scanned snapshot for SARIF; Col remains byte-based for JSON/pretty.
	// Zero means no derived column is available (e.g. an intake diagnostic).
	UTF16Col int `json:"-"`
	// ArtifactURI carries source-declared URI provenance for SARIF; Path remains the display identity.
	ArtifactURI string `json:"-"`
	// Redacted is the masked secret by default; with --show-secrets it holds the FULL unredacted value.
	Redacted string `json:"redacted"`
	Stage    string `json:"stage"`
	// URL, when set, is a direct locator for the finding (a Jira browse URL, a Confluence page URL).
	// Code findings leave it empty and use Path:Line. Omitted from JSON when empty.
	URL       string `json:"url,omitempty"`
	Verified  *bool  `json:"verified,omitempty"`
	Rationale string `json:"rationale,omitempty"`
	// Fingerprint is a stable type/path/value identity (SHA-256, or scoped HMAC with an identity key), set at
	// scan time before redaction. Baselining keys on this so two distinct secrets that share their
	// first/last 4 chars (e.g. all AWS keys start AKIA) don't collide to one fingerprint.
	Fingerprint string `json:"fingerprint,omitempty"`
	// Context is the ML feature context (surrounding line + leading name). Emitted only under
	// --show-secrets, since the line holds the raw secret; it lets the flywheel train on the exact
	// features the scan scored, instead of a context-stripped value.
	Context *FindingContext `json:"context,omitempty"`
	// InFinalImage (image scans only): true if the file survives to the flattened/deployed image, false
	// if only in a historical/overwritten/whiteout-deleted layer, nil = unknown or not an image scan.
	InFinalImage *bool `json:"in_final_image,omitempty"`
	// ImageEntry is internal provenance; it is deliberately absent from report formats.
	ImageEntry int `json:"-"`
	// Instruction (image scans with --show-secrets only): the Dockerfile build step that introduced the layer.
	Instruction   string            `json:"instruction,omitempty"`
	SecretID      string            `json:"secret_id,omitempty"`
	IdentityScope string            `json:"identity_scope,omitempty"`
	Occurrences   []Occurrence      `json:"occurrences,omitempty"`
	OccurrenceID  string            `json:"occurrence_id,omitempty"`
	Evidence      []Evidence        `json:"evidence,omitempty"`
	Provenance    map[string]string `json:"provenance,omitempty"`
	Verification  *Verification     `json:"verification,omitempty"`
	MLScore       *float64          `json:"ml_score,omitempty"`
}

// Evidence points at observed source spans; it never stores plaintext fragments.
type Evidence struct {
	Path      string `json:"path"`
	Start     int    `json:"start"`
	End       int    `json:"end"`
	Line      int    `json:"line"`
	Col       int    `json:"col"`
	Transform string `json:"transform"`
}

type Verification struct {
	Status       string   `json:"status"`
	Verifier     string   `json:"verifier,omitempty"`
	CheckedAt    string   `json:"checked_at,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	Reason       string   `json:"reason,omitempty"`
}

// FindingContext mirrors mlscore.Context's value-dependent fields (path/source are already on Finding).
type FindingContext struct {
	Name string `json:"name,omitempty"`
	Line string `json:"line,omitempty"`
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
	runes := []rune(v)
	if len(runes) <= 2*keep {
		return strings.Repeat("*", len(runes))
	}
	mid := len(runes) - 2*keep
	if mid > 8 {
		mid = 8
	}
	return string(runes[:keep]) + strings.Repeat("*", mid) + string(runes[len(runes)-keep:])
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
