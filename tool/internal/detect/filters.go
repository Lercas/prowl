package detect

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"regexp"
	"strings"
)

// exampleValues are well-known documentation values that must never score as a real secret.
var exampleValues = map[string]bool{
	"akiaiosfodnn7example":                     true,
	"wjalrxutnfemi/k7mdeng/bpxrficyexamplekey": true,
	"sk_test_4ec39hqlyjwdarjtt1zdp7dc":         true,
	"pk_test_tyoomqauvdedq54nitphi7jx":         true,
	"1234567890abcdef1234567890abcdef":         true,
	"00000000-0000-0000-0000-000000000000":     true,
}

var placeholderSubstr = []string{
	"example", "your_", "your-", "changeme", "change_me", "change_this", "change-this",
	"changethis", "placeholder", "dummy",
	"redacted", "<", ">", "xxxx", "myapikey", "secret_here", "lorem",
	// variable / env references
	"${", "{{", "os.environ", "process.env", "getenv",
	// placeholder / test DSN credentials
	"user:password", ":password@", "/dbname", "user:pass@", ":pass@", ":pw@",
	"test_password", "test_user", "fakeurl", "dani:pass",
}

// placeholderSubstrWeak are words that also occur inside random secrets, so weakPlaceholderToken
// gates them on entropy (weakPlaceholderMaxEntropy; see tuning.go) before treating them as placeholders.
var placeholderSubstrWeak = []string{"insert", "replace", "fake", "sample", "todo", "fixme"}

// weakPlaceholderToken reports whether v is a placeholder: a weak word AND low enough entropy to be
// text, not a random secret. Takes the original value (entropy is case-sensitive); match is case-fold.
func weakPlaceholderToken(v string) bool {
	if ShannonEntropy(v) >= weakPlaceholderMaxEntropy {
		return false // high-entropy: a real secret that merely contains the fragment
	}
	low := strings.ToLower(v)
	for _, w := range placeholderSubstrWeak {
		if strings.Contains(low, w) {
			return true
		}
	}
	return false
}

// reTemplateRef matches a single template/variable reference token ($NAME, ${...}, $(...), {{...}},
// %(...)s, <...>, __NAME__), anchored so the placeholder must BE the whole trimmed value. The bare
// $NAME form requires an identifier so a password with a stray mid-string '$' (Pr0d$Pass99) isn't matched.
var reTemplateRef = regexp.MustCompile(
	`^\s*(?:` +
		`\$\{[^}]*\}` + // ${NAME} / ${...}
		`|\$\([^)]*\)` + // $(VAR)
		`|\$[A-Za-z_][A-Za-z0-9_]*` + // $NAME / $GC_DB_PASS
		`|\{\{.*?\}\}` + // {{ name }} / {{name}}
		`|%\([^)]*\)[a-z]` + // %(password)s (python percent-format)
		`|<[^>]*>` + // <password>
		`|__[A-Za-z0-9]+__` + // __PASSWORD__
		`)\s*$`)

// IsTemplatePlaceholder reports whether v is entirely an unresolved template/variable reference
// (e.g. $GC_DB_PASS, ${DB_PASSWORD}) rather than a literal secret.
func IsTemplatePlaceholder(v string) bool {
	return reTemplateRef.MatchString(v)
}

// connURICredential returns the password segment of a credentialed connection URI / userinfo authority
// and true when present. It anchors on "//" so it handles both scheme://user:PASSWORD@host and the bare
// //user:PASSWORD@ form, taking the run from the first ':' after "//" to the next '@'.
func connURICredential(uri string) (string, bool) {
	s := strings.Index(uri, "//")
	if s < 0 {
		return "", false
	}
	rest := uri[s+2:]
	at := strings.IndexByte(rest, '@')
	if at < 0 {
		return "", false
	}
	authority := rest[:at] // user:password
	colon := strings.IndexByte(authority, ':')
	if colon < 0 {
		return "", false // no password segment
	}
	return authority[colon+1:], true
}

// ConnURICredentialIsPlaceholder reports whether uri's password segment is an unresolved template
// placeholder (e.g. postgresql://user:$GC_DB_PASS@host). False when uri has no user:password authority.
func ConnURICredentialIsPlaceholder(uri string) bool {
	cred, ok := connURICredential(uri)
	if !ok {
		return false
	}
	return IsTemplatePlaceholder(cred)
}

// hexCtxSecretKw are line cues that keep a 32-hex value as a secret rather than an md5/etag.
var hexCtxSecretKw = []string{"key", "token", "api", "datadog", "dd_", "cred", "sign"}

func isHexRun(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}

// lineCtxWindow caps the backward line-start scan so a long single line (minified JS/JSON) keeps the
// per-run context checks O(1), not O(n). 2KB is wide enough to catch a preceding password=/api_key: cue.
const lineCtxWindow = 2048

// lineBefore returns the lowercased text from the start of the line containing `start` up to
// `start`, scanning back at most lineCtxWindow bytes for the preceding newline.
func lineBefore(text string, start int) string {
	lo := start - lineCtxWindow
	if lo < 0 {
		lo = 0
	}
	ls := strings.LastIndexByte(text[lo:start], '\n')
	if ls < 0 {
		ls = lo // no newline within the window: use the window start
	} else {
		ls += lo + 1 // byte after the newline
	}
	return strings.ToLower(text[ls:start])
}

// IsHashNotSecret rejects pure-hex digests posing as high-entropy secrets: 40/56/64/96/128-hex are
// always digests; 32-hex is a hash unless the line names it like a secret.
func IsHashNotSecret(text string, start int, val string) bool {
	if !isHexRun(val) {
		return false
	}
	switch len(val) {
	case 40, 56, 64, 96, 128: // sha1 / sha224 / sha256 / sha384 / sha512
		return true
	case 32:
		before := lineBefore(text, start)
		for _, kw := range hexCtxSecretKw {
			if strings.Contains(before, kw) {
				return false
			}
		}
		return true
	}
	return false
}

// reFillerRun matches repeated filler glyphs (xxxx / XXXX / ****). These never occur in a real
// base62/hex secret, so a substring match anywhere is a safe placeholder signal.
var reFillerRun = regexp.MustCompile(`x{4,}|X{4,}|\*{4,}`)

// reSeqRun matches placeholder runs that also occur inside genuine base62/hex secrets (zero runs, the
// 1234567 ramp, abcdef0123, deadbeef), so a hit only counts when the run dominates v (placeholderRunDominates).
var reSeqRun = regexp.MustCompile(`0{6,}|1234567|abcdef0123|deadbeef`)

// placeholderRunDominates reports whether sequential/zero runs cover enough of v to treat it as a
// placeholder: v is short (≤16) or the runs span ≥50% of it. So a stray ramp in a 24+ char key is kept.
func placeholderRunDominates(v string) bool {
	locs := reSeqRun.FindAllStringIndex(v, -1)
	if locs == nil {
		return false
	}
	if len(v) <= 16 {
		return true
	}
	covered := 0
	for _, loc := range locs {
		covered += loc[1] - loc[0]
	}
	return covered*2 >= len(v) // dangerous runs cover ≥ 50% of the value
}

// IsExampleOrPlaceholder reports whether a value is a documentation example / placeholder.
func IsExampleOrPlaceholder(v string) bool {
	low := strings.ToLower(v)
	if exampleValues[low] {
		return true
	}
	for _, s := range placeholderSubstr {
		if strings.Contains(low, s) {
			return true
		}
	}
	if weakPlaceholderToken(v) { // pass the original value: entropy is case-sensitive
		return true
	}
	if reFillerRun.MatchString(v) {
		return true
	}
	if IsTemplatePlaceholder(v) { // whole value is an unresolved $VAR / ${...} / {{...}} / %(...)s ref
		return true
	}
	return placeholderRunDominates(low)
}

// looksLikePassword reports whether v carries a digit, uppercase, or symbol (not a plain word).
func looksLikePassword(v string) bool {
	for i := 0; i < len(v); i++ {
		if c := v[i]; !(c >= 'a' && c <= 'z') {
			return true
		}
	}
	return false
}

var reSnakeWord = regexp.MustCompile(`^[a-z]+(_[a-z]+)+$`)             // start_pass_main
var reCamelWord = regexp.MustCompile(`^[A-Z][a-z]+([A-Z][a-z]+){2,}$`) // TestGetIndent (≥3 words)
var reCodeCall = regexp.MustCompile(`[A-Za-z_]\w*\(`)                  // a func call: get_auth_from_url( , str( , .encode(

// hasUnbalancedBrackets reports whether v has an unpaired () [] or {} (or a closer before its opener),
// the sign the generic_password match swept up a code fragment (`bytes)`, `headers[`) rather than a
// literal — a real password with brackets (`P@ss(w)ord`) is balanced and survives.
func hasUnbalancedBrackets(v string) bool {
	var paren, square, curly int
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '(':
			paren++
		case ')':
			paren--
		case '[':
			square++
		case ']':
			square--
		case '{':
			curly++
		case '}':
			curly--
		}
		if paren < 0 || square < 0 || curly < 0 {
			return true // a closer with no opener before it
		}
	}
	return paren != 0 || square != 0 || curly != 0
}

// looksLikeIdentifier reports whether v looks like a code identifier / env ref (snake_case,
// multi-word CamelCase, $VAR/@ ref, path, function call, or a bracket-unbalanced code fragment), not a
// password.
func looksLikeIdentifier(v string) bool {
	if len(v) > 0 && (v[0] == '$' || v[0] == '@') {
		return true
	}
	if strings.ContainsAny(v, "/") {
		return true
	}
	if reCodeCall.MatchString(v) {
		return true // a function-call expression (get_auth_from_url(proxy), str(pw)) — code, not a literal secret
	}
	if hasUnbalancedBrackets(v) {
		return true // a captured code fragment (bytes), headers[ ) — code, not a literal secret
	}
	return reSnakeWord.MatchString(v) || reCamelWord.MatchString(v)
}

// looksLikeCodePath reports whether v is a slash path of letters only. The no-digit rule keeps a real
// base64/AWS secret (always digit-bearing) from ever matching.
func looksLikeCodePath(v string) bool {
	slash := false
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c == '/':
			slash = true
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c == '_', c == '$':
		default:
			return false
		}
	}
	return slash
}

var reJSMember = regexp.MustCompile(`^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$`) // a.b.c member access

// jsOperators never occur in a real password, so they veto a value whether quoted or not.
var jsOperators = []string{"===", "!==", "=>"}

func hasJSOperator(v string) bool {
	for _, t := range jsOperators {
		if strings.Contains(v, t) {
			return true
		}
	}
	return false
}

// jsKeywords and a member-access chain also occur as base words inside real passwords (myFunction2024!,
// my.secret.token), so looksLikeJSCode is applied to UNQUOTED values only — a quoted literal is the
// common leak form and must be kept.
var jsKeywords = []string{"arguments", "function", "typeof", "prototype", "undefined"}

func looksLikeJSCode(v string) bool {
	for _, t := range jsKeywords {
		if strings.Contains(v, t) {
			return true
		}
	}
	return reJSMember.MatchString(v)
}

// reLicenseKey matches a product key (2UQ52-GH3P8-…); no provider key uses equal-length dash groups.
var reLicenseKey = regexp.MustCompile(`^[A-Z0-9]{5}(?:-[A-Z0-9]{5}){3,}$`)

func isLicenseKeyShape(v string) bool { return reLicenseKey.MatchString(v) }

var reUnicodeEsc = regexp.MustCompile(`\\u[0-9a-fA-F]{4}`)

// looksLikeUnicodeEscaped reports whether v is a \uXXXX-escaped JS string (minified i18n), not a secret.
func looksLikeUnicodeEscaped(v string) bool {
	m := reUnicodeEsc.FindAllStringIndex(v, -1)
	if len(m) < 3 {
		return false
	}
	covered := 0
	for _, x := range m {
		covered += x[1] - x[0]
	}
	return covered*5 >= len(v)*4 // escapes dominate the value
}

var reRecaptchaSiteKey = regexp.MustCompile(`^6L[0-9A-Za-z_-]{38}$`) // public reCAPTCHA client key

var recaptchaCues = []string{"recaptcha", "sitekey", "site_key", "site-key"}

// hasRecaptchaCue reports whether the line names the value as a reCAPTCHA key, so a coincidental 40-char
// 6L-prefixed secret without that cue is not dropped on shape alone.
func hasRecaptchaCue(text string, start int) bool {
	before := lineBefore(text, start)
	for _, c := range recaptchaCues {
		if strings.Contains(before, c) {
			return true
		}
	}
	return false
}

// looksLikeRegexAuthority reports whether a //user:pass@ match is really a URL-parsing regex (a group or
// negated class) — these litter compiled native libs and dex string pools. A lone backslash is NOT a
// signal: a real DSN password may contain one.
func looksLikeRegexAuthority(v string) bool {
	return strings.Contains(v, "(?") || strings.Contains(v, "[^")
}

// isVersionOrNumber rejects version strings / numbers captured as a password (e.g. password=3.6.18).
func isVersionOrNumber(v string) bool {
	for i := 0; i < len(v); i++ {
		if c := v[i]; !((c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// secretNameContext are line cues that mark a high-entropy run as a likely secret.
var secretNameContext = []string{
	"secret", "password", "passwd", "passwort", "pwd", "token", "apikey", "api_key", "api-key",
	"accesskey", "access_key", "access-key", "auth", "credential", "private", "signing", "bearer",
	"client_secret", "encryption", "session_key", "_key", "-key", "key=", "key:", "key ",
}

// HasSecretNameContext reports whether the line containing `start` names the value like a secret.
func HasSecretNameContext(text string, start int) bool {
	before := lineBefore(text, start)
	for _, kw := range secretNameContext {
		if strings.Contains(before, kw) {
			return true
		}
	}
	return false
}

var nonSecretBlobMarkers = []string{
	"ssh-rsa", "ssh-ed25519", "ssh-dss", "ecdsa-sha2", // public keys
	"data:", ";base64,", // data URIs
	"$2a$", "$2b$", "$2y$", // bcrypt
	"-----begin public", "-----begin certificate", // public material
	"integrity=", "sha384-", "sha512-", // SRI hashes
}

// IsKnownNonSecretBlob reports whether the run at start sits in a known non-secret context
// (public key, data URI, bcrypt hash, SRI integrity).
func IsKnownNonSecretBlob(text string, start int) bool {
	before := lineBefore(text, start)
	for _, m := range nonSecretBlobMarkers {
		if strings.Contains(before, m) {
			return true
		}
	}
	return false
}

// ShannonEntropy in bits/char over the empirical symbol distribution.
func ShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := make(map[rune]int)
	for _, r := range s {
		counts[r]++
	}
	n := float64(len([]rune(s)))
	h := 0.0
	for _, c := range counts {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// generic_api_key placeholder filtering: the regex captures whatever follows an api_key/secret/token
// cue, so the run is often an instructional placeholder (sk_live_…HERE, your_api_key, change_this).
// IsExampleOrPlaceholder catches the substring-y ones; the helpers below add the two classes it misses,
// all keeping the "placeholder must BE/dominate the value" discipline so real high-entropy keys survive.

// reGluedUpperPlaceholder matches an uppercase HERE/YOUR run glued onto a value's end (…sk_liveHERE).
// Anchored at end so a real key with HERE mid-string (k3yWithdeadbeefInsideItHere9xQmZ) isn't matched.
var reGluedUpperPlaceholder = regexp.MustCompile(`(?:HERE|YOUR)$`)

// placeholderTokens are whole separator-delimited tokens (lowercased) marking the value as a placeholder
// when standalone — "here" plus common non-English equivalents. Checked per-token, not as a substring.
var placeholderTokens = map[string]bool{
	"here": true, "aqui": true, "aquí": true, // en / es
	"sini": true, "disini": true, "disama": true, // id
	"buraya": true, "burada": true, // tr
	"hier": true, "ici": true, // de / fr
	"yourkey": true, "yourapikey": true, "yourtoken": true, "yoursecret": true,
	"mykey": true, "myapikey": true, "mytoken": true, "mysecret": true,
	"changethis": true, "replaceme": true,
}

// reAPISep splits a value into its alnum segments on any non-alnum separator (case-insensitive so it
// can split an original-case value; callers lowercase tokens themselves when needed).
var reAPISep = regexp.MustCompile(`[^A-Za-z0-9]+`)

// reRampTail matches a low-entropy repeated/ascending run at the END of a (lowercased) value (0000,
// 1234, 7890, abcd, wxyz), the giveaway of a hand-typed placeholder. Only drops a value when no segment
// looks random (see placeholderRampTail), so a genuine key ending in such a run is preserved.
var reRampTail = regexp.MustCompile(`(?:0000+|1111+|2222+|3333+|4444+|5555+|6666+|7777+|8888+|9999+|` +
	`0123|1234|2345|3456|4567|5678|6789|7890|` +
	`abcd|bcde|cdef|defg|efgh|fghi|ghij|hijk|wxyz|vwxy|uvwx)$`)

// looksRandomSegment reports whether a separator-delimited segment carries the entropy mix of a real
// key — mixed-case base62, or a long single-case letters+digits run. Vetoes the ramp-tail drop.
func looksRandomSegment(seg string) bool {
	var hasUpper, hasLower, hasDigit, hasLetter bool
	for i := 0; i < len(seg); i++ {
		switch c := seg[i]; {
		case c >= 'A' && c <= 'Z':
			hasUpper, hasLetter = true, true
		case c >= 'a' && c <= 'z':
			hasLower, hasLetter = true, true
		case c >= '0' && c <= '9':
			hasDigit = true
		}
	}
	if hasUpper && hasLower { // mixed-case alnum is the hallmark of a random base62 secret
		return true
	}
	// a long single-case letters+digits run (≥16, e.g. a hex/base36 key) also reads as random
	return len(seg) >= 16 && hasLetter && hasDigit
}

// reAPIHasSep reports whether a value carries an internal non-alnum separator (_ - . space …),
// i.e. it has the word_word_RAMP shape of a hand-typed placeholder rather than one opaque token.
var reAPIHasSep = regexp.MustCompile(`[A-Za-z0-9][^A-Za-z0-9][A-Za-z0-9]`)

// placeholderRampTail reports whether v is a hand-typed placeholder ending in a low-entropy ramp
// (local_dev_key_1234, demo_key_7890). Fires only when v ends in a ramp AND is short (≤16) or has an
// internal separator AND no segment looks random — so a real key ending in such a run is kept. A long
// separator-less token is left to IsExampleOrPlaceholder / placeholderRunDominates.
func placeholderRampTail(v string) bool {
	if !reRampTail.MatchString(strings.ToLower(v)) {
		return false
	}
	if len(v) > 16 && !reAPIHasSep.MatchString(v) {
		return false // one opaque token: not the word_word_RAMP placeholder shape
	}
	for _, seg := range reAPISep.Split(v, -1) {
		if looksRandomSegment(seg) {
			return false
		}
	}
	return true
}

// IsPlaceholderAPIKey reports whether a generic_api_key value is an instructional placeholder. It layers
// three checks on IsExampleOrPlaceholder: a standalone placeholder token (…_here, your_key), a glued
// uppercase HERE/YOUR tail, and a low-entropy ramp tail — all keeping the placeholder-dominates discipline.
func IsPlaceholderAPIKey(v string) bool {
	if IsExampleOrPlaceholder(v) {
		return true
	}
	if reGluedUpperPlaceholder.MatchString(v) {
		return true
	}
	low := strings.ToLower(v)
	for _, tok := range reAPISep.Split(low, -1) {
		if placeholderTokens[tok] {
			return true
		}
	}
	return placeholderRampTail(v)
}

// jwt example-token filtering: the jwt.io demo token and a few doc fixtures dominate JWT findings.
// Decoding the payload offline lets us recognise the canonical examples by their claims and drop them.

// decodeJWTPart base64url-decodes one JWT segment, tolerating stray '=' padding.
func decodeJWTPart(seg string) ([]byte, bool) {
	seg = strings.TrimRight(seg, "=")
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return nil, false
	}
	return b, true
}

// exampleJWTSigs are signature segments that only ever appear on documentation/sample tokens: the
// jwt.io HS256 demo signature and the literal "signature" filler. A JWT carrying one is an example.
var exampleJWTSigs = map[string]bool{
	"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c": true, // jwt.io HS256 sample (sub 1234567890, John Doe)
	"signature": true,
}

// jwtClaimIsExample reports whether a decoded sub/name/email claim value marks the token as a doc
// example (the jwt.io persona, or an obvious test/example address).
func jwtClaimIsExample(val string) bool {
	v := strings.ToLower(strings.TrimSpace(val))
	switch {
	case strings.Contains(v, "john doe"), strings.Contains(v, "jane doe"):
		return true
	// only RFC-2606 reserved example domains, not any claim containing the substring (admin@example-corp.io)
	case strings.Contains(v, "@example.com"), strings.Contains(v, "@example.org"), strings.Contains(v, "@example.net"):
		return true
	case v == "example", strings.HasPrefix(v, "example "), strings.HasSuffix(v, " example"):
		return true
	case strings.Contains(v, "test@"), strings.Contains(v, "foo@bar"):
		return true
	}
	return false
}

// IsExampleJWT reports whether token is a well-known JWT documentation sample. It decodes the payload
// offline and matches the jwt.io sample, an example sub/name/email claim, or an example signature segment.
func IsExampleJWT(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false // not a 3-segment JWT; leave to the structural check
	}
	sig := parts[2]
	if sig == "" || exampleJWTSigs[sig] {
		return true
	}
	payload, ok := decodeJWTPart(parts[1])
	if !ok {
		return false
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return false // unparseable payload: don't claim it's an example
	}
	subStr, _ := claims["sub"].(string)
	nameStr, _ := claims["name"].(string)
	// the canonical jwt.io sample payload
	if subStr == "1234567890" && nameStr == "John Doe" {
		return true
	}
	for _, k := range []string{"sub", "name", "email"} {
		if s, ok := claims[k].(string); ok && jwtClaimIsExample(s) {
			return true
		}
	}
	return false
}
