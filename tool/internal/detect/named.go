package detect

import (
	"context"
	"regexp"
	"strings"

	"github.com/Lercas/prowl/tool/internal/linewin"
)

// Named-assignment builtins. The taxonomy's generic regexes expect `cue = value` with the cue glued
// to the assignment sign and a short list of cue words. Real code and config write the same
// assignment many other ways:
//
//	SECRET_KEY=3ec85be3…            a hex key (openssl rand -hex 32) under any *_KEY / *_SECRET name
//	os.environ["API_KEY"] = "…"     the name closed by a quote and bracket
//	'api_key' => '…'                PHP / Ruby / Perl hash rocket
//	export DEPLOY_TOKEN=…           an arbitrary prefix before the cue
//	Use the API key: …              a cue written with a space
//	Authorization: "Basic …"        a header built as a string in code
//	password = "Kx7;mP,q2'vL"       a quoted value holding the separators the regex stops at
//
// The builtins are single-line on purpose (blanks around the sign are spaces and tabs only): the line
// windows then cover one line per cue instead of five.
//
// Each builtin is one regex (run through the same line windows as the taxonomy) plus a validator that
// decides on the name and the value, so widening the accepted syntax does not widen what is reported.

const (
	stageContextKey     = "L1-context-key"
	minNamedSecret      = 20
	minShortNamedSecret = 12
	minHexSecret        = 32
)

var (
	// 1 = the name from its cue word on, 2-5 = value (double-quoted, single-quoted, backticked, bare).
	// The regex starts at the cue so it has a literal to anchor on; what precedes the cue in the name
	// (DEPLOY_ in DEPLOY_TOKEN) is recovered by nameStart.
	reNamedKey = regexp.MustCompile("(?i)((?:token|secret|api[_\\- ]?key|apikey|key|credential)[A-Za-z0-9_\\-]*)" +
		"[\"'`\\])]{0,3}[ \\t]*(?:=>|:=|=|:)[ \\t]*" +
		"(?:[bru]?\"([^\"\\s]{12,200})\"|[bru]?'([^'\\s]{12,200})'|`([^`\\s]{12,200})`|([A-Za-z0-9_\\-+/=.]{12,200}))")
	// 1 = a generated key in a bounded, explicit prose binding.
	reProseKey = regexp.MustCompile("(?i)(?:api[_\\- ]?key|apikey|[A-Za-z0-9_]*_key|[A-Za-z0-9_]*secret|[A-Za-z0-9_]*token)[A-Za-z0-9_]*(?:\\*\\*)?[\"'`]?(?:[ \\t]+(?:is|was|equals|lautet|ist|est|actuel|actual|atual|é|è|es|to|now|used|for|authentication|access)){0,4}[ \\t]*(?:[(:（：]|[—–-][ \\t]+|[ \\t]+)[ \\t]*[\"'`(]?([A-Za-z0-9_\\-+/=.]{16,200})")
	// 1 = base64 credentials after the Basic scheme.
	reBasicScheme = regexp.MustCompile(`(?i)\bbasic\s+([A-Za-z0-9+/]{8,512}={0,2})`)
	// 1 = what follows the cue in the name, 2 = double-quoted value, 3 = single-quoted value.
	reQuotedPassword = regexp.MustCompile("(?i)(?:pass(?:word|wd|phrase)?|pwd)([A-Za-z0-9_]{0,24})" +
		"[\"'`\\])]{0,3}[ \\t]*(?:=>|:=|=|:)[ \\t]*[bru]?(?:\"([^\"\\s]{6,64})\"|'([^'\\s]{6,64})')")

	namedBuiltins = []*regexp.Regexp{reNamedKey, reBasicScheme, reQuotedPassword, reComparisonRight, reComparisonLeft, reProseKey}
)

// nonSecretNameParts mark a name that holds a description of a secret rather than the secret: a
// digest of it, a reference to where it lives, its metadata, or public material.
var nonSecretNameParts = []string{
	"hash", "sha", "md5", "digest", "checksum", "crc", "fingerprint", "thumbprint", "etag", "integrity",
	"commit", "revision", "uuid", "guid", "public", "pub_", "_pub", "pubkey",
	"name", "reference", "path", "file", "url", "uri", "endpoint", "host", "type", "kind", "algo",
	"length", "size", "count", "version", "label", "title", "desc", "prefix", "suffix", "field",
	"header", "param", "format", "pattern", "regex", "expir", "lifetime",
	"timeout", "created", "updated", "status", "enabled", "required", "valid", "policy", "rotation",
	"csrf", "xsrf", "page", "cursor", "continuation", "nonce", "idempot", "tokenizer", "keyword",
	"keyboard", "keystroke", "keyframe", "monkey", "turkey", "hotkey", "shortcut",
}

// nonSecretNameWords are the short markers: matched only as a whole word of the name (a `_`/`-`
// separated part, or its ending), since as substrings they sit inside real names — "ref" in
// refresh_token, "len" in challenge_token, "env" in environment_secret.
var nonSecretNameWords = []string{"ref", "len", "dir", "env", "var", "arn", "ttl", "id", "ids", "alg"}

// keyQualifiers are what make a bare "…key" name a credential (as opposed to a cache key, a sort key,
// a primary key, a map key).
var keyQualifiers = []string{
	"secret", "private", "priv", "api", "access", "encrypt", "crypt", "cipher", "sign", "master",
	"auth", "app", "hmac", "aes", "session", "consumer", "client", "license", "licence", "deploy",
	"service", "account", "storage", "shared", "symmetric", "jwt", "webhook", "admin", "root",
}

// nameIsSecretLike decides whether an assigned name designates a credential. hexOnly reports that the
// name is strong enough only for a long hex value (a bare `key`, as in a key file).
func nameIsSecretLike(name string) (ok, hexOnly bool) {
	n := strings.ToLower(name)
	if i := strings.LastIndexByte(n, '.'); i >= 0 {
		n = n[i+1:] // obj.field: the field carries the meaning
	}
	n = strings.ReplaceAll(n, " ", "_")
	for _, p := range nonSecretNameParts {
		if strings.Contains(n, p) {
			return false, false
		}
	}
	for _, part := range strings.FieldsFunc(n, func(r rune) bool { return r == '_' || r == '-' }) {
		for _, w := range nonSecretNameWords {
			if part == w {
				return false, false
			}
		}
	}
	// camelCase endings (secretRef, tokenId, keyLen) survive lowercasing only as suffixes
	for _, w := range []string{"ref", "id", "ids", "len", "arn", "ttl"} {
		if strings.HasSuffix(n, w) && len(n) > len(w) && !strings.HasSuffix(n, "valid") && !strings.HasSuffix(n, "token") {
			return false, false
		}
	}
	switch {
	case strings.Contains(n, "token"), strings.Contains(n, "secret"), strings.Contains(n, "credential"),
		strings.Contains(n, "apikey"):
		return true, false
	}
	// only "key" is left as the cue
	for _, q := range keyQualifiers {
		if strings.Contains(n, q) {
			return true, false
		}
	}
	if n == "key" {
		return true, true
	}
	return false, false
}

// looksRandom reports whether v reads as generated key material rather than a word, an identifier or
// a composed label: letters and digits both present, enough entropy, and — when it is built from
// separator-joined parts — at least one part that is itself random.
func (policyTuning Tuning) looksRandom(v string) bool {
	var letter, digit bool
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c >= '0' && c <= '9':
			digit = true
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			letter = true
		}
	}
	if !letter || !digit {
		return false
	}
	if isHexRun(v) {
		return len(v) >= minHexSecret && ShannonEntropy(v) >= 3.0
	}
	if ShannonEntropy(v) < policyTuning.GenericEntropyMin || classSwitchRate(v) < minClassSwitchRate {
		return false
	}
	parts := strings.FieldsFunc(v, func(r rune) bool { return r == '_' || r == '-' || r == '.' })
	if len(parts) < 3 {
		return true
	}
	for _, p := range parts {
		if len(p) >= 12 && partIsRandom(p) {
			return true
		}
	}
	return false
}

// minClassSwitchRate separates generated material from identifiers. Random base62 switches between
// lowercase, uppercase and digit on well over half of its adjacent pairs; camelCase names and dotted
// expressions (testRSAPrivateKey, tls13.NewEarlySecret, encapsulationKey1024) on about one in seven.
const minClassSwitchRate = 0.3

// classSwitchRate is the share of adjacent alphanumeric pairs whose character class differs.
func classSwitchRate(v string) float64 {
	class := func(c byte) int {
		switch {
		case c >= 'a' && c <= 'z':
			return 1
		case c >= 'A' && c <= 'Z':
			return 2
		case c >= '0' && c <= '9':
			return 3
		}
		return 0
	}
	pairs, switches := 0, 0
	for i := 1; i < len(v); i++ {
		a, b := class(v[i-1]), class(v[i])
		if a == 0 || b == 0 {
			continue
		}
		pairs++
		if a != b {
			switches++
		}
	}
	if pairs == 0 {
		return 0
	}
	return float64(switches) / float64(pairs)
}

// partIsRandom: a run of 12+ characters mixing digits with letters, or both letter cases, densely
// enough that it is not a word with a number attached.
func partIsRandom(p string) bool {
	var lo, up, dg int
	for i := 0; i < len(p); i++ {
		switch c := p[i]; {
		case c >= 'a' && c <= 'z':
			lo++
		case c >= 'A' && c <= 'Z':
			up++
		case c >= '0' && c <= '9':
			dg++
		}
	}
	return dg >= 2 && lo+up >= 2 || lo >= 3 && up >= 3
}

var reUUID = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// namedKeyValueOK applies the value-side checks shared by every named-key form.
func (policyTuning Tuning) namedKeyValueOK(v string, hexOnly bool) bool {
	return policyTuning.namedKeyValueWithMinimum(v, hexOnly, minNamedSecret)
}

func (policyTuning Tuning) namedKeyValueWithMinimum(v string, hexOnly bool, minimum int) bool {
	if len(v) < minimum || hexOnly && !isHexRun(v) {
		return false
	}
	if strings.Contains(v, "://") || reUUID.MatchString(v) || isVersionOrNumber(v) {
		return false
	}
	if policyTuning.IsPlaceholderAPIKey(v) || IsTemplatePlaceholder(v) || isLicenseKeyShape(v) || looksLikeCodePath(v) {
		return false
	}
	return policyTuning.looksRandom(v)
}

// Short generated material needs an explicit credential field and a taxonomy
// that accepts its length. The legacy prose path retains its twenty-byte floor.
func (d *Detector) boundKeyValueOK(name, value string, hexOnly bool) bool {
	if len(value) >= minNamedSecret {
		return d.Tuning().namedKeyValueOK(value, hexOnly)
	}
	ok, onlyHex := nameIsSecretLike(name)
	if !ok || !d.Tuning().namedKeyValueWithMinimum(value, hexOnly || onlyHex, minShortNamedSecret) {
		return false
	}
	for _, ct := range d.types {
		if ct.st.ID != "generic_api_key" {
			continue
		}
		for _, field := range []string{name, "api_key"} {
			prefix := "\"" + field + "\": \""
			ix := ct.st.RE.FindStringSubmatchIndex(prefix + value + "\"")
			if ix != nil {
				start, end := extractSpan(ix, ct.st.Extract)
				if start == len(prefix) && end == start+len(value) {
					return true
				}
			}
		}
	}
	return false
}

var identifierWords = []string{
	"private", "public", "secret", "token", "passw", "config", "default", "client", "server",
	"example", "sample", "test", "value", "string", "key",
}

// bareValueIsCode reports whether an unquoted value is an expression rather than a literal: a call
// or index (`NewEarlySecret(`, `keys[`), or a member access (`tls13.NewEarlySecret`, `cert.PrivateKey`).
func bareValueIsCode(text string, vs, ve int) bool {
	if ve < len(text) && (text[ve] == '(' || text[ve] == '[' || text[ve] == '{') {
		return true
	}
	v := text[vs:ve]
	// An unquoted value spelling out what it is (`jwtTestEC256PrivateKey`, `defaultClientSecret2`) is a
	// reference to a variable. Generated material does not contain these words by chance.
	low := strings.ToLower(v)
	for _, w := range identifierWords {
		if strings.Contains(low, w) {
			return true
		}
	}
	for i := 1; i+1 < len(v); i++ {
		if v[i] != '.' {
			continue
		}
		a, b := v[i-1], v[i+1]
		if (a >= 'a' && a <= 'z' || a >= 'A' && a <= 'Z' || a == ')' || a == ']') && (b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z') {
			return true
		}
	}
	return false
}

// nameStart extends a name leftwards from its cue word over identifier characters.
func nameStart(text string, cue int) int {
	i := cue
	for i > 0 && cue-i < 64 {
		c := text[i-1]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-') {
			break
		}
		i--
	}
	return i
}

// firstGroup returns the span of the first participating capture group in [from, to].
func firstGroup(ix []int, from, to int) (int, int, bool) {
	for g := from; g <= to; g++ {
		if 2*g+1 < len(ix) && ix[2*g] >= 0 {
			return ix[2*g], ix[2*g+1], true
		}
	}
	return 0, 0, false
}

// namedSecrets runs the named-assignment builtins. lower is the ASCII-lowered text.
func (d *Detector) namedSecrets(ctx context.Context, text, lower string, budget int) ([]Match, bool) {
	if budget <= 0 || (!d.genericKey && !d.genericPwd && !d.basicAuth) {
		return nil, false
	}
	if lower == "" {
		lower = strings.ToLower(text)
	}
	hasKey := strings.Contains(lower, "key") || strings.Contains(lower, "token") ||
		strings.Contains(lower, "secret") || strings.Contains(lower, "credential")
	hasBasic := strings.Contains(lower, "basic")
	hasPass := strings.Contains(lower, "pass") || strings.Contains(lower, "pw")
	wantComparison := d.genericKey && hasKey || d.genericPwd && hasPass
	want := []bool{d.genericKey && hasKey, d.basicAuth && hasBasic, d.genericPwd && hasPass, wantComparison, wantComparison, d.genericKey && hasKey}
	if !want[0] && !want[1] && !want[2] {
		return nil, false
	}
	var wins *linewin.Windows
	if !wholeTextOnly.Load() {
		if len(lower) != len(text) {
			lower = "" // a Unicode-lowered copy may not be byte-aligned; let Prepare lower it
		}
		wins = d.namedWin.Prepare(text, lower, "", want)
		defer wins.Release()
	}
	var out []Match
	capped := false
	indices := func(i int, re *regexp.Regexp) [][]int {
		ix := wins.FindAllGated(i, re, namedASCIIGates[i], text, lower, budget+1)
		if len(ix) > budget {
			capped = true
			ix = ix[:budget]
		}
		return ix
	}
	full := func() bool { return len(out) >= budget || ctx.Err() != nil }

	if want[0] {
		for _, ix := range indices(0, reNamedKey) {
			if full() {
				break
			}
			name := text[nameStart(text, ix[2]):ix[3]]
			ok, hexOnly := nameIsSecretLike(name)
			vs, ve, found := firstGroup(ix, 2, 5)
			if !ok || !found {
				continue
			}
			// Drop a sentence-ending dot and base64 '=' padding: spans exclude padding everywhere in
			// this package, so the decode stage and this one agree on the blob's extent.
			if ix[10] >= 0 && bareValueIsCode(text, vs, ve) {
				continue
			}
			if ve-vs < minNamedSecret && ix[10] < 0 {
				end, complete := literalPasswordEnd(text, vs)
				if !complete || end != ve {
					continue
				}
			}
			val := strings.TrimRight(text[vs:ve], ".=")
			if !d.boundKeyValueOK(name, val, hexOnly) {
				continue
			}
			out = append(out, Match{Type: "generic_api_key", Value: val, Start: vs, End: vs + len(val),
				Confidence: 0.6, Category: d.genericKeyCat, Stage: stageContextKey})
		}
	}
	if want[5] {
		for _, ix := range indices(5, reProseKey) {
			if full() {
				break
			}
			vs, ve := ix[2], ix[3]
			// A length ceiling or unsupported token suffix must not mint a prefix identity.
			if ve < len(text) && (isTokenChar(text[ve]) || text[ve] == '/') {
				continue
			}
			val := strings.TrimRight(text[vs:ve], ".=")
			name := proseSecretName(lineBefore(text, vs))
			ok, hexOnly := nameIsSecretLike(name)
			// Keep the existing entropy type/identity for the long base64-shaped prose path.
			if BindingName(text, vs) != "" || !ok || !d.Tuning().namedKeyValueOK(val, hexOnly) || d.genericEntropy && len(val) >= 32 && !strings.ContainsAny(val, "_-") {
				continue
			}
			out = append(out, Match{Type: "generic_api_key", Value: val, Start: vs, End: vs + len(val), Confidence: .6, Category: d.genericKeyCat, Stage: stageContextKey, ContextName: name})
		}
	}
	if want[1] {
		for _, ix := range indices(1, reBasicScheme) {
			if full() {
				break
			}
			vs, ve := ix[2], ix[3]
			dec, ok := tryB64Decode(text[vs:ve])
			if !ok || !printableText(dec) {
				continue
			}
			user, pass, ok := strings.Cut(string(dec), ":")
			if !ok || !isBasicAuthUser(user) || len(pass) < 1 || !isBasicAuthPassword(pass+"      "[:max(0, 6-len(pass))]) ||
				d.Tuning().IsExampleOrPlaceholder(pass) {
				continue
			}
			// The decoded user:password pair is proof of what the blob is, unlike the bare regex shape.
			out = append(out, Match{Type: "basic_auth_header", Value: text[vs:ve], Start: vs, End: ve,
				Confidence: 0.9, Category: d.basicAuthCat, Stage: "L1-base64"})
		}
	}
	if want[2] {
		for _, ix := range indices(2, reQuotedPassword) {
			if full() {
				break
			}
			vs, ve, found := firstGroup(ix, 2, 3)
			if !found || passwordNameSuffixIsMeta(text[ix[2]:ix[3]]) {
				continue
			}
			val := text[vs:ve]
			// Only values the main regex cannot take whole: it stops at a quote, comma or semicolon.
			if !strings.ContainsAny(val, `"',;`) || !d.Tuning().passwordWithSeparatorsOK(val) {
				continue
			}
			out = append(out, Match{Type: "generic_password", Value: val, Start: vs, End: ve,
				Confidence: 0.6, Category: "generic", Stage: "L1-context-pw"})
		}
	}
	if wantComparison {
		for i, re := range []*regexp.Regexp{reComparisonRight, reComparisonLeft} {
			for _, ix := range indices(i+3, re) {
				if full() {
					break
				}
				if match, ok := d.comparisonMatch(text, ix, i == 1); ok {
					out = append(out, match)
				}
			}
		}
	}
	return out, capped || ctx.Err() != nil
}

// passwordMetaSuffixes: what may follow "password" in a name that describes the password instead of
// holding it (password_rules, passwordPolicy, password_hint, passwordRegex ...).
var passwordMetaSuffixes = []string{
	"rule", "polic", "hint", "regex", "pattern", "format", "length", "min", "max", "field", "label",
	"prompt", "message", "msg", "error", "help", "text", "title", "placeholder", "reset", "valid",
	"strength", "expir", "hash", "salt", "requirement", "complex", "charset", "chars", "option",
}

func passwordNameSuffixIsMeta(suffix string) bool {
	low := strings.ToLower(suffix)
	for _, m := range passwordMetaSuffixes {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}

// passwordWithSeparatorsOK: a quoted password holding separator characters must still look like one —
// a letter and a digit, no placeholder, no template or code fragment.
func (policyTuning Tuning) passwordWithSeparatorsOK(v string) bool {
	var letter, digit bool
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c >= '0' && c <= '9':
			digit = true
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			letter = true
		case c == '(' || c == ')' || c == '{' || c == '}' || c == '<' || c == '>' || c == '[' || c == ']':
			return false // a call, a template or markup, not a literal
		}
	}
	return letter && digit && !policyTuning.IsExampleOrPlaceholder(v) && !IsTemplatePlaceholder(v) && !hasJSOperator(v)
}
