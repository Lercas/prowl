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
// Each builtin is one regex (run through the same line windows as the taxonomy) plus a validator that
// decides on the name and the value, so widening the accepted syntax does not widen what is reported.

const (
	stageContextKey = "L1-context-key"
	minNamedSecret  = 20
	minHexSecret    = 32
)

var (
	// 1 = name, 2-5 = value (double-quoted, single-quoted, backticked, bare).
	reNamedKey = regexp.MustCompile("(?i)([A-Za-z0-9_.\\-]*(?:token|secret|api[_\\- ]?key|apikey|key|credential)[A-Za-z0-9_\\-]*)" +
		"[\"'`\\])]{0,3}\\s*(?:=>|:=|=|:)\\s*[bru]?" +
		"(?:\"([^\"\\s]{16,200})\"|'([^'\\s]{16,200})'|`([^`\\s]{16,200})`|([A-Za-z0-9_\\-+/=.]{16,200}))")
	// 1 = base64 credentials after the Basic scheme.
	reBasicScheme = regexp.MustCompile(`(?i)\bbasic\s+([A-Za-z0-9+/]{8,512}={0,2})`)
	// 1 = double-quoted value, 2 = single-quoted value, after a password-like name.
	reQuotedPassword = regexp.MustCompile("(?i)(?:pass(?:word|wd|phrase)?|pwd)[A-Za-z0-9_]{0,24}" +
		"[\"'`\\])]{0,3}\\s*(?:=>|:=|=|:)\\s*[bru]?(?:\"([^\"\\s]{6,64})\"|'([^'\\s]{6,64})')")

	namedBuiltins = []*regexp.Regexp{reNamedKey, reBasicScheme, reQuotedPassword}
)

// nonSecretNameParts mark a name that holds a description of a secret rather than the secret: a
// digest of it, a reference to where it lives, its metadata, or public material.
var nonSecretNameParts = []string{
	"hash", "sha", "md5", "digest", "checksum", "crc", "fingerprint", "thumbprint", "etag", "integrity",
	"commit", "revision", "uuid", "guid", "public", "pub_", "_pub", "pubkey",
	"name", "ref", "path", "file", "dir", "url", "uri", "endpoint", "host", "type", "kind", "algo",
	"length", "size", "count", "len", "version", "label", "title", "desc", "prefix", "suffix", "field",
	"header", "param", "env", "var", "arn", "format", "pattern", "regex", "expir", "ttl", "lifetime",
	"timeout", "created", "updated", "status", "enabled", "required", "valid", "policy", "rotation",
	"csrf", "xsrf", "page", "cursor", "continuation", "nonce", "idempot", "tokenizer", "keyword",
	"keyboard", "keystroke", "keyframe", "monkey", "turkey", "hotkey", "shortcut",
}

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
	if strings.HasSuffix(n, "_id") || strings.HasSuffix(n, "id") && !strings.HasSuffix(n, "valid") {
		return false, false
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
func looksRandom(v string) bool {
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
	if ShannonEntropy(v) < genericEntropyMin {
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
func namedKeyValueOK(v string, hexOnly bool) bool {
	if len(v) < minNamedSecret || hexOnly && !isHexRun(v) {
		return false
	}
	if strings.Contains(v, "://") || reUUID.MatchString(v) || isVersionOrNumber(v) {
		return false
	}
	if IsPlaceholderAPIKey(v) || IsTemplatePlaceholder(v) || isLicenseKeyShape(v) || looksLikeCodePath(v) {
		return false
	}
	return looksRandom(v)
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
func (d *Detector) namedSecrets(ctx context.Context, text, lower string, budget int) []Match {
	if budget <= 0 || (!d.genericKey && !d.genericPwd && !d.basicAuth) {
		return nil
	}
	if lower == "" {
		lower = strings.ToLower(text)
	}
	hasKey := strings.Contains(lower, "key") || strings.Contains(lower, "token") ||
		strings.Contains(lower, "secret") || strings.Contains(lower, "credential")
	hasBasic := strings.Contains(lower, "basic")
	hasPass := strings.Contains(lower, "pass") || strings.Contains(lower, "pwd")
	want := []bool{d.genericKey && hasKey, d.basicAuth && hasBasic, d.genericPwd && hasPass}
	if !want[0] && !want[1] && !want[2] {
		return nil
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
	full := func() bool { return len(out) >= budget || ctx.Err() != nil }

	if want[0] {
		for _, ix := range wins.FindAll(0, reNamedKey, text, budget+1) {
			if full() {
				break
			}
			ok, hexOnly := nameIsSecretLike(text[ix[2]:ix[3]])
			vs, ve, found := firstGroup(ix, 2, 5)
			if !ok || !found {
				continue
			}
			val := strings.TrimRight(text[vs:ve], ".") // a bare value ending a sentence
			if !namedKeyValueOK(val, hexOnly) {
				continue
			}
			out = append(out, Match{Type: "generic_api_key", Value: val, Start: vs, End: vs + len(val),
				Confidence: 0.6, Category: d.genericKeyCat, Stage: stageContextKey})
		}
	}
	if want[1] {
		for _, ix := range wins.FindAll(1, reBasicScheme, text, budget+1) {
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
				IsExampleOrPlaceholder(pass) {
				continue
			}
			// The decoded user:password pair is proof of what the blob is, unlike the bare regex shape.
			out = append(out, Match{Type: "basic_auth_header", Value: text[vs:ve], Start: vs, End: ve,
				Confidence: 0.9, Category: d.basicAuthCat, Stage: "L1-base64"})
		}
	}
	if want[2] {
		for _, ix := range wins.FindAll(2, reQuotedPassword, text, budget+1) {
			if full() {
				break
			}
			vs, ve, found := firstGroup(ix, 1, 2)
			if !found {
				continue
			}
			val := text[vs:ve]
			// Only values the main regex cannot take whole: it stops at a quote, comma or semicolon.
			if !strings.ContainsAny(val, `"',;`) || !passwordWithSeparatorsOK(val) {
				continue
			}
			out = append(out, Match{Type: "generic_password", Value: val, Start: vs, End: ve,
				Confidence: 0.6, Category: "generic", Stage: "L1-context-pw"})
		}
	}
	return out
}

// passwordWithSeparatorsOK: a quoted password holding separator characters must still look like one —
// a letter and a digit, no placeholder, no template or code fragment.
func passwordWithSeparatorsOK(v string) bool {
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
	return letter && digit && !IsExampleOrPlaceholder(v) && !IsTemplatePlaceholder(v) && !hasJSOperator(v)
}
