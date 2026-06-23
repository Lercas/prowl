package mlfeatures

import (
	"math"
	"regexp"
	"strings"
	"unicode"
)

// Context mirrors the optional context dict in the Python reference. All fields
// are optional strings (name / line / path / source).
type Context struct {
	Name   string
	Line   string
	Path   string
	Source string
}

// FeatureNames is the stable feature order (matching FEATURE_NAMES in
// src/features/extract.py); Extract returns values in exactly this order.
var FeatureNames = []string{
	// string-intrinsic
	"length",
	"log_length",
	"shannon_entropy",
	"normalized_entropy",
	"base64_entropy",
	"hex_entropy",
	"bigram_entropy",
	"compression_ratio",
	"char_diversity",
	// _char_class_stats
	"frac_lower",
	"frac_upper",
	"frac_digit",
	"frac_special",
	"frac_hex",
	"frac_vowel",
	"case_transitions_norm",
	"longest_digit_run",
	"longest_alpha_run",
	// _format_flags
	"is_uuid",
	"is_hex",
	"is_base64_charset",
	"is_base32_charset",
	"is_numeric",
	"is_jwt",
	"is_pem_private_key",
	"is_dsn",
	"has_known_prefix",
	"is_hashlike_len",
	// _placeholder_flags
	"placeholder_marker_count",
	"has_placeholder_marker",
	"has_placeholder_run",
	// _context_features
	"ctx_name_has_secret_kw",
	"ctx_line_has_secret_kw",
	"ctx_any_secret_kw",
	"ctx_is_assignment",
	"ctx_in_quotes",
	"ctx_in_url",
	"ctx_is_comment",
	"ctx_test_path",
	"ctx_name_len",
	"ctx_source_code",
	"ctx_source_jira",
	"ctx_source_confluence",
	"ctx_source_unknown",
	// _structural_flags (appended last: keeps the original 44 indices stable)
	"is_ssh_pubkey",
	"is_arn",
	"is_data_uri",
	"is_object_id",
	"url_host_local",
}

// --- structural regexes, mirroring src/features/extract.py -------------------
var (
	reUUID      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reHex       = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	reNumeric   = regexp.MustCompile(`^[0-9]+$`)
	reJWT       = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$`)
	rePEM       = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)
	reDSN       = regexp.MustCompile(`(?i)^[a-z][a-z0-9+.\-]*://`)
	rePlaceRun  = regexp.MustCompile(`(x{4,}|X{4,}|\*{4,}|\.{3,}|0{6,}|1234|abcd|asdf|qwerty)`)
	reAssignEnd = regexp.MustCompile(`[:=]\s*['"]?$`)
	reAssignKV  = regexp.MustCompile(`\b\w+\s*[:=]\s*`)
	reQuote     = regexp.MustCompile(`['"]`)
)

// knownPrefixes mirrors KNOWN_PREFIXES (order matters only for "first hit",
// which does not affect the boolean output).
var knownPrefixes = []string{
	"AKIA", "ASIA", "AIza", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
	"glpat-", "xoxb-", "xoxp-", "xoxa-", "xapp-", "sk_live_", "pk_live_", "rk_live_",
	"sk-ant-", "sk-proj-", "sk-", "SG.", "npm_", "pypi-", "AC", "SK", "shpat_", "shpss_",
	"dop_v1_", "glptt-", "EAACEdEose0cBA", "key-", "xkeysib-",
}

// placeholderMarkers mirrors PLACEHOLDER_MARKERS.
var placeholderMarkers = []string{
	"example", "your_", "your-", "yourkey", "changeme", "change_me", "placeholder",
	"dummy", "sample", "test", "fake", "xxxx", "xxx", "<", ">", "...", "redacted",
	"insert", "todo", "fixme", "replace", "myapikey", "secret_here", "abcdef123456",
	"0000000000", "1234567890", "deadbeef", "foobar", "lorem",
}

// secretKeywords mirrors SECRET_KEYWORDS.
var secretKeywords = []string{
	"secret", "password", "passwd", "pwd", "token", "apikey", "api_key", "access_key",
	"accesskey", "auth", "credential", "private_key", "privatekey", "client_secret",
	"secret_key", "session", "bearer", "authorization", "encryption_key", "signing_key",
	"passphrase", "connectionstring", "conn_str", "dsn", "key", "cert", "ssh",
}

// sourceTypes mirrors SOURCE_TYPES.
var sourceTypes = []string{"code", "jira", "confluence", "unknown"}

// sshPubkeyPrefixes mirrors SSH_PUBKEY_PREFIXES.
var sshPubkeyPrefixes = []string{
	"ssh-rsa ", "ssh-ed25519 ", "ssh-dss ", "ecdsa-sha2-", "sk-ssh-", "sk-ecdsa-",
}

// localHosts mirrors LOCAL_HOSTS (exact-match set after lowercasing).
var localHosts = map[string]struct{}{
	"localhost": {}, "127.0.0.1": {}, "0.0.0.0": {}, "::1": {}, "[::1]": {},
}

// privateHostPrefixes mirrors PRIVATE_HOST_PREFIXES.
var privateHostPrefixes = []string{"10.", "192.168.", "169.254."}

// dockerHosts mirrors DOCKER_HOSTS: bare service names that resolve only inside a
// compose/k8s network, so a DSN to one is not a leak.
var dockerHosts = map[string]struct{}{
	"db": {}, "database": {}, "postgres": {}, "postgresql": {}, "redis": {},
	"mysql": {}, "mongo": {}, "mongodb": {}, "rabbitmq": {}, "memcached": {},
	"host.docker.internal": {},
}

// boolf converts a bool to a 0.0/1.0 feature value, mirroring Python float(bool).
func boolf(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

// Extract returns the 49 features for one candidate (value + optional context)
// in FeatureNames order. It is an exact port of extract_features().
func Extract(value string, ctx Context) []float64 {
	s := value

	out := make([]float64, 0, len(FeatureNames))

	// string-intrinsic (9)
	out = append(out,
		float64(runeLen(s)),                // length
		math.Log1p(float64(runeLen(s))),    // log_length
		shannonEntropy(s),                  // shannon_entropy
		normalizedEntropy(s),               // normalized_entropy
		alphabetEntropy(s, base64Alphabet), // base64_entropy
		alphabetEntropy(s, hexAlphabet),    // hex_entropy
		bigramEntropy(s),                   // bigram_entropy
		compressionRatio(s),                // compression_ratio
		charDiversity(s),                   // char_diversity
	)

	out = appendCharClassStats(out, s)
	out = appendFormatFlags(out, s)
	out = appendPlaceholderFlags(out, s)
	out = appendContextFeatures(out, ctx)
	out = appendStructuralFlags(out, s)

	return out
}

// appendCharClassStats mirrors _char_class_stats(). Output order:
// frac_lower, frac_upper, frac_digit, frac_special, frac_hex, frac_vowel,
// case_transitions_norm, longest_digit_run, longest_alpha_run.
func appendCharClassStats(out []float64, s string) []float64 {
	rs := []rune(s)
	n := len(rs)
	if n == 0 {
		n = 1 // Python: n = len(s) or 1
	}

	lower, upper, digit, special, hexish, vowels := 0, 0, 0, 0, 0, 0
	for _, c := range rs {
		if pyIsLower(c) {
			lower++
		}
		if pyIsUpper(c) {
			upper++
		}
		if pyIsDigit(c) {
			digit++
		}
		if !pyIsAlnum(c) {
			special++
		}
		if _, ok := hexAlphabet[c]; ok {
			hexish++
		}
		if isVowel(c) {
			vowels++
		}
	}

	// case transitions: count lower<->upper switches (ignoring "O" class).
	transitions := 0
	prev := byte(0) // 0 = none, 'L', 'U', 'O'
	for _, c := range rs {
		var cls byte
		switch {
		case pyIsLower(c):
			cls = 'L'
		case pyIsUpper(c):
			cls = 'U'
		default:
			cls = 'O'
		}
		if prev != 0 && cls != prev && cls != 'O' && prev != 'O' {
			transitions++
		}
		prev = cls
	}

	longestRun := func(pred func(rune) bool) int {
		best, cur := 0, 0
		for _, c := range rs {
			if pred(c) {
				cur++
			} else {
				cur = 0
			}
			if cur > best {
				best = cur
			}
		}
		return best
	}

	fn := float64(n)
	out = append(out,
		float64(lower)/fn,              // frac_lower
		float64(upper)/fn,              // frac_upper
		float64(digit)/fn,              // frac_digit
		float64(special)/fn,            // frac_special
		float64(hexish)/fn,             // frac_hex
		float64(vowels)/fn,             // frac_vowel
		float64(transitions)/fn,        // case_transitions_norm
		float64(longestRun(pyIsDigit)), // longest_digit_run
		float64(longestRun(pyIsAlpha)), // longest_alpha_run
	)
	return out
}

// appendFormatFlags mirrors _format_flags().
func appendFormatFlags(out []float64, s string) []float64 {
	isHex := reHex.MatchString(s)

	// in_b64 = all chars in BASE64_ALPHABET AND len > 0
	inB64 := len(s) > 0 && allInSet(s, base64Alphabet)
	inB32 := len(s) > 0 && allInSet(s, base32Alphabet)

	prefixHit := false
	for _, p := range knownPrefixes {
		if strings.HasPrefix(s, p) {
			prefixHit = true
			break
		}
	}

	n := runeLen(s)
	hashlike := isHex && (n == 32 || n == 40 || n == 56 || n == 64 || n == 128)

	out = append(out,
		boolf(reUUID.MatchString(s)),    // is_uuid
		boolf(isHex),                    // is_hex
		boolf(inB64),                    // is_base64_charset
		boolf(inB32),                    // is_base32_charset
		boolf(reNumeric.MatchString(s)), // is_numeric
		boolf(reJWT.MatchString(s)),     // is_jwt
		boolf(rePEM.MatchString(s)),     // is_pem_private_key (Python re.search)
		boolf(reDSN.MatchString(s)),     // is_dsn (Python re.match -> anchored ^)
		boolf(prefixHit),                // has_known_prefix
		boolf(hashlike),                 // is_hashlike_len
	)
	return out
}

// appendPlaceholderFlags mirrors _placeholder_flags().
func appendPlaceholderFlags(out []float64, s string) []float64 {
	low := strings.ToLower(s)
	markerHits := 0
	for _, m := range placeholderMarkers {
		if strings.Contains(low, m) {
			markerHits++
		}
	}
	out = append(out,
		float64(markerHits),              // placeholder_marker_count
		boolf(markerHits > 0),            // has_placeholder_marker
		boolf(rePlaceRun.MatchString(s)), // has_placeholder_run (Python re.search)
	)
	return out
}

// appendContextFeatures mirrors _context_features().
func appendContextFeatures(out []float64, ctx Context) []float64 {
	name := strings.ToLower(ctx.Name)
	line := strings.ToLower(ctx.Line)
	path := strings.ToLower(ctx.Path)
	// Empty Source lowercases to "" (Python's "unknown" default only applies to an
	// absent dict key, which the struct field never is).
	src := strings.ToLower(ctx.Source)

	nameKw := containsAny(name, secretKeywords)
	lineKw := containsAny(line, secretKeywords)

	// assignment: a trailing "key: " before the value, or any "word = " on the line.
	var assignTarget string
	if name != "" && strings.Contains(line, name) {
		assignTarget = pySplitFirst(line, name)
	} else {
		assignTarget = line
	}
	assignment := reAssignEnd.MatchString(assignTarget) || reAssignKV.MatchString(line)

	inQuotes := reQuote.MatchString(line)
	inURL := strings.Contains(line, "http://") || strings.Contains(line, "https://") || strings.Contains(line, "://")

	// is_comment: line.strip().startswith(("#", "//", "*", "<!--", "--"))
	stripped := pyStrip(line)
	isComment := strings.HasPrefix(stripped, "#") ||
		strings.HasPrefix(stripped, "//") ||
		strings.HasPrefix(stripped, "*") ||
		strings.HasPrefix(stripped, "<!--") ||
		strings.HasPrefix(stripped, "--")

	testPath := strings.Contains(path, "test") ||
		strings.Contains(path, "fixture") ||
		strings.Contains(path, "example") ||
		strings.Contains(path, "sample") ||
		strings.Contains(path, "mock") ||
		strings.Contains(path, "spec") ||
		strings.Contains(path, "/docs/")

	out = append(out,
		boolf(nameKw),           // ctx_name_has_secret_kw
		boolf(lineKw),           // ctx_line_has_secret_kw
		boolf(nameKw || lineKw), // ctx_any_secret_kw
		boolf(assignment),       // ctx_is_assignment
		boolf(inQuotes),         // ctx_in_quotes
		boolf(inURL),            // ctx_in_url
		boolf(isComment),        // ctx_is_comment
		boolf(testPath),         // ctx_test_path
		float64(runeLen(name)),  // ctx_name_len
	)
	for _, st := range sourceTypes {
		out = append(out, boolf(src == st)) // ctx_source_*
	}
	return out
}

// appendStructuralFlags mirrors _structural_flags(). Output order:
// is_ssh_pubkey, is_arn, is_data_uri, is_object_id, url_host_local.
func appendStructuralFlags(out []float64, s string) []float64 {
	// is_object_id: 24 hex code points (runeLen matches Python's len()).
	isObjectID := runeLen(s) == 24 && reHex.MatchString(s)

	out = append(out,
		boolf(hasAnyPrefix(s, sshPubkeyPrefixes)), // is_ssh_pubkey
		boolf(strings.HasPrefix(s, "arn:")),       // is_arn
		boolf(strings.HasPrefix(s, "data:")),      // is_data_uri
		boolf(isObjectID),                         // is_object_id
		boolf(isLocalHost(urlHost(s))),            // url_host_local
	)
	return out
}

// --- helpers ----------------------------------------------------------------

func allInSet(s string, set map[rune]struct{}) bool {
	for _, r := range s {
		if _, ok := set[r]; !ok {
			return false
		}
	}
	return true
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func isVowel(c rune) bool {
	switch c {
	case 'a', 'e', 'i', 'o', 'u', 'A', 'E', 'I', 'O', 'U':
		return true
	}
	return false
}

// pySplitFirst returns the substring before the first sep, like Python's
// "line.split(name)[0]".
func pySplitFirst(s, sep string) string {
	idx := strings.Index(s, sep)
	if idx < 0 {
		return s
	}
	return s[:idx]
}

// pyStrip mirrors Python str.strip(): strips Unicode whitespace from both ends.
func pyStrip(s string) string {
	return strings.TrimSpace(s)
}

// hasAnyPrefix reports whether s starts with any of the given prefixes.
func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// urlHost mirrors _url_host(s): the ASCII-lowercased host of a
// scheme://[user[:pw]@]host[:port]/... value, or "" when there is no "://".
func urlHost(s string) string {
	i := strings.Index(s, "://")
	if i < 0 {
		return ""
	}
	// authority: up to the first "/", then after the last "@".
	rest := s[i+3:]
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		rest = rest[:slash]
	}
	authority := rest
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		authority = authority[at+1:]
	}
	var host string
	if strings.HasPrefix(authority, "[") {
		// IPv6 literal [::1]:port -> strip brackets (end>0 since [0] is '[').
		end := strings.IndexByte(authority, ']')
		if end > 0 {
			host = authority[1:end]
		} else {
			host = authority[1:]
		}
	} else {
		host = authority
		if colon := strings.IndexByte(host, ':'); colon >= 0 {
			host = host[:colon] // drop :port
		}
	}
	return lowerASCII(host)
}

// isLocalHost mirrors _is_local_host(host). host is assumed already lowercased
// (urlHost lowercases its result, matching the Python call site).
func isLocalHost(host string) bool {
	if host == "" {
		return false
	}
	if _, ok := localHosts[host]; ok {
		return true
	}
	if _, ok := dockerHosts[host]; ok {
		return true
	}
	if hasAnyPrefix(host, privateHostPrefixes) {
		return true
	}
	if strings.HasPrefix(host, "172.") {
		// 172.16.0.0/12: second octet in 16..31.
		parts := strings.Split(host, ".")
		if len(parts) >= 2 && asciiIsDigits(parts[1]) {
			if v, ok := atoiASCII(parts[1]); ok && v >= 16 && v <= 31 {
				return true
			}
		}
	}
	return false
}

// lowerASCII maps 'A'-'Z' to 'a'-'z' and leaves other bytes unchanged, matching
// Python str.lower() on the ASCII host values fed here without Unicode folding.
func lowerASCII(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			if b == nil {
				b = []byte(s)
			}
			b[i] = c + ('a' - 'A')
		}
	}
	if b == nil {
		return s
	}
	return string(b)
}

// asciiIsDigits reports whether s is non-empty and all ASCII digits. Host octets
// are ASCII, so restricting to ASCII keeps int() parsing exact.
func asciiIsDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// atoiASCII parses an all-ASCII-digit string to an int, capping the accumulator
// so a long digit run cannot overflow before the 16..31 range check rejects it.
func atoiASCII(s string) (int, bool) {
	v := 0
	for i := 0; i < len(s); i++ {
		v = v*10 + int(s[i]-'0')
		if v > 1<<30 {
			return v, true // already far outside 16..31; exact value irrelevant
		}
	}
	return v, true
}

// --- Python-faithful character classification -------------------------------
//
// These mirror Python's per-char str.islower/isupper/isdigit/isalpha/isalnum.
// Go's unicode.* predicates match them identically on ASCII (what the model was
// trained on).

func pyIsLower(c rune) bool {
	return unicode.IsLower(c)
}

func pyIsUpper(c rune) bool {
	return unicode.IsUpper(c)
}

func pyIsDigit(c rune) bool {
	return unicode.IsDigit(c)
}

func pyIsAlpha(c rune) bool {
	return unicode.IsLetter(c)
}

func pyIsAlnum(c rune) bool {
	return unicode.IsLetter(c) || unicode.IsDigit(c) || unicode.IsNumber(c)
}
