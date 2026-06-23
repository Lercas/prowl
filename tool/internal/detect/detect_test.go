package detect

import (
	"encoding/base64"
	"regexp"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

func newDetector(t testing.TB) *Detector {
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	return New(tax)
}

func validGithubToken() string {
	// placeholder-free body (no sequential digits / example runs that the filter would catch)
	body := "kP9aZ2bYwcX4dWqeV8fUmgThS6iRnjQ7"[:30]
	return "ghp_" + body + b62crc32(body, 6)
}

func TestChecksum(t *testing.T) {
	tok := validGithubToken()
	if !GithubChecksumOK(tok) {
		t.Errorf("valid github token rejected: %s", tok)
	}
	if GithubChecksumOK("ghp_" + strings.Repeat("a", 36)) {
		t.Error("invalid-checksum github token accepted")
	}
	if !JWTStructuralOK("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig") {
		t.Error("valid JWT rejected")
	}
	if JWTStructuralOK("eyJabc.def") {
		t.Error("2-segment JWT accepted")
	}
}

func TestExampleFilter(t *testing.T) {
	// obvious placeholders that MUST be filtered
	placeholders := []string{
		"AKIAIOSFODNN7EXAMPLE", "your_api_key_here", "changeme", "xxxxxxxx",
		"AKIAXXXXXXXXXXXXXXXX",             // filler-run placeholder
		"sk_live_0000000000000000000000",   // long zero run dominates
		"1234567890abcdef1234567890abcdef", // canonical hex placeholder
		"1234567890abcdef",                 // short sequential placeholder
		"deadbeefdeadbeefdeadbeefdeadbeef", // all-deadbeef filler dominates
	}
	for _, v := range placeholders {
		if !IsExampleOrPlaceholder(v) {
			t.Errorf("expected %q to be example/placeholder", v)
		}
	}
	// real-looking secrets that merely CONTAIN a placeholder run must NOT be dropped (Bug 1)
	reals := []string{
		"AKIANAFGYOEYPXU1DSYP",
		"sk_live_aZ9xK1234567qR4tV8wY1bC3d", // stray 1234567 inside a 28-char key
		"k3yWithdeadbeefInsideItHere9xQmZ",  // stray deadbeef inside a 32-char key
	}
	for _, v := range reals {
		if IsExampleOrPlaceholder(v) {
			t.Errorf("real secret %q wrongly flagged as example/placeholder", v)
		}
	}
}

// TestWeakPlaceholderUsesOriginalCaseEntropy guards the fix that weakPlaceholderToken's entropy gate
// runs on the ORIGINAL (case-preserving) value, not the lowercased one. A mixed-case real secret
// that merely contains a weak word ("fake"/"sample") and whose TRUE entropy is just above the 4.2
// ceiling used to be wrongly suppressed because case-folding dropped its entropy below 4.2.
func TestWeakPlaceholderUsesOriginalCaseEntropy(t *testing.T) {
	// Mixed-case real secrets: true entropy > 4.2, lowercased entropy < 4.2. Must NOT be suppressed.
	for _, v := range []string{
		"SampleAbCdEfGhIjKlMnOpQr", // orig 4.418, low 4.168
		"FakeAaBbCcDdEeFfGgHhIiJj", // orig 4.335, low 3.407
	} {
		if ShannonEntropy(v) < weakPlaceholderMaxEntropy {
			t.Fatalf("test value %q has true entropy %.3f below the ceiling — pick a higher-entropy value", v, ShannonEntropy(v))
		}
		if weakPlaceholderToken(v) {
			t.Errorf("weakPlaceholderToken(%q) = true on the original value; entropy %.3f >= ceiling, must be false", v, ShannonEntropy(v))
		}
		if IsExampleOrPlaceholder(v) {
			t.Errorf("mixed-case real secret %q (entropy %.3f) wrongly suppressed as placeholder", v, ShannonEntropy(v))
		}
	}
	// Genuine low-entropy placeholders containing a weak word must STILL be suppressed.
	for _, v := range []string{"fake", "sample", "fakefakefake", "my_fake_token", "todo_replace"} {
		if !IsExampleOrPlaceholder(v) {
			t.Errorf("genuine low-entropy placeholder %q should still be suppressed", v)
		}
	}
}

func TestPlaceholderAPIKey(t *testing.T) {
	// generic_api_key values that are obvious instructional placeholders and MUST be dropped
	drop := []string{
		"sk_live_xxxxxxxxHERE",    // uppercase HERE run + filler
		"sk_live_HERE",            // HERE token after separator
		"API_KEY_HERE",            // HERE standalone token
		"tokenHERE",               // glued uppercase HERE tail
		"your_api_key",            // your_ phrase
		"YOUR_API_KEY_HERE",       // your_ + HERE
		"<your-key>", "<api-key>", // <...> bracketed
		"replace-me", "replaceme", // replace word
		"changeme", "change_this", // change words
		"example_api_key",            // example word
		"dummy_secret_token",         // dummy word
		"placeholder_value",          // placeholder word
		"todo_add_real_key",          // todo word
		"xxxxxxxx",                   // filler run
		"local_dev_key_1234",         // low-entropy 1234 ramp tail
		"my_api_key_0000",            // 0000 tail
		"test_token_wxyz",            // wxyz letter ramp tail
		"demo_key_7890",              // 7890 ramp tail
		"klingai_api_key_1234567890", // long digit ramp tail
		"secret_aqui",                // es "here" token
		"anahtar_buraya",             // tr "here" token
		"kunci_disini",               // id "here" token
	}
	for _, v := range drop {
		if !IsPlaceholderAPIKey(v) {
			t.Errorf("expected %q to be dropped as a placeholder api key", v)
		}
	}
	// real keys that must NOT be dropped (high-entropy / mixed-case / dedicated-provider shapes)
	keep := []string{
		"sk_live_4eC39HqLyjWDarjtT1zdp7Xc",              // real stripe sk_live_ + 24 random
		"xoxb-2334534534-3434334334-aZ9xK1bC3dQ7rT4vW8", // real slack xoxb-
		"AIzaSyDabc123XYZdef456GHIjklMNO789pqrs",        // real google
		"aZ9xK1bC3dQ7rT4vW8yU2pL5",                      // bare 24-char high-entropy key
		"k3yWithdeadbeefInsideItHere9xQmZ",              // 'here' glued mid-token, real
		"02f5e1a9c3b7d4f60a8e2c1b9d3f7a50",              // 32-hex real-ish
		"aZ9xK1bC3dQ7rT4vW8yU2pL5nM6oP0sR1234",          // mixed-case key that happens to end in a ramp
		"f3a91c2e8b7d40569a1c3e7b8d2f6789",              // real 32-hex ending in 6789 (no separator) -> keep
	}
	for _, v := range keep {
		if IsPlaceholderAPIKey(v) {
			t.Errorf("real api key %q wrongly dropped as a placeholder", v)
		}
	}
}

// the canonical jwt.io HS256 sample token (sub 1234567890 / John Doe / iat 1516239022).
const jwtIOExample = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
	"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
	"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

func TestExampleJWT(t *testing.T) {
	// example/sample tokens that MUST be dropped (name -> token; payloads noted in comments)
	drop := []struct{ name, tok string }{
		{"jwt.io HS256 sample", jwtIOExample},
		// payload {"sub":"111","name":"Jane Doe"}, different signature
		{"jane doe payload", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMTEiLCJuYW1lIjoiSmFuZSBEb2UifQ.abcDEFxyz123"},
		// payload {"sub":"user@example.com"}
		{"example claim in sub", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIn0.someRealLookingSigXyZ9"},
		// payload {"email":"test@acme.dev"}
		{"test@ email claim", "eyJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6InRlc3RAYWNtZS5kZXYifQ.anotherSigValueHere99"},
		// payload {"sub":"realuser99"} but the literal "signature" filler segment
		{"literal signature sig", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJyZWFsdXNlcjk5In0.signature"},
	}
	for _, c := range drop {
		if !IsExampleJWT(c.tok) {
			t.Errorf("expected example JWT (%s) to be dropped", c.name)
		}
	}
	// real-looking tokens that must be KEPT
	keep := []struct{ name, tok string }{
		// payload {"sub":"abcdefg"} — the e2e fixture
		{"real sub claim", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmNkZWZnIn0.dozjgNryP4Jq3mNHl9wYZ"},
		// payload {"sub":"u_8f3a2c","email":"alice@corp.io"}
		{"real user id + email", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1XzhmM2EyYyIsImVtYWlsIjoiYWxpY2VAY29ycC5pbyJ9.rZ4Kp9XwUq3mNHl9wYZbC"},
	}
	for _, c := range keep {
		if IsExampleJWT(c.tok) {
			t.Errorf("real JWT (%s) wrongly dropped as example", c.name)
		}
	}
}

// TestScanDropsExamples exercises the full Scan() path: placeholder generic_api_key values and the
// jwt.io example token are dropped, while a real high-entropy generic key and a real JWT still fire.
func TestScanDropsExamples(t *testing.T) {
	d := newDetector(t)
	has := func(text, typ string) bool {
		for _, m := range d.Scan(text) {
			if m.Type == typ {
				return true
			}
		}
		return false
	}
	// placeholders dropped (no generic_api_key finding)
	for _, text := range []string{
		`api_key = "sk_live_xxxxxxxxHERE"`,
		`api_key = "your_api_key_value00"`,
		`secret = "local_dev_key_1234"`,
		`api_key = "change_this_secret00"`,
	} {
		if has(text, "generic_api_key") {
			t.Errorf("placeholder reported as generic_api_key in %q", text)
		}
	}
	// a real high-entropy generic key (no dedicated rule) still fires
	if !has(`api_key = "aZ9xK1bC3dQ7rT4vW8yU2pL5"`, "generic_api_key") {
		t.Error("real generic_api_key dropped")
	}
	// jwt.io example dropped, real JWT kept
	if has(`tok = "`+jwtIOExample+`"`, "jwt") {
		t.Error("jwt.io example reported as jwt")
	}
	if !has(`tok = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmNkZWZnIn0.dozjgNryP4Jq3mNHl9wYZ"`, "jwt") {
		t.Error("real JWT dropped")
	}
}

func TestTemplatePlaceholderMatcher(t *testing.T) {
	// unresolved template/variable references that are the WHOLE token -> placeholder
	placeholders := []string{
		"$GC_DB_PASS", "${DB_PASSWORD}", "${...}", "$(VAR)",
		"{{ db_password }}", "{{db_password}}", "%(password)s",
		"<password>", "__PASSWORD__", "  $GC_DB_PASS  ", // surrounding whitespace tolerated
	}
	for _, v := range placeholders {
		if !IsTemplatePlaceholder(v) {
			t.Errorf("expected %q to be a template placeholder", v)
		}
	}
	// real secrets / tokens that merely CONTAIN a $ or { mid-string -> NOT a placeholder
	reals := []string{
		"Pr0dPass99XyZ",  // plain real password
		"Pr0d$Pass99XyZ", // a $ mid-string, real surrounding secret
		"aZ9xK1bC3dQ7rT4vW8yU2pL5nM6oP0sR1eF7gH9j", // high-entropy key
		"k3y{abc}def", // a { mid-string, not anchored
		"my$VAR",      // leading literal text
		"$",           // lone $, no identifier
		"password",    // plain word
	}
	for _, v := range reals {
		if IsTemplatePlaceholder(v) {
			t.Errorf("real value %q wrongly flagged as template placeholder", v)
		}
	}
}

func TestConnectionStringTemplatePlaceholder(t *testing.T) {
	d := newDetector(t)
	dbType := func(text string) (string, string, bool) {
		for _, m := range d.Scan(text) {
			if m.Type == "db_connection_string" {
				return m.Type, m.Value, true
			}
		}
		return "", "", false
	}

	// A connection URI whose password segment is an unresolved variable/template reference is a
	// false positive and MUST be filtered (no db_connection_string finding).
	filtered := []string{
		`database_url = "postgresql://user:$GC_DB_PASS@host/db"`, // the real bug
		`database_url = "postgres://user:${DB_PASSWORD}@host/db"`,
		`database_url = "postgres://user:{{db_password}}@host/db"`,
		`database_url = "postgres://user:%(password)s@host/db"`,
		`database_url = "mysql://root:$(DB_PW)@10.0.0.1:3306/app"`,
		`database_url = "redis://:__REDIS_PASS__@cache:6379"`,
	}
	for _, text := range filtered {
		if _, val, ok := dbType(text); ok {
			t.Errorf("placeholder credential reported as secret in %q (value=%q)", text, val)
		}
	}

	// A real high-entropy password in a URI MUST still be reported, including one that merely
	// contains a single `$` mid-string.
	reported := []string{
		`database_url = "postgres://admin:Sup3rS3cretPw99@db.internal:5432/prod"`,
		`database_url = "postgres://admin:Pr0d$Pass99XyZ@db.internal:5432/prod"`, // one $ mid-string
	}
	for _, text := range reported {
		if _, _, ok := dbType(text); !ok {
			t.Errorf("real connection-string secret was dropped in %q", text)
		}
	}
}

func TestBasicAuthURLTemplatePlaceholder(t *testing.T) {
	d := newDetector(t)
	basicAuth := func(text string) (string, bool) {
		for _, m := range d.Scan(text) {
			if m.Type == "basic_auth_header" {
				return m.Value, true
			}
		}
		return "", false
	}
	// the scheme://user:password@ URL form of basic_auth_header with a placeholder password is the
	// same false-positive class and must be filtered (no basic_auth_header finding).
	for _, text := range []string{
		`url = "https://user:$GC_DB_PASS@host"`,
		`url = "https://user:%(password)s@host"`,
	} {
		if v, ok := basicAuth(text); ok {
			t.Errorf("placeholder userinfo reported as basic_auth_header in %q (value=%q)", text, v)
		}
	}
	// a real userinfo credential must still be reported
	if _, ok := basicAuth(`url = "https://user:R3alStr0ngPw99@host"`); !ok {
		t.Error("real basic-auth userinfo dropped")
	}
}

func TestGenericPasswordTemplatePlaceholder(t *testing.T) {
	d := newDetector(t)
	hits := func(text string) bool {
		for _, m := range d.Scan(text) {
			if m.Type == "generic_password" {
				return true
			}
		}
		return false
	}
	// a generic password assignment whose value is a template/variable ref must be filtered
	for _, text := range []string{
		`password = "$GC_DB_PASS"`,
		`password = "${DB_PASSWORD}"`,
		`password = "%(password)s"`,
		`password = "<password>"`,
	} {
		if hits(text) {
			t.Errorf("template placeholder reported as generic_password in %q", text)
		}
	}
	// a real password must still fire
	if !hits(`password = "Str0ngP@ssw0rd!"`) {
		t.Error("real generic_password dropped")
	}
	// a real QUOTED password may legitimately contain a bracket / (-run — the code-fragment heuristics
	// (looksLikeIdentifier / bracket-balance) must NOT drop it inside a string literal (audit regression).
	for _, text := range []string{`password = "Winter(2024"`, `db_pass = "Adm1n)pass"`, `pwd = "a[b]c9X"`} {
		if !hits(text) {
			t.Errorf("real quoted password with a bracket was dropped: %q", text)
		}
	}
	// but an UNQUOTED swept-up code fragment is still rejected
	for _, text := range []string{`password = get_auth_from_url(proxy)`, `self.password = bytes)`} {
		if hits(text) {
			t.Errorf("unquoted code fragment reported as generic_password: %q", text)
		}
	}
}

func TestScanDetectsAndFilters(t *testing.T) {
	d := newDetector(t)
	text := `
AWS = "AKIANAFGYOEYPXU1DSYP"
GH  = "` + validGithubToken() + `"
DB  = "postgres://admin:Pr0dPass99@db.internal:5432/prod"
EX  = "AKIAIOSFODNN7EXAMPLE"
ID  = "550e8400-e29b-41d4-a716-446655440000"
`
	got := map[string]bool{}
	for _, m := range d.Scan(text) {
		got[m.Type] = true
	}
	for _, want := range []string{"aws_access_key_id", "github_pat_classic", "db_connection_string"} {
		if !got[want] {
			t.Errorf("missing %s; got %v", want, got)
		}
	}
	// example key + bare UUID must NOT produce a (real) secret finding
	if n := len(d.Scan(`k = "AKIAIOSFODNN7EXAMPLE"`)); n != 0 {
		t.Errorf("example key produced %d findings, want 0", n)
	}
	if n := len(d.Scan(`id = "550e8400-e29b-41d4-a716-446655440000"`)); n != 0 {
		t.Errorf("bare UUID produced %d findings, want 0", n)
	}
}

func TestSecretGroupExtraction(t *testing.T) {
	// Bug 2: a gitleaks rule with secretGroup=2 must report the group-2 span (the 40-char secret),
	// not the group-1 prefix. Extract:2 threads that through to the extractor.
	secret := "aZ9xK1bC3dQ7rT4vW8yU2pL5nM6oP0sR1eF7gH9j" // 40 chars, placeholder-free
	tax := &taxonomy.Taxonomy{Types: []taxonomy.SecretType{{
		ID:        "grouped",
		Name:      "Grouped",
		Sensitive: true,
		Detection: taxonomy.Detection{Regex: `(prefix)_(?:x)_([A-Za-z0-9]{40})`},
		Keywords:  []string{"prefix"},
		Source:    "gitleaks",
		Extract:   2,
	}}}
	for i := range tax.Types {
		re := regexp.MustCompile(tax.Types[i].Detection.Regex)
		tax.Types[i].RE = re
	}
	d := New(tax)
	ms := d.Scan("k = prefix_x_" + secret)
	if len(ms) != 1 {
		t.Fatalf("want 1 match, got %d: %+v", len(ms), ms)
	}
	if ms[0].Value != secret {
		t.Errorf("secretGroup ignored: reported %q, want the group-2 secret %q", ms[0].Value, secret)
	}
}

// TestTrailingBoundaryDashUnderscore guards the trailing-\b boundary fix in the taxonomy: many token
// regexes ended with `...{N}\b`, but RE2 `\b` needs a word/non-word transition — a base64url/token
// value ending in '-' (a non-word char) before EOL or another non-word char has NO transition, so the
// match FAILED (fixed-length patterns) or TRUNCATED the value by one char (range patterns). The fix
// replaces the trailing \b with a non-captured (?:[^class]|$) boundary while keeping the value in a
// capture group, so a token ending in '-'/'_' is detected AND its full value (including the trailing
// delimiter char) is reported without swallowing the boundary char.
func TestTrailingBoundaryDashUnderscore(t *testing.T) {
	d := newDetector(t)
	// Exact provider lengths; placeholder-free, high-entropy bodies; ending in '-' and '_'.
	cases := []struct {
		name, typ, token string
	}{
		{"gitlab_pat dash", "gitlab_pat", "glpat-K9aZ2bYwcX4dWqeV8fU-"},
		{"gitlab_pat underscore", "gitlab_pat", "glpat-K9aZ2bYwcX4dWqeV8fU_"},
		{"gcp_api_key dash", "gcp_api_key", "AIzaK9aZ2bYwcX4dWqeV8fUmgThS6iRnjQ7uPp-"},
		{"gcp_api_key underscore", "gcp_api_key", "AIzaK9aZ2bYwcX4dWqeV8fUmgThS6iRnjQ7uPp_"},
		{"telegram dash", "telegram_bot_token", "123456789:K9aZ2bYwcX4dWqeV8fUmgThS6iRnjQ7uPp-"},
		{"sendgrid dash", "sendgrid_api_key", "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"},
		{"discord dash", "discord_bot_token", "MK9aZ2bYwcX4dWqeV8fUmgTh.K9aZ2b.K9aZ2bYwcX4dWqeV8fUmgThS6iRnj-"},
		{"pypi dash", "pypi_token", "pypi-AgEIcHlwaS5vcmcK9aZ2bYwcX4dWqeV8fUmgThS6iRnjQ7uPpLoMdSeXc3hVbN5tG1K9aZ2bYw-"},
		{"jwt dash", "jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.K9aZ2bYwcX4dWqeV8fUmgThS6iRnjQ7uPpLoMdSeXc-"},
		{"openai dash", "openai_api_key", "sk-proj-K9aZ2bYwcX4dWqeV8fUmgThS6T3BlbkFJK9aZ2bYwcX4dWqeV8fUmgThS-"},
	}
	for _, c := range cases {
		text := `tok = "` + c.token + `"`
		var hit *Match
		ms := d.Scan(text)
		for i := range ms {
			if ms[i].Type == c.typ {
				hit = &ms[i]
				break
			}
		}
		if hit == nil {
			t.Errorf("%s: %s NOT detected for token ending %q; got %v", c.name, c.typ, c.token[len(c.token)-1:], ms)
			continue
		}
		// The reported value must be the FULL token including its trailing delimiter — the boundary
		// char must not be swallowed into the value, and a range pattern must not truncate it.
		if hit.Value != c.token {
			t.Errorf("%s: value=%q, want full token %q (trailing delimiter swallowed or value truncated)",
				c.name, hit.Value, c.token)
		}
	}

	// Length discipline must survive the boundary change: gcp_api_key is the fixed-length AIza+{35}
	// shape (39 chars total). An AIza token with a 36-char body (one char too long) must NOT be
	// reported as a gcp_api_key with that over-length value — the leading anchor + exact length still
	// bound the match, so the non-captured boundary did not introduce over-matching.
	tooLong := "AIzaK9aZ2bYwcX4dWqeV8fUmgThS6iRnjQ7uPpLo" // AIza + 36-char body (40 total, one too long)
	for _, m := range d.Scan(`tok = "` + tooLong + `"`) {
		if m.Type == "gcp_api_key" && m.Value == tooLong {
			t.Errorf("over-length token %q wrongly matched gcp_api_key at its exact %d-char shape", tooLong, 39)
		}
	}
}

func TestBase64Unmask(t *testing.T) {
	d := newDetector(t)
	blob := base64.StdEncoding.EncodeToString([]byte("AWS_ACCESS_KEY_ID=AKIANAFGYOEYPXU1DSYP"))
	found := false
	for _, m := range d.Scan(`secret = "` + blob + `"`) {
		if m.Type == "aws_access_key_id" && m.Stage == "L1-base64" {
			found = true
		}
	}
	if !found {
		t.Error("base64-wrapped AWS key not unmasked")
	}
}

func TestKeywordPrefilterParity(t *testing.T) {
	// the keyword pre-filter must not drop any detection vs running every regex
	d := newDetector(t)
	text := strings.Repeat("noise line without any secret keywords here\n", 50) +
		`token = "` + validGithubToken() + `"` + "\n" +
		`db = "mysql://root:hunter2pw@10.0.0.1:3306/app"`
	n := 0
	for _, m := range d.Scan(text) {
		_ = m
		n++
	}
	if n < 2 {
		t.Errorf("prefilter dropped detections; got %d", n)
	}
}

func BenchmarkScan(b *testing.B) {
	d := newDetector(b)
	// ~50KB of realistic code with a few embedded secrets
	chunk := `func handler(w http.ResponseWriter, r *http.Request) {
	id := uuid.New().String()
	log.Printf("request %s from %s", id, r.RemoteAddr)
	result := process(r.Context(), parseBody(r))
	json.NewEncoder(w).Encode(result)
}
`
	text := strings.Repeat(chunk, 300) +
		"\nAWS=\"AKIANAFGYOEYPXU1DSYP\"\nGH=\"" + validGithubToken() + "\"\n"
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Scan(text)
	}
}

func BenchmarkScanClean(b *testing.B) {
	d := newDetector(b)
	// ~50KB of pure code with NO secrets and no secret keywords (the common repo file)
	chunk := `func process(ctx context.Context, in Input) (Output, error) {
	items := make([]Item, 0, len(in.Records))
	for _, r := range in.Records {
		if r.Valid() { items = append(items, transform(r)) }
	}
	return Output{Items: items, Count: len(items)}, nil
}
`
	text := strings.Repeat(chunk, 300)
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Scan(text)
	}
}

func TestStructuralPrefilterRecall(t *testing.T) {
	d := newDetector(t)
	// real-shape telegram + discord tokens must still be detected (prefilter must pass them)
	text := `tg = "528193746:KpZbYwcXdWqVfUmgThSRnjQtLoMxBvHeNk7"
dc = "MKpZbYwcXdWqVfUmgThSRnjQ.KtLoMx.BvHeNkZpAqWsEdRfTgYhUjImKoLp7"`
	got := map[string]bool{}
	for _, m := range d.Scan(text) {
		got[m.Type] = true
	}
	if !got["telegram_bot_token"] {
		t.Error("telegram token dropped by structural prefilter")
	}
	if !got["discord_bot_token"] {
		t.Error("discord token dropped by structural prefilter")
	}
	// clean code must NOT trip the prefilters (the whole point)
	if pf := structuralPrefilter["telegram_bot_token"]; pf(scanStructure("func f(ctx context.Context) {}", 32)) {
		t.Error("telegram prefilter false-positive on clean code")
	}
	if pf := structuralPrefilter["discord_bot_token"]; pf(scanStructure("a.b.c short.dotted.id", 32)) {
		t.Error("discord prefilter false-positive on short dotted ids")
	}
}

func TestContextualMultilingualPassword(t *testing.T) {
	d := newDetector(t)
	// password token in multilingual prose WITHOUT an adjacent anchor — the regex misses these
	hits := func(text string) bool {
		for _, m := range d.Scan(text) {
			if m.Type == "generic_password" {
				return true
			}
		}
		return false
	}
	if !hits("Interesse am Massenkauf. Ihr Passwort lautet F4QPE91sc6iN bitte sicher aufbewahren.") {
		t.Error("german prose password missed")
	}
	if !hits("Bonjour, votre mot de passe temporaire est C1CmREwv5Kac pour la connexion.") {
		t.Error("french prose password missed")
	}
	// must NOT fire on prose with a cue but no random token (precision)
	if hits("Veuillez réinitialiser votre mot de passe sur notre site web officiel.") {
		t.Error("false positive on cue-only prose (no token)")
	}
	// must NOT fire on a capitalized word (no digit/symbol) near a cue
	if hits("Das Passwort Massenkauf ist erforderlich") {
		t.Error("false positive on a plain capitalized word")
	}
}

func TestAhoCorasickMatchesContains(t *testing.T) {
	d := newDetector(t)
	texts := []string{
		`AWS = "AKIANAFGYOEYPXU1DSYP"; ghp_xxx; password = "x"`,
		"random text with no keywords at all here",
		"votre mot de passe / пароль / kennwort / api_key: token secret",
		`https://hooks.slack.com/services/x  postgres://u:p@h/db  -----BEGIN`,
	}
	for _, txt := range texts {
		low := strings.ToLower(txt)
		got := d.keywordsPresent(low)
		for i, kw := range d.allKW { // naive reference
			want := strings.Contains(low, kw)
			if got[i] != want {
				t.Errorf("keyword %q: AC=%v contains=%v in %q", kw, got[i], want, txt)
			}
		}
	}
}
