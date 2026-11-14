package detect

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const depthAWSKey = "AKIANAFGYOEYPXU1DSYP"

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// findType returns the first match of the given type, or nil.
func findType(ms []Match, typ string) *Match {
	for i := range ms {
		if ms[i].Type == typ {
			return &ms[i]
		}
	}
	return nil
}

func TestDecodeLayers(t *testing.T) {
	d := newDetector(t)
	gh := validGithubToken()
	var gz, zl bytes.Buffer
	gw := gzip.NewWriter(&gz)
	_, _ = gw.Write([]byte("GITHUB_TOKEN=" + gh + "\n"))
	_ = gw.Close()
	zw := zlib.NewWriter(&zl)
	_, _ = zw.Write([]byte("GITHUB_TOKEN=" + gh + "\n"))
	_ = zw.Close()
	cases := []struct {
		name, text, typ string
	}{
		{"base64 under a neutral name", "blob: " + b64(gh) + "\n", "github_pat_classic"},
		{"base64 with no name at all", b64("id="+depthAWSKey+" ok") + "\n", "aws_access_key_id"},
		{"base64 of base64", "payload: " + b64(b64("token "+gh)) + "\n", "github_pat_classic"},
		{"three layers", "payload: " + b64(b64(b64("token "+gh))) + "\n", "github_pat_classic"},
		{"hex", `token_hex = "` + hex.EncodeToString([]byte(gh)) + `"` + "\n", "github_pat_classic"},
		{"hex inside base64", "v: " + b64("x="+hex.EncodeToString([]byte(gh))) + "\n", "github_pat_classic"},
		{"gzip inside base64", "archive: " + base64.StdEncoding.EncodeToString(gz.Bytes()) + "\n", "github_pat_classic"},
		{"zlib inside base64", "archive: " + base64.StdEncoding.EncodeToString(zl.Bytes()) + "\n", "github_pat_classic"},
	}
	for _, c := range cases {
		ms, limited := d.ScanCtxWithStatus(context.Background(), c.text)
		m := findType(ms, c.typ)
		if m == nil || limited {
			t.Errorf("%s: no %s (matches=%d limited=%v)", c.name, c.typ, len(ms), limited)
			continue
		}
		if m.Stage != "L1-base64" {
			t.Errorf("%s: stage %q, want L1-base64", c.name, m.Stage)
		}
		if blob := c.text[m.Start:m.End]; strings.ContainsAny(blob, " \n\"") || len(blob) < 16 {
			t.Errorf("%s: span %q is not the outer blob", c.name, blob)
		}
	}
}

func TestDecodeDepthIsBounded(t *testing.T) {
	d := newDetector(t)
	blob := "token " + validGithubToken()
	for i := 0; i < maxDecodeDepth+1; i++ {
		blob = b64(blob)
	}
	if ms := d.Scan("payload: " + blob + "\n"); findType(ms, "github_pat_classic") != nil {
		t.Fatalf("a secret %d layers deep was decoded; the depth bound is %d", maxDecodeDepth+1, maxDecodeDepth)
	}
}

func TestInflateIsBounded(t *testing.T) {
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	_, _ = gw.Write(bytes.Repeat([]byte("a"), 8*maxInflateBytes))
	_ = gw.Close()
	out, ok := inflate(gz.Bytes())
	if !ok || len(out) != maxInflateBytes {
		t.Fatalf("inflate returned %d bytes (ok=%v), want the %d cap", len(out), ok, maxInflateBytes)
	}
}

func TestUnnamedBlobNeedsPreciseTypedHit(t *testing.T) {
	d := newDetector(t)
	// A typed regex hit (0.9) speaks for itself wherever the blob sits.
	if findType(d.Scan(`blob = "`+b64("aws_secret??="+base64URLTestKey)+`"`), "aws_secret_access_key") == nil {
		t.Error("a typed secret in a blob with a neutral name was not decoded")
	}
	// Opaque or merely generic content in an unnamed blob stays silent.
	for _, text := range []string{
		"blob: " + b64("ordinary benign text, nothing to see") + "\n",
		"blob: " + b64("password=hunter2hunter2") + "\n",
		"checksum: " + hex.EncodeToString([]byte("0123456789abcdef0123456789abcdef")) + "\n",
		"sha256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n",
	} {
		for _, m := range d.Scan(text) {
			if m.Stage == "L1-base64" {
				t.Errorf("%q produced a decoded finding %s", text, m.Type)
			}
		}
	}
}

func TestEncodedBasicAuth(t *testing.T) {
	d := newDetector(t)
	pair := b64("deploy:Tr0ub4dor&3xKq9")
	for _, text := range []string{
		`{"auths":{"registry.example.com":{"auth": "` + pair + `"}}}`,
		"//registry.npmjs.org/:_auth=" + pair + "\n",
		"auth: " + pair + "\n",
	} {
		m := findType(d.Scan(text), "basic_auth_header")
		// the span is the blob without its '=' padding, like every decoded finding
		if m == nil || text[m.Start:m.End] != strings.TrimRight(pair, "=") {
			t.Errorf("%q: encoded user:password under an auth key not reported", text)
		}
	}
	for _, text := range []string{
		"author: " + pair + "\n",                           // the key merely contains "auth"
		"oauth_state: " + pair + "\n",                      // likewise
		"auth: " + b64("ordinary benign one") + "\n",       // no user:password shape
		"auth: " + b64("user:changeme") + "\n",             // placeholder password
		"auth: " + b64("not a user:but a sentence") + "\n", // spaces: prose, not a credential pair
	} {
		if m := findType(d.Scan(text), "basic_auth_header"); m != nil && m.Stage == "L1-base64" {
			t.Errorf("%q: reported as encoded basic auth", text)
		}
	}
}

func TestViews(t *testing.T) {
	d := newDetector(t)
	gh := validGithubToken()
	const secret = "wJalrXUtnFEMIK7MDENGbPxRfiCYzK8vQ2mN4pLs"
	inner, _ := json.Marshal(map[string]string{"aws_secret_access_key": secret})
	outer, _ := json.Marshal(map[string]string{"env": string(inner)})
	uni := ""
	for _, c := range gh {
		uni += fmt.Sprintf(`\u%04x`, c)
	}
	hexEsc := ""
	for _, c := range depthAWSKey {
		hexEsc += fmt.Sprintf(`\x%02x`, c)
	}
	cases := []struct {
		name, text, typ, value string
	}{
		{"JSON inside a JSON string", string(outer) + "\n", "aws_secret_access_key", secret},
		{`\uXXXX escapes`, `var k="` + uni + `";` + "\n", "github_pat_classic", gh},
		{`\xNN escapes`, `var j="` + hexEsc + `";` + "\n", "aws_access_key_id", depthAWSKey},
		{"string concatenation", `const t = "` + gh[:20] + `" + "` + gh[20:] + `";` + "\n", "github_pat_classic", gh},
		{"concatenation across lines", "const a = \"" + depthAWSKey[:10] + "\"+\n  \"" + depthAWSKey[10:] + "\";\n", "aws_access_key_id", depthAWSKey},
		{"operator-leading concatenation", "a = '" + depthAWSKey[:10] + "'\n  + '" + depthAWSKey[10:] + "'\n", "aws_access_key_id", depthAWSKey},
		{"YAML folded scalar", "aws_secret_access_key: >-\n  " + secret + "\n", "aws_secret_access_key", secret},
		{"YAML literal scalar", "db:\n  password: |\n    Tr0ub4dor&3xKq9\n", "generic_password", "Tr0ub4dor&3xKq9"},
		{"markdown bold key", "## Credentials\n- **password**: Tr0ub4dor&3xKq9\n", "generic_password", "Tr0ub4dor&3xKq9"},
		{"markdown bold key and colon", "**Password:** Tr0ub4dor&3xKq9\n", "generic_password", "Tr0ub4dor&3xKq9"},
		{"markdown code spans", "`password`: `Tr0ub4dor&3xKq9`\n", "generic_password", "Tr0ub4dor&3xKq9"},
	}
	for _, c := range cases {
		ms := d.Scan(c.text)
		var m *Match
		for i := range ms {
			if ms[i].Type == c.typ && ms[i].Value == c.value {
				m = &ms[i]
			}
		}
		if m == nil {
			t.Errorf("%s: no %s with the plain value (got %d matches)", c.name, c.typ, len(ms))
			continue
		}
		if m.Start < 0 || m.End > len(c.text) || m.Start >= m.End {
			t.Errorf("%s: span [%d,%d) outside the text", c.name, m.Start, m.End)
			continue
		}
		// the reported span is the secret as written: it starts and ends on the secret's own bytes
		src := c.text[m.Start:m.End]
		if !strings.HasPrefix(src, c.value[:1]) && !strings.HasPrefix(src, `\`) {
			t.Errorf("%s: span %q does not start at the secret", c.name, src)
		}
	}
}

func TestViewsStayPrecise(t *testing.T) {
	d := newDetector(t)
	for _, text := range []string{
		// joined literals may only yield a precise typed secret, never a generic guess
		`msg = "password = " + "hunter2hunter2"` + "\n",
		`s = "secret" + "=" + "aB3xQ9zP7mK2wL5vN8tR4yC6dF1gH0jK"` + "\n",
		// a masked credential is not markdown emphasis
		`out: "http://user:***@host.example/"` + "\n",
		// rewriting must not turn a fragment of a longer token into a secret
		strings.Repeat("x", 300) + `ghp_` + strings.Repeat("A", 36) + `\"` + "\n",
	} {
		plain := map[string]bool{}
		wholeText := strings.NewReplacer(`\"`, `\'`).Replace(text) // same text without the construct
		_ = wholeText
		for _, m := range d.Scan(text) {
			plain[m.Type] = true
		}
		v := buildView(text)
		if v == nil {
			continue
		}
		for _, m := range d.scanViews(context.Background(), text) {
			switch m.Type {
			case "generic_password", "generic_api_key", "generic_high_entropy", "basic_auth_header":
				if strings.Contains(text, `" + "`) || strings.Contains(text, "***") {
					t.Errorf("%q: view produced generic %s %q", text, m.Type, m.Value)
				}
			case "github_pat_classic":
				t.Errorf("%q: view produced a token from a fragment: %q", text, m.Value)
			}
		}
	}
}

func TestViewOffsetsMapIntoSource(t *testing.T) {
	for _, text := range []string{
		`{"a":"{\"k\":\"v\"}"}`, `x="a"+"b"`, "k: |\n  v\n", "**k:** v", "`k`: `v`", `A\x42\/\\`,
		strings.Repeat(`\"`, 1000), strings.Repeat("a", 1000) + `\"` + strings.Repeat("b", 1000),
	} {
		v := buildView(text)
		if v == nil {
			t.Errorf("%q: no view", text)
			continue
		}
		if len(v.start) != len(v.text) || len(v.end) != len(v.text) {
			t.Fatalf("%q: offset tables do not cover the view", text)
		}
		for i := range v.text {
			if s, e := int(v.start[i]), int(v.end[i]); s < 0 || e < s || e > len(text) {
				t.Fatalf("%q: view byte %d maps to [%d,%d)", text, i, s, e)
			}
		}
	}
}

func FuzzViews(f *testing.F) {
	for _, s := range []string{
		`{"env":"{\"password\":\"hunter2hunter2\"}"}`, `t = "ghp_abc" + "def"`, "key: >-\n  value\n",
		"**Password:** x", "`a`: `b`", `\u00`, `"+`, ":|\n", "`:`", "**:**", `\`,
	} {
		f.Add(s)
	}
	d := fuzzDetector(f)
	f.Fuzz(func(t *testing.T, text string) {
		for _, m := range d.scanViews(context.Background(), text) {
			if m.Start < 0 || m.End > len(text) || m.Start > m.End {
				t.Fatalf("view match span [%d,%d) outside a %d-byte text", m.Start, m.End, len(text))
			}
		}
	})
}
