package detect

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

const jwtPasswordFixture = "R7v!K9pX2mQ"
const jwtAWSFixture = "AKIANAFGYOEYPXU1DSYP"

func jwtFixture(payload string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".q7Mn9Jk3Qw5Er8Ty2Ui6Op4As1Df0Gh9"
}

func TestJWTContainerRetainsTypedAndNamedPayloadCredentials(t *testing.T) {
	git := validGithubToken()
	payload := fmt.Sprintf(`{"access_key":"%s","github_token":"%s","password":"%s","sub":"v9N7jQ3mX8kP4wZ2rT6yU5bA1sD0fG9h"}`, jwtAWSFixture, git, jwtPasswordFixture)
	token := jwtFixture(payload)
	text := "prefix 🚀\ntoken='" + token + "'\n"
	r := newDetector(t).ScanWithStatus(t.Context(), text, ScanOptions{})
	if r.CandidateLimited || r.Base64Limited {
		t.Fatal("complete JWT became incomplete")
	}
	seen := map[string]int{}
	for _, m := range r.Matches {
		seen[m.Value]++
		if m.Value == token {
			if m.JWTPayload {
				t.Fatal("container marked as its own descendant")
			}
			continue
		}
		if !m.JWTPayload || !strings.HasPrefix(m.Stage, "L1-jwt-payload") || len(m.DecodeSpans) != 1 || m.Start >= m.End || m.End > len(text) || m.Start < strings.Index(text, token)+strings.IndexByte(token, '.')+1 {
			t.Fatal("invalid payload source range")
		}
		proof := m.DecodeSpans[0]
		decoded, err := base64.RawURLEncoding.DecodeString(text[proof.Start:proof.End])
		if err != nil || string(decoded) != payload || m.Start < proof.Start || m.End > proof.End || m.DecodedText == "" {
			t.Fatal("lost original payload/context evidence")
		}
		if m.Type == "generic_password" && m.ChecksumValid {
			t.Fatal("generic payload inherited JWT structural proof")
		}
	}
	for _, value := range []string{token, jwtAWSFixture, git, jwtPasswordFixture} {
		if seen[value] != 1 {
			t.Fatalf("expected one occurrence, got %d", seen[value])
		}
	}
	if len(seen) != 4 {
		t.Fatal("unbound claim identifier became a credential", len(seen))
	}
}

func TestJWTExampleContainerDoesNotHideRealPayloadSecret(t *testing.T) {
	token := jwtFixture(`{"name":"John Doe","password":"` + jwtPasswordFixture + `"}`)
	ms := newDetector(t).Scan(token)
	if len(ms) != 1 || ms[0].Value != jwtPasswordFixture || !ms[0].JWTPayload {
		t.Fatal("example-token filtering hid an independent secret", len(ms))
	}
}

func TestJWTPayloadDoesNotRequireJWTOutputType(t *testing.T) {
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	for i := range tax.Types {
		if tax.Types[i].ID == "jwt" {
			tax.Types = append(tax.Types[:i], tax.Types[i+1:]...)
			break
		}
	}
	ms := New(tax).Scan(jwtFixture(`{"password":"` + jwtPasswordFixture + `"}`))
	if len(ms) != 1 || ms[0].Type != "generic_password" || ms[0].Value != jwtPasswordFixture {
		t.Fatal("JWT output disablement hid payload credential", len(ms))
	}
}

func TestJWTPayloadEscapesDuplicatesAndNestedContainers(t *testing.T) {
	for _, payload := range []string{
		`{"pa\u0073sword":"R7v!K9pX2mQ"}`,
		`{"password":"R7v!K9pX2mQ","password":"N4q!B8xZ6rT"}`,
		fmt.Sprintf(`{"nested":"%s"}`, jwtFixture(`{"password":"R7v!K9pX2mQ"}`)),
	} {
		r := newDetector(t).ScanWithStatus(t.Context(), jwtFixture(payload), ScanOptions{})
		if r.CandidateLimited {
			t.Fatal("bounded valid claims became incomplete")
		}
		found := false
		for _, m := range r.Matches {
			if m.Value == jwtPasswordFixture {
				found = m.JWTPayload && len(m.DecodeSpans) > 0
			}
		}
		if !found {
			t.Fatal("escaped/duplicate/nested payload secret lost")
		}
	}
}

func TestJWTPayloadWhitespaceHeadersUnsignedAndJWEScope(t *testing.T) {
	d := newDetector(t)
	for _, header := range []string{`{ "alg":"HS256" }`, " \r\n\t{\"alg\":\"none\"}"} {
		text := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(" \n{\"password\":\""+jwtPasswordFixture+"\"}")) + "."
		ms, limited := d.jwtPayloadFindings(t.Context(), text, nil, ScanOptions{})
		if limited || len(ms) != 1 || ms[0].Value != jwtPasswordFixture {
			t.Fatal("standard JSON whitespace/unsigned claims hidden")
		}
	}
	for _, text := range []string{jwtFixture(`{"password":"R7v!K9pX2mQ"}`) + ".extra.segments", "Code.Information.Debug"} {
		ms, limited := d.jwtPayloadFindings(t.Context(), text, nil, ScanOptions{})
		if limited || len(ms) != 0 {
			t.Fatal("non-JWS container misinterpreted")
		}
	}
}

func TestJWTPayloadEscapedCredentialsHaveExactLogicalValues(t *testing.T) {
	for _, value := range []string{"R7v!\"K9pX2mQ", "R7v!\nK9pX2mQ", "R7v!\\K9pX2mQ", "R7v!😀K9pX2mQ"} {
		payload := fmt.Sprintf(`{"password":%q}`, value)
		r := newDetector(t).ScanWithStatus(t.Context(), jwtFixture(payload), ScanOptions{})
		found := 0
		for _, m := range r.Matches {
			if m.Type == "generic_password" {
				found++
				if m.Value != value {
					t.Fatal("reported JSON spelling/prefix instead of logical password")
				}
			}
		}
		if found != 1 || r.CandidateLimited {
			t.Fatal("escaped logical password missing", found)
		}
	}
	text := jwtFixture(`{"password":"R7v!\ud83d\ude00K9pX2mQ"}`)
	found := false
	for _, m := range newDetector(t).Scan(text) {
		if m.Type == "generic_password" {
			found = m.Value == "R7v!😀K9pX2mQ"
		}
	}
	if !found {
		t.Fatal("surrogate pair was not decoded into the logical password")
	}
}

func TestJWTEscapedAPIKeyAndScalarLimit(t *testing.T) {
	const value = "Q7mN9xP3tR5vW8zA2sD6fG4hJ1kL0uB\"next"
	payload := fmt.Sprintf(`{"api_key":%q}`, value)
	found := 0
	for _, m := range newDetector(t).Scan(jwtFixture(payload)) {
		if m.Type == "generic_api_key" {
			found++
			if m.Value != value {
				t.Fatal("escaped API key prefix reported")
			}
		}
	}
	if found != 1 {
		t.Fatal("logical API key missing")
	}
	payload = `{"notes":[` + strings.Repeat(`"\n",`, maxJWTEscapedScalars) + `"\n"]}`
	r := newDetector(t).ScanWithStatus(t.Context(), jwtFixture(payload), ScanOptions{})
	if !r.CandidateLimited || !r.Base64Limited {
		t.Fatal("escaped scalar budget failed open")
	}
}

func TestJWTHeaderPrefixPreservesAllJSONInitialBytes(t *testing.T) {
	for first := 0; first < 256; first++ {
		for second := 0; second < 256; second++ {
			encoded := base64.RawURLEncoding.EncodeToString([]byte{byte(first), byte(second)})
			want := first == '{' || first == ' ' || first == '\r' || first == '\n' || first == '\t'
			if jwtHeaderPrefix(encoded[0], encoded[1]) != want {
				t.Fatal("base64 prefix omitted a valid JSON initial byte")
			}
		}
	}
}

func TestJWTPayloadBoundsRemainIncomplete(t *testing.T) {
	deep := jwtFixture(`{"password":"` + jwtPasswordFixture + `"}`)
	for i := 0; i < maxJWTPayloadDepth+1; i++ {
		deep = jwtFixture(fmt.Sprintf(`{"nested":%q}`, deep))
	}
	for _, text := range []string{
		jwtFixture(`{"password":"` + jwtPasswordFixture + `"`),
		jwtFixture(`{"password":"\ud800"}`),
		jwtFixture(`{"padding":"` + strings.Repeat("x", maxBase64Blob) + `"}`),
		strings.Repeat(jwtFixture(`{"sub":"neutral-person"}`)+"\n", maxJWTPayloads+1),
		deep,
	} {
		r := newDetector(t).ScanWithStatus(t.Context(), text, ScanOptions{})
		if !r.CandidateLimited || !r.Base64Limited {
			t.Fatal("uninspected payload became clean")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, _ := newDetector(t).jwtPayloadFindings(ctx, jwtFixture(`{"password":"`+jwtPasswordFixture+`"}`), nil, ScanOptions{}); len(got) != 0 {
		t.Fatal("canceled payload scan continued")
	}
}

func FuzzJWTPayloadSourceMapping(f *testing.F) {
	d := newDetector(f)
	f.Add(`{"password":"R7v!K9pX2mQ"}`)
	f.Add(`{"access_key":"AKIANAFGYOEYPXU1DSYP"}`)
	f.Add(`{"pa\u0073sword":"R7v!K9pX2mQ"}`)
	f.Fuzz(func(t *testing.T, payload string) {
		if len(payload) > 8192 {
			return
		}
		text := jwtFixture(payload)
		ms, _ := d.jwtPayloadFindings(t.Context(), text, nil, ScanOptions{})
		for _, m := range ms {
			if !m.JWTPayload || m.Start < 0 || m.Start >= m.End || m.End > len(text) || len(m.DecodeSpans) == 0 || len(m.DecodeSpans) > maxBase64Depth {
				t.Fatal("invalid source/depth")
			}
			for _, span := range m.DecodeSpans {
				if span.Start < 0 || span.End > len(text) || span.Start > m.Start || span.End < m.End {
					t.Fatal("proof escaped source")
				}
			}
		}
	})
}
