package detect

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

func TestBase64JWTKeepsClaimsAndOuterProof(t *testing.T) {
	d := newDetector(t)
	token := jwtFixture(`{"password":"` + jwtPasswordFixture + `","access_key":"AKIANAFGYOEYPXU1DSYP"}`)
	unwrapped := "xx>xx?\n" + token // forces '+'/'/' versus '-'/'_' in the first wrapper
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		for layers := 1; layers <= 3; layers++ {
			blob := unwrapped
			for i := 0; i < layers; i++ {
				blob = encoding.EncodeToString([]byte(blob))
			}
			text := "note 🚀\nblob=" + blob
			r := d.ScanWithStatus(t.Context(), text, ScanOptions{})
			found := map[string]bool{}
			for _, m := range r.Matches {
				if !m.JWTPayload {
					continue
				}
				found[m.Value] = true
				if len(m.DecodeSpans) != layers+1 || m.DecodedText == "" || m.Start < strings.Index(text, blob) || m.End > len(text) || m.Start >= m.End {
					t.Fatal("missing logical context or invalid composed span", layers)
				}
				outer := m.DecodeSpans[0]
				decoded, err := encoding.DecodeString(text[outer.Start:outer.End])
				if err != nil {
					t.Fatal("outer proof is not the source Base64 encoding")
				}
				for i := 1; i < layers; i++ {
					decoded, err = encoding.DecodeString(string(decoded))
					if err != nil {
						t.Fatal(err)
					}
				}
				if string(decoded) != unwrapped {
					t.Fatal("outer proof lost its JWT source")
				}
				for _, span := range m.DecodeSpans {
					if span.Start < 0 || span.Start >= span.End || span.End > len(text) {
						t.Fatal("proof escaped original source")
					}
				}
			}
			if !found[jwtPasswordFixture] || !found["AKIANAFGYOEYPXU1DSYP"] || r.CandidateLimited || r.Base64Limited {
				t.Fatal("wrapped JWT lost children or became incomplete", layers, len(found))
			}
		}
	}
}

func TestBase64JWTDepthAndAttemptBudgetCannotReset(t *testing.T) {
	d := newDetector(t)
	token := jwtFixture(`{"password":"` + jwtPasswordFixture + `"}`)
	for i := 0; i < 4; i++ {
		token = base64.RawURLEncoding.EncodeToString([]byte(token))
	}
	r := d.ScanWithStatus(t.Context(), token, ScanOptions{})
	for _, m := range r.Matches {
		if m.Value == jwtPasswordFixture {
			t.Fatal("outer Base64 reset the proof depth")
		}
	}
	if !r.Base64Limited {
		t.Fatal("over-depth wrapped claims became complete")
	}
	token = jwtFixture(`{"password":"` + jwtPasswordFixture + `"}`)
	for i := 0; i < 3; i++ {
		token = jwtFixture(fmt.Sprintf(`{"nested":%q}`, token))
	}
	r = d.ScanWithStatus(t.Context(), token, ScanOptions{})
	for _, m := range r.Matches {
		if m.Value == jwtPasswordFixture {
			t.Fatal("alternate Base64 route reset the JWT depth")
		}
	}
	if !r.Base64Limited {
		t.Fatal("over-depth JWT nesting became complete")
	}
	token = base64.RawURLEncoding.EncodeToString([]byte(jwtFixture(`{"password":"` + jwtPasswordFixture + `"}`)))
	observed := 0
	r = d.ScanWithStatus(t.Context(), strings.Repeat(token+"\n", maxJWTPayloads+1), ScanOptions{ObserveJWTPayload: func(JWTPayloadView) { observed++ }})
	if observed != maxJWTPayloads || !r.Base64Limited {
		t.Fatal("wrapped roots bypassed the shared payload attempt budget", observed)
	}
}

func TestJWTClaimsIsolationSurvivesDisabledContainerAndEscapedDuplicates(t *testing.T) {
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	var types []taxonomy.SecretType
	for _, st := range tax.Types {
		if st.ID != "jwt" {
			types = append(types, st)
		}
	}
	d := New(&taxonomy.Taxonomy{Types: types})
	for _, wrapped := range []bool{false, true} {
		token := jwtFixture(`{"access_key":"AKIANAFGYOEYPXU1DSYP"}`)
		if wrapped {
			token = base64.RawURLEncoding.EncodeToString([]byte(token))
		}
		found := false
		for _, m := range d.Scan(token) {
			if m.Value == "AKIANAFGYOEYPXU1DSYP" {
				found = true
				if !m.JWTPayload {
					t.Fatal("ordinary duplicate erased claims binding isolation", wrapped)
				}
			}
		}
		if !found {
			t.Fatal("disabled JWT output hid a payload child")
		}
	}
	token := jwtFixture(`{"password":"` + jwtPasswordFixture + `"}`)
	escaped := `\u0065` + token[1:]
	outer := jwtFixture(`{"first":"` + escaped + `","second":"` + escaped + `"}`)
	starts := map[int]bool{}
	for _, m := range d.Scan(outer) {
		if m.Value == jwtPasswordFixture {
			starts[m.Start] = true
		}
	}
	if len(starts) != 2 {
		t.Fatal("observer-free escaped origins collapsed distinct occurrences", len(starts))
	}
}

func FuzzBase64JWTPayloadProofAndDepth(f *testing.F) {
	for i, note := range []string{"ordinary", "😀密码", "quotes\"\\\n", "# prowl:allow"} {
		f.Add(note, uint8(i))
	}
	d := newDetector(f)
	f.Fuzz(func(t *testing.T, note string, mode uint8) {
		if len(note) > 64 {
			return
		}
		payload, _ := json.Marshal(map[string]string{"note": note, "password": jwtPasswordFixture})
		token := jwtFixture(string(payload))
		layers := int(mode) % 5
		encodings := []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding}
		enc := encodings[int(mode)/5%len(encodings)]
		blob := token
		for i := 0; i < layers; i++ {
			blob = enc.EncodeToString([]byte(blob))
		}
		text := "note 🚀\nblob='" + blob + "'"
		r := d.ScanWithStatus(t.Context(), text, ScanOptions{})
		found := false
		for _, m := range r.Matches {
			if m.Value != jwtPasswordFixture {
				continue
			}
			found = true
			if !m.JWTPayload || len(m.DecodeSpans) != layers+1 || m.Start < 0 || m.Start >= m.End || m.End > len(text) {
				t.Fatal("claims lost identity or composed source bounds")
			}
			for _, span := range m.DecodeSpans {
				if span.Start < 0 || span.Start >= span.End || span.End > len(text) {
					t.Fatal("proof outside original source")
				}
			}
		}
		if layers < 4 && !found {
			t.Fatal("valid bounded wrapper hid password")
		}
		if layers == 4 && (found || !r.Base64Limited) {
			t.Fatal("outer encoding reset proof depth or coverage")
		}
	})
}
