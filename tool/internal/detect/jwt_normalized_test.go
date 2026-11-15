package detect

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
	"strings"
	"testing"
)

func normalizedJWTFixture(token, kind string) (string, string) {
	switch kind {
	case "escape":
		return `\u0065` + token[1:], "text-normalize"
	case "hex-escape":
		return `\x65` + token[1:], "text-normalize"
	case "percent":
		return strings.ReplaceAll(token, ".", "%2E"), "percent-html-decode"
	case "html":
		return strings.ReplaceAll(token, ".", "&#46;"), "percent-html-decode"
	case "concat":
		return token[:18] + `" + "` + token[18:], "text-normalize"
	}
	return token, ""
}

func TestNormalizedJWTClaimsAndWholeSourceProof(t *testing.T) {
	d := newDetector(t)
	for _, long := range []bool{false, true} {
		note := ""
		if long {
			note = strings.Repeat("ordinary", 150)
		}
		token := jwtFixture(fmt.Sprintf(`{"password":%q,"access_key":"AKIANAFGYOEYPXU1DSYP","note":%q}`, jwtPasswordFixture, note))
		for _, kind := range []string{"escape", "hex-escape", "percent", "html", "concat", "charcode"} {
			t.Run(fmt.Sprintf("%s-%t", kind, long), func(t *testing.T) {
				blob, transform := normalizedJWTFixture(token, kind)
				if kind == "charcode" {
					blob = charCodeFixture(token, "spread")
					transform = "charcode-decode"
				}
				text := "note 🚀\nblob='" + blob + "'"
				var views []JWTPayloadView
				r := d.ScanWithStatus(t.Context(), text, ScanOptions{ObserveJWTPayload: func(v JWTPayloadView) { views = append(views, v) }})
				check := func(steps []DecodeStep) {
					t.Helper()
					if len(steps) != 2 || steps[0].Transform != transform || steps[1].Transform != "base64-decode" {
						t.Fatal("normalization/decode proof lost", len(steps))
					}
					first := steps[0]
					if first.Start != strings.Index(text, blob) || first.End != first.Start+len(blob) {
						t.Fatal("normalization did not name the whole source carrier", kind, first)
					}
					for _, s := range steps {
						if s.Start < 0 || s.Start >= s.End || s.End > len(text) {
							t.Fatal("virtual coordinates in proof")
						}
					}
				}
				found := map[string]bool{}
				for _, m := range r.Matches {
					if !m.JWTPayload {
						continue
					}
					found[m.Value] = true
					check(m.ProofSteps())
					if m.DecodedText == "" || m.Start < 0 || m.Start >= m.End || m.End > len(text) {
						t.Fatal("lost context or mapping")
					}
				}
				if !found[jwtPasswordFixture] || !found["AKIANAFGYOEYPXU1DSYP"] || r.Base64Limited || r.CandidateLimited || len(views) != 1 {
					t.Fatal("normalized JWT lost claims or completeness", len(found), len(views), r.Base64Limited, r.CandidateLimited)
				}
				check(views[0].DecodeSteps())
			})
		}
	}
}

func TestNormalizedJWTComposesWithTransportAndCompression(t *testing.T) {
	d := newDetector(t)
	token := jwtFixture(`{"password":"` + jwtPasswordFixture + `"}`)
	for _, kind := range []string{"escape", "percent", "html", "concat"} {
		inner, _ := normalizedJWTFixture(token, kind)
		for _, chain := range []string{"b", "h", "bg", "hg", "bgbz"} {
			blob := compressedJWTWrap(t, inner, chain)
			found := false
			r := d.ScanWithStatus(t.Context(), blob, ScanOptions{})
			for _, m := range r.Matches {
				if m.Value != jwtPasswordFixture {
					continue
				}
				found = true
				for _, s := range m.ProofSteps() {
					if s.Start < 0 || s.Start >= s.End || s.End > len(blob) {
						t.Fatal("composed proof escaped source")
					}
				}
			}
			if !found || r.Base64Limited || r.CandidateLimited {
				t.Fatal("encoded normalized carrier lost claims", kind, chain, r.Base64Limited)
			}
			// Escaping the first byte must preserve its actual logical value, not force 'e'.
			raw := compressedJWTWrap(t, token, chain)
			outer := fmt.Sprintf(`\u%04x`, raw[0]) + raw[1:]
			found = false
			for _, m := range d.Scan(outer) {
				found = found || m.Value == jwtPasswordFixture
			}
			if !found {
				t.Fatal("normalized outer transport lost claims", chain)
			}
		}
	}
}

func TestNormalizedJWTPreservesPhysicalPositionsAndLimits(t *testing.T) {
	d := newDetector(t)
	token := jwtFixture(`{"password":"` + jwtPasswordFixture + `"}`)
	observed := 0
	blob := charCodeFixture(token+"\n"+token, "apply")
	r := d.ScanWithStatus(t.Context(), blob, ScanOptions{ObserveJWTPayload: func(JWTPayloadView) { observed++ }})
	if observed != 2 || r.Base64Limited {
		t.Fatal("coarse numeric source collapsed distinct containers", observed)
	}
	for _, budget := range []*jwtPayloadBudget{{viewBytes: maxViewBytes}, {viewConstructs: maxViewConstructs}, {count: maxJWTPayloads}} {
		raw, _ := normalizedJWTFixture(token, "percent")
		r := d.ScanWithStatus(t.Context(), raw, ScanOptions{jwtBudget: budget})
		for _, m := range r.Matches {
			if m.JWTPayload {
				t.Fatal("shared view/JWT budget bypassed")
			}
		}
		if !r.Base64Limited && !r.CandidateLimited {
			t.Fatal("resource failure became complete")
		}
	}
	raw, _ := normalizedJWTFixture(token, "escape")
	r = d.ScanWithStatus(t.Context(), raw, ScanOptions{jwtViewDepth: maxDecodeDepth})
	for _, m := range r.Matches {
		if m.JWTPayload {
			t.Fatal("view depth reset")
		}
	}
	if !r.Base64Limited && !r.CandidateLimited {
		t.Fatal("view depth rejection became complete")
	}
	twice := strings.ReplaceAll(token, ".", "%252E")
	for _, m := range d.Scan(twice) {
		if m.Value == jwtPasswordFixture {
			t.Fatal("percent decoding recursively interpreted its own output")
		}
	}
	for _, kind := range []string{"percent", "html", "escape"} {
		bad := jwtFixture(`{"password":"` + jwtPasswordFixture + `"`)
		raw, _ := normalizedJWTFixture(bad, kind)
		r := d.ScanWithStatus(t.Context(), raw, ScanOptions{})
		if !r.Base64Limited && !r.CandidateLimited {
			t.Fatal("normalized malformed JSON became complete", kind)
		}
	}
}

func FuzzNormalizedJWTPayloadProofAndDepth(f *testing.F) {
	for i, note := range []string{"ordinary", "😀密码", "quotes\"\\\n"} {
		f.Add(note, uint8(i))
	}
	d := newDetector(f)
	kinds := []string{"escape", "hex-escape", "percent", "html", "concat", "charcode"}
	f.Fuzz(func(t *testing.T, note string, mode uint8) {
		if len(note) > 64 {
			return
		}
		payload, _ := json.Marshal(map[string]string{"note": note, "password": jwtPasswordFixture})
		token := jwtFixture(string(payload))
		kind := kinds[int(mode)%len(kinds)]
		blob, _ := normalizedJWTFixture(token, kind)
		if kind == "charcode" {
			blob = charCodeFixture(token, "hex")
		}
		if mode&8 != 0 {
			blob = base64.RawURLEncoding.EncodeToString([]byte(blob))
		}
		text := "blob='" + blob + "'"
		r := d.ScanWithStatus(t.Context(), text, ScanOptions{})
		found := false
		for _, m := range r.Matches {
			found = found || m.Value == jwtPasswordFixture
			for _, s := range m.ProofSteps() {
				if s.Start < 0 || s.Start >= s.End || s.End > len(text) {
					t.Fatal("source proof escaped input")
				}
			}
		}
		if !found || r.Base64Limited || r.CandidateLimited {
			t.Fatal("bounded normalized JWT lost claims or completeness", kind)
		}
	})
}

func TestNormalizedJWTNestedEscapedBindingKeepsGenericChildWhenContainerDisabled(t *testing.T) {
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
	token := jwtFixture(`{"password":"` + jwtPasswordFixture + `"}`)
	for _, name := range []string{"token", "password", "script"} {
		nested, _ := normalizedJWTFixture(token, "percent")
		outer := jwtFixture(fmt.Sprintf(`{"\u%04x%s":%q}`, name[0], name[1:], nested))
		found := false
		for _, m := range d.Scan(outer) {
			found = found || m.Value == jwtPasswordFixture && m.JWTPayload
		}
		if !found {
			t.Fatal("escaped outer binding replaced a validated claims child", name)
		}
	}
}
