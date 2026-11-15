package detect

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func hexJWTWrap(text, chain string) string {
	for i := len(chain) - 1; i >= 0; i-- {
		if chain[i] == 'h' {
			text = hex.EncodeToString([]byte(text))
		} else {
			text = base64.RawURLEncoding.EncodeToString([]byte(text))
		}
	}
	return text
}

func TestHexJWTMixedProofsAndViews(t *testing.T) {
	d := newDetector(t)
	token := jwtFixture(`{"password":"` + jwtPasswordFixture + `","access_key":"AKIANAFGYOEYPXU1DSYP"}`)
	for _, chain := range []string{"h", "hh", "hhh", "hb", "bh", "hbh", "bhb", "bhbh", "bbbh"} {
		for _, upper := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", chain, upper), func(t *testing.T) {
				blob := hexJWTWrap(token, chain)
				if upper && chain[0] == 'h' {
					blob = strings.ToUpper(blob)
				}
				text := "note 🚀\nblob='" + blob + "'"
				var views []JWTPayloadView
				r := d.ScanWithStatus(t.Context(), text, ScanOptions{ObserveJWTPayload: func(v JWTPayloadView) { views = append(views, v) }})
				found := map[string]bool{}
				expected := []string{}
				for _, c := range chain {
					if c == 'h' {
						expected = append(expected, "hex-decode")
					} else {
						expected = append(expected, "base64-decode")
					}
				}
				expected = append(expected, "base64-decode")
				check := func(steps []DecodeStep) {
					t.Helper()
					if len(steps) != len(expected) {
						t.Fatalf("proof count %d, want %d", len(steps), len(expected))
					}
					for i, s := range steps {
						if !strings.HasPrefix(s.Transform, expected[i]) || s.Start < strings.Index(text, blob) || s.End > strings.Index(text, blob)+len(blob) || s.Start >= s.End {
							t.Fatal("invalid source proof", i, s)
						}
					}
					first := steps[0]
					var decoded []byte
					var err error
					if chain[0] == 'h' {
						decoded, err = hex.DecodeString(text[first.Start:first.End])
					} else {
						decoded, err = base64.RawURLEncoding.DecodeString(text[first.Start:first.End])
					}
					if err != nil || string(decoded) != hexJWTWrap(token, chain[1:]) {
						t.Fatal("outer proof does not decode its source")
					}
				}
				for _, m := range r.Matches {
					if !m.JWTPayload {
						continue
					}
					found[m.Value] = true
					check(m.ProofSteps())
					if m.DecodedText == "" || m.Start < strings.Index(text, blob) || m.End > len(text) || m.Start >= m.End {
						t.Fatal("lost decoded context/source")
					}
				}
				if !found[jwtPasswordFixture] || !found["AKIANAFGYOEYPXU1DSYP"] || r.Base64Limited || r.CandidateLimited || len(views) != 1 {
					t.Fatal("claims lost, duplicated or incomplete", len(found), len(views), r.Base64Limited, r.CandidateLimited)
				}
				check(views[0].DecodeSteps())
			})
		}
	}
}

func TestHexJWTDepthAndWorkCannotReset(t *testing.T) {
	d := newDetector(t)
	token := jwtFixture(`{"password":"` + jwtPasswordFixture + `"}`)
	for _, chain := range []string{"hhhh", "bhhhh", "hbbbb"} {
		r := d.ScanWithStatus(t.Context(), hexJWTWrap(token, chain), ScanOptions{})
		for _, m := range r.Matches {
			if m.Value == jwtPasswordFixture {
				t.Fatal("codec nesting reset depth", chain)
			}
		}
		if !r.Base64Limited {
			t.Fatal("depth rejection became complete", chain)
		}
	}
	for _, budget := range []*jwtPayloadBudget{{hexAttempts: maxJWTConstructs}, {hexWork: maxBase64Work}, {count: maxJWTPayloads}} {
		r := d.ScanWithStatus(t.Context(), hexJWTWrap(token, "h"), ScanOptions{jwtBudget: budget})
		for _, m := range r.Matches {
			if m.JWTPayload {
				t.Fatal("shared budget bypassed")
			}
		}
		if !r.Base64Limited {
			t.Fatal("resource rejection became complete")
		}
	}
	for _, input := range []string{`password="` + jwtPasswordFixture + `"`, jwtFixture(`not JSON`)} {
		for _, m := range d.Scan(hexJWTWrap(input, "h")) {
			if m.Value == jwtPasswordFixture {
				t.Fatal("hex without validated JWT enabled generic detection")
			}
		}
	}
	observed := 0
	r := d.ScanWithStatus(t.Context(), strings.Repeat(hexJWTWrap(token, "h")+"\n", maxJWTPayloads+1), ScanOptions{ObserveJWTPayload: func(JWTPayloadView) { observed++ }})
	if observed != maxJWTPayloads || !r.Base64Limited {
		t.Fatal("hex roots bypassed shared attempts", observed)
	}
}

func TestHexJWTNestedAndEscapedClaims(t *testing.T) {
	d := newDetector(t)
	child := hexJWTWrap(jwtFixture(`{"password":"`+jwtPasswordFixture+`"}`), "h")
	outer := jwtFixture(fmt.Sprintf(`{"nested":%q}`, child))
	escapedOuter := jwtFixture(`{"nested":"\u0036` + child[1:] + `"}`)
	for _, blob := range []string{outer, escapedOuter, hexJWTWrap(outer, "h"), hexJWTWrap(jwtFixture(`{"password":"R7v!K9pX2m\u0051"}`), "h")} {
		found := false
		for _, m := range d.Scan(blob) {
			if m.Value == jwtPasswordFixture {
				found = true
				for _, s := range m.ProofSteps() {
					if s.Start < 0 || s.Start >= s.End || s.End > len(blob) {
						t.Fatal("nested proof escaped source")
					}
				}
			}
		}
		if !found {
			t.Fatal("nested/escaped hex claim lost")
		}
	}
}

func TestHexJWTClaimsReplaceOnlyTheirCoarseDuplicate(t *testing.T) {
	d := newDetector(t)
	const key = "AKIANAFGYOEYPXU1DSYP"
	text := key + "\nblob='" + hexJWTWrap(jwtFixture(`{"access_key":"`+key+`"}`), "h") + "'"
	ordinary, claims := 0, 0
	for _, m := range d.Scan(text) {
		if m.Value != key {
			continue
		}
		if m.JWTPayload {
			claims++
		} else {
			ordinary++
		}
	}
	if ordinary != 1 || claims != 1 {
		t.Fatal("independent source occurrence collapsed or coarse duplicate survived", ordinary, claims)
	}
}

func FuzzHexJWTPayloadProofAndDepth(f *testing.F) {
	for i, note := range []string{"ordinary", "😀密码", "quotes\"\\\n"} {
		f.Add(note, uint8(i))
	}
	d := newDetector(f)
	chains := []string{"h", "hh", "hhh", "hb", "bh", "hbh", "bhbh", "hhhh", "hbbbb"}
	f.Fuzz(func(t *testing.T, note string, mode uint8) {
		if len(note) > 64 {
			return
		}
		payload, _ := json.Marshal(map[string]string{"note": note, "password": jwtPasswordFixture})
		chain := chains[int(mode)%len(chains)]
		text := "blob='" + hexJWTWrap(jwtFixture(string(payload)), chain) + "'"
		r := d.ScanWithStatus(t.Context(), text, ScanOptions{})
		found := false
		for _, m := range r.Matches {
			if m.Value == jwtPasswordFixture {
				found = true
			}
			for _, s := range m.ProofSteps() {
				if s.Start < 0 || s.Start >= s.End || s.End > len(text) {
					t.Fatal("proof escaped source")
				}
			}
		}
		bounded := chain != "hhhh" && chain != "hbbbb"
		if found != bounded || (!bounded && !r.Base64Limited) {
			t.Fatal("depth/claims contract changed", chain)
		}
	})
}
