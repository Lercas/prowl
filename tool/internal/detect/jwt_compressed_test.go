package detect

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// The chain is outer-to-inner; transports and compression retain distinct proofs.
func compressedJWTWrap(t testing.TB, text, chain string) string {
	t.Helper()
	for i := len(chain) - 1; i >= 0; i-- {
		switch chain[i] {
		case 'b':
			text = base64.RawURLEncoding.EncodeToString([]byte(text))
		case 'h':
			text = hex.EncodeToString([]byte(text))
		case 'g', 'z':
			text = string(compressedFixture(t, text, chain[i] == 'g'))
		default:
			t.Fatal("unknown fixture codec")
		}
	}
	return text
}

func TestCompressedJWTClaimsAndSourceProof(t *testing.T) {
	d := newDetector(t)
	token := jwtFixture(`{"password":"` + jwtPasswordFixture + `","access_key":"AKIANAFGYOEYPXU1DSYP"}`)
	for _, chain := range []string{"bg", "bz", "hg", "hz", "bbg", "hbg", "bgh", "bgz", "bgg", "bggg", "bgbz", "bghz", "hgbz"} {
		t.Run(chain, func(t *testing.T) {
			blob := compressedJWTWrap(t, token, chain)
			text := "note 🚀\nblob='" + blob + "'"
			var views []JWTPayloadView
			r := d.ScanWithStatus(t.Context(), text, ScanOptions{ObserveJWTPayload: func(v JWTPayloadView) { views = append(views, v) }})
			expected := []string{}
			for _, c := range chain {
				expected = append(expected, map[rune]string{'b': "base64-decode", 'h': "hex-decode", 'g': "gzip-inflate", 'z': "zlib-inflate"}[c])
			}
			expected = append(expected, "base64-decode")
			check := func(steps []DecodeStep) {
				t.Helper()
				if len(steps) != len(expected) {
					t.Fatal("incorrect proof count", len(steps), len(expected))
				}
				for i, s := range steps {
					if !strings.HasPrefix(s.Transform, expected[i]) || s.Start < strings.Index(text, blob) || s.Start >= s.End || s.End > strings.Index(text, blob)+len(blob) {
						t.Fatal("wrong order or virtual source interval", i, s)
					}
				}
				// The first inflate step must point at an entire decodable source stream.
				data := []byte(text[steps[0].Start:steps[0].End])
				var err error
				for _, c := range chain {
					switch c {
					case 'b':
						data, err = base64.RawURLEncoding.DecodeString(string(data))
					case 'h':
						data, err = hex.DecodeString(string(data))
					case 'g', 'z':
						var ok, limited bool
						data, ok, limited = inflateStatus(data)
						if !ok || limited {
							t.Fatal("source proof did not name an intact stream")
						}
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				if string(data) != token {
					t.Fatal("source proof lost the container")
				}
			}
			found := map[string]bool{}
			for _, m := range r.Matches {
				if !m.JWTPayload {
					continue
				}
				found[m.Value] = true
				check(m.ProofSteps())
				if m.Start < 0 || m.Start >= m.End || m.End > len(text) || m.DecodedText == "" {
					t.Fatal("lost source or ML context")
				}
			}
			if !found[jwtPasswordFixture] || !found["AKIANAFGYOEYPXU1DSYP"] || r.Base64Limited || r.CandidateLimited || len(views) != 1 {
				t.Fatal("claims lost or incomplete", len(found), len(views), r.Base64Limited)
			}
			check(views[0].DecodeSteps())
		})
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		blob := encoding.EncodeToString(compressedFixture(t, token, true))
		found := false
		for _, m := range d.Scan(blob) {
			found = found || m.Value == jwtPasswordFixture
		}
		if !found {
			t.Fatal("transport alphabet lost compressed JWT")
		}
	}
}

func TestCompressedJWTPhysicalCacheAndSharedLimits(t *testing.T) {
	d := newDetector(t)
	token := jwtFixture(`{"password":"` + jwtPasswordFixture + `"}`)
	nested := compressedJWTWrap(t, token, "bg")
	for _, text := range []string{token + "\n" + token, nested + "\n" + nested} {
		observed := 0
		r := d.ScanWithStatus(t.Context(), compressedJWTWrap(t, text, "bg"), ScanOptions{ObserveJWTPayload: func(JWTPayloadView) { observed++ }})
		if observed != 2 || r.Base64Limited {
			t.Fatal("coarse stream coordinates collapsed distinct JWT containers", observed)
		}
	}
	for _, chain := range []string{"bgggg", "bgbgbgbg", "hghghghg"} {
		r := d.ScanWithStatus(t.Context(), compressedJWTWrap(t, token, chain), ScanOptions{})
		for _, m := range r.Matches {
			if m.Value == jwtPasswordFixture {
				t.Fatal("mixed-codec path reset nesting", chain)
			}
		}
		if !r.Base64Limited {
			t.Fatal("depth failure became complete", chain)
		}
	}
	for _, budget := range []*jwtPayloadBudget{{inflateBytes: maxJWTInflateWork}, {inflateAttempts: maxJWTConstructs}, {inflateBytes: maxJWTInflateWork - 1}, {count: maxJWTPayloads}} {
		r := d.ScanWithStatus(t.Context(), compressedJWTWrap(t, token, "bg"), ScanOptions{jwtBudget: budget})
		for _, m := range r.Matches {
			if m.JWTPayload {
				t.Fatal("shared resource budget bypassed")
			}
		}
		if !r.Base64Limited {
			t.Fatal("resource failure became complete")
		}
	}
	observed := 0
	r := d.ScanWithStatus(t.Context(), compressedJWTWrap(t, strings.Repeat(token+"\n", maxJWTPayloads+1), "bg"), ScanOptions{ObserveJWTPayload: func(JWTPayloadView) { observed++ }})
	if observed != maxJWTPayloads || !r.Base64Limited {
		t.Fatal("stream bypassed shared JWT attempts", observed)
	}
	for _, codec := range []string{"bg", "bz", "hg", "hz"} {
		for _, m := range d.Scan(compressedJWTWrap(t, `password="`+jwtPasswordFixture+`"`, codec)) {
			if m.Value == jwtPasswordFixture {
				t.Fatal("non-JWT compression enabled generic detection")
			}
		}
	}
}

func TestCompressedJWTIntegrityAndInflateBoundary(t *testing.T) {
	d := newDetector(t)
	token := jwtFixture(`{"password":"` + jwtPasswordFixture + `"}`)
	for _, gzipFormat := range []bool{false, true} {
		good := compressedFixture(t, token, gzipFormat)
		damaged := append([]byte(nil), good...)
		damaged[len(damaged)-1] ^= 1
		for _, data := range [][]byte{damaged, good[:len(good)-3], compressedFixture(t, token+strings.Repeat(" ", maxInflateBytes), gzipFormat)} {
			blob := base64.RawURLEncoding.EncodeToString(data)
			r := d.ScanWithStatus(t.Context(), blob, ScanOptions{})
			if !r.Base64Limited {
				t.Fatal("compressed integrity or omitted tail became complete")
			}
		}
		for _, size := range []int{maxInflateBytes - 1, maxInflateBytes} {
			data := compressedFixture(t, token+strings.Repeat(" ", size-len(token)), gzipFormat)
			r := d.ScanWithStatus(t.Context(), base64.RawURLEncoding.EncodeToString(data), ScanOptions{})
			found := false
			for _, m := range r.Matches {
				found = found || m.Value == jwtPasswordFixture
			}
			if !found || r.Base64Limited {
				t.Fatal("valid boundary stream lost claims or completeness", size)
			}
		}
	}
	first := compressedFixture(t, "ordinary\n", true)
	multi := append(first, compressedFixture(t, token, true)...)
	found := false
	for _, m := range d.Scan(base64.RawURLEncoding.EncodeToString(multi)) {
		found = found || m.Value == jwtPasswordFixture
	}
	if !found {
		t.Fatal("later gzip member lost JWT")
	}
}

func FuzzCompressedJWTPayloadProofAndDepth(f *testing.F) {
	for i, note := range []string{"ordinary", "😀密码", "quotes\"\\\n"} {
		f.Add(note, uint8(i))
	}
	d := newDetector(f)
	chains := []string{"bg", "bz", "hg", "hz", "bgbz", "bghz", "bgz", "bggg", "bgggg"}
	f.Fuzz(func(t *testing.T, note string, mode uint8) {
		if len(note) > 64 {
			return
		}
		payload, _ := json.Marshal(map[string]string{"note": note, "password": jwtPasswordFixture})
		chain := chains[int(mode)%len(chains)]
		blob := compressedJWTWrap(t, jwtFixture(string(payload)), chain)
		text := "note 🚀\nblob='" + blob + "'"
		r := d.ScanWithStatus(t.Context(), text, ScanOptions{})
		found := false
		for _, m := range r.Matches {
			found = found || m.Value == jwtPasswordFixture
			for _, s := range m.ProofSteps() {
				if s.Start < 0 || s.Start >= s.End || s.End > len(text) {
					t.Fatal("source proof escaped original file")
				}
			}
		}
		if found != (chain != "bgggg") || chain == "bgggg" && !r.Base64Limited {
			t.Fatal("claims/depth contract changed", chain)
		}
	})
}
