package detect

import (
	"context"
	"encoding/base64"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

func TestShortBase64AccessKey(t *testing.T) {
	d := newDetector(t)
	const key = "\x41KIANAFGYOEYPXU1DSYP"
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		blob := enc.EncodeToString([]byte(key))
		for _, prefix := range []string{"api_key = \"", "password is ", "😀 auth: \""} {
			matches, limited := d.ScanCtxWithStatus(context.Background(), prefix+blob+"\"")
			found := false
			for _, m := range matches {
				if m.Type == "aws_access_key_id" && m.Stage == "L1-base64" && m.Value == key {
					found = true
					if len(m.DecodeSpans) != 1 || m.DecodeSpans[0].Start != len(prefix) || strings.TrimRight((prefix + blob)[m.DecodeSpans[0].Start:m.DecodeSpans[0].End], "=") != strings.TrimRight(blob, "=") {
						t.Fatal("short decoded secret lost its complete outer range")
					}
				}
			}
			if limited || !found {
				t.Errorf("short encoded access key lost: encoded bytes=%d prefix=%s limited=%v", len(blob), prefix, limited)
			}
		}
	}
}

func TestShortBase64URLCustomType(t *testing.T) {
	const key = "OWNED_G7?J9kLm5pQ2"
	d := New(&taxonomy.Taxonomy{Types: []taxonomy.SecretType{{
		ID: "owned_short", Category: "cloud", RE: regexp.MustCompile(`OWNED_[A-Za-z0-9?>]{12}`),
	}}})
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		blob := enc.EncodeToString([]byte(key))
		matches, limited := d.ScanCtxWithStatus(context.Background(), "password is "+blob)
		if limited || len(matches) != 1 || matches[0].Type != "owned_short" || matches[0].Value != key || matches[0].Stage != "L1-base64" {
			t.Errorf("short custom typed blob lost: encoded bytes=%d matches=%d limited=%v", len(blob), len(matches), limited)
		}
	}
}

func TestStandardBase64SurvivesGenericCapAfterNoise(t *testing.T) {
	defer ApplyTuning(3.5, 4.2, 50000)
	ApplyTuning(3.5, 4.2, 2)
	d := newDetector(t)
	blob := base64.RawStdEncoding.EncodeToString([]byte("AWS_ACCESS_KEY_ID=\x41KIANAFGYOEYPXU1DSYP"))
	text := strings.Repeat("secret = \"aB3xQ9zP7mK2wL5vN8tR4yC6dF1gH0jKpQ9zP7mK\"\n", 20) + "password is " + blob
	matches, limited := d.ScanCtxWithStatus(context.Background(), text)
	if !limited || len(matches) > 2 {
		t.Fatal("combined cap or incomplete status was lost")
	}
	for _, m := range matches {
		if m.Type == "aws_access_key_id" && m.Stage == "L1-base64" {
			return
		}
	}
	t.Fatal("generic noise starved a later standard-alphabet typed blob")
}

func TestShortBase64DoesNotExpandGenericNoise(t *testing.T) {
	d := newDetector(t)
	blob := base64.RawStdEncoding.EncodeToString([]byte("ordinary benign one"))
	matches, limited := d.ScanCtxWithStatus(context.Background(), "auth: "+blob)
	if len(matches) != 0 || limited {
		t.Fatal("a short harmless Base64 blob became a generic finding")
	}
	// A union of both alphabets is not a canonical blob. Do not salvage its short prefix.
	blob = base64.RawStdEncoding.EncodeToString([]byte("\x41KIANAFGYOEYPXU1DSYP")) + "/_opaqueR4tV8wC6nF2b"
	for _, m := range d.Scan("password is " + blob) {
		if m.Stage == "L1-base64" {
			t.Fatal("mixed-alphabet noise was decoded as a short canonical prefix")
		}
	}
}

func TestBase64IndependentBudgetAndFilteredStatus(t *testing.T) {
	defer ApplyTuning(3.5, 4.2, 50000)
	ApplyTuning(3.5, 4.2, 2)
	full := base64.RawURLEncoding.EncodeToString([]byte("aws_secret??=" + base64URLTestKey))
	text := strings.Repeat("password is "+full+"\n", 2)
	candidates, limited := base64Candidates(context.Background(), text, scanStructure(text, 32).b64decodeRuns)
	if limited || len(candidates) != 2 || candidates[0].Value != full || candidates[1].Value != full {
		t.Fatal("partial standard-alphabet subspans consumed the full URL blob budget")
	}
	d := newDetector(t)
	harmless := base64.RawStdEncoding.EncodeToString([]byte("ordinary benign one"))
	key := base64.RawStdEncoding.EncodeToString([]byte("\x41KIANAFGYOEYPXU1DSYP"))
	text = "auth: " + harmless + "\nauth: " + harmless + "\nauth: " + key
	matches, limited := d.ScanCtxWithStatus(context.Background(), text)
	if !limited || len(matches) != 0 {
		t.Fatal("independent candidate limit became false clean after generic decoded hits were removed")
	}
}

func FuzzBase64DecodeRuns(f *testing.F) {
	for _, s := range []string{
		"", strings.Repeat("a", 15), strings.Repeat("Z", 16), strings.Repeat("Q", 17) + " ",
		"😀" + strings.Repeat("Q-", 40) + "\xff", strings.Repeat("A+_", 20),
		"auth: " + base64.RawStdEncoding.EncodeToString([]byte("\x41KIANAFGYOEYPXU1DSYP")),
		"auth: " + base64.RawURLEncoding.EncodeToString([]byte("aws_secret??="+base64URLTestKey)),
	} {
		f.Add(s)
	}
	d := fuzzDetector(f)
	runRE := regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}`)
	f.Fuzz(func(t *testing.T, text string) {
		want := scanStructure(text, 32)
		var scratch []byte
		got := d.acAndStructure(lowerScratch(&scratch, text), make([]bool, len(d.allKW)))
		if !reflect.DeepEqual(got, want) {
			t.Fatal("fused and standalone decode runs disagree")
		}
		var expected [][2]int
		for _, r := range runRE.FindAllStringIndex(text, -1) {
			val := text[r[0]:r[1]]
			if !(strings.ContainsAny(val, "+/") && strings.ContainsAny(val, "-_")) {
				expected = append(expected, [2]int{r[0], r[1]})
			}
		}
		if !reflect.DeepEqual(want.b64decodeRuns, expected) {
			t.Fatal("decoded candidates disagree with whole canonical alphabet runs")
		}
	})
}
