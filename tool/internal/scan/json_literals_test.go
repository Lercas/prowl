package scan

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/secretindex"
)

func escapedJSON(value string) string {
	var out strings.Builder
	for _, u := range utf16.Encode([]rune(value)) {
		fmt.Fprintf(&out, `\u%04x`, u)
	}
	return out.String()
}

func TestJSONCanonicalValuesIdentityAndSourceSpans(t *testing.T) {
	for _, c := range []struct{ name, value, typ string }{
		{"password", "Winter42!Autumn", "generic_password"},
		{"пароль", "ЖукЖук🚀", "generic_password"},
		{"password", "\"Winter42\"\nAutumn\\53", "generic_password"},
		{"password", "Winter<42>Autumn", "generic_password"},
		{"password", "Winter${42}Autumn", "generic_password"},
		{"password", "Winter{{42}}Autumn", "generic_password"},
		{"api_key", "AKIANAFGYOEYPXU1DSYP", "aws_access_key_id"},
		{"token", "sk_live_Q5t7U9i2O4p6A8s0D3f5G7h9", "stripe_secret_key"},
	} {
		t.Run(c.name+"/"+c.typ+"/"+escapedJSON(c.value), func(t *testing.T) {
			for _, scored := range []bool{false, true} {
				scorer := &tableRecordScorer{}
				opts := Options{Detector: detector(t), RevealSecrets: true}
				if scored {
					opts.ML = scorer
				}
				p := New(opts)
				raw := escapedJSON(c.value)
				text := "{\"" + escapedJSON(c.name) + "\":\"" + raw + "\"}"
				item := model.Item{Path: "production.json", Source: "code", Text: text}
				fs := p.Findings(t.Context(), item)
				if len(fs) != 1 || fs[0].Type != c.typ || fs[0].Redacted != c.value {
					t.Fatalf("canonical credential lost: %+v", fs)
				}
				f := fs[0]
				if text[f.ByteStart:f.ByteEnd] != raw || f.Fingerprint != model.ComputeFingerprint(c.typ, item.Path, c.value) || f.Context != nil || f.Col != strings.Index(text, raw)+1 {
					t.Fatal("identity, source span or disclosure policy changed")
				}
				if len(f.Evidence) != 1 || f.Evidence[0].Transform != "json-string" || text[f.Evidence[0].Start:f.Evidence[0].End] != raw {
					t.Fatal("original source evidence missing")
				}
				if scored && (len(scorer.records) != 1 || scorer.records[0].Value != c.value) {
					t.Fatal("ML did not receive the exact logical value")
				}
				plain, _ := json.Marshal(map[string]string{c.name: c.value})
				item.Text = string(plain)
				other := p.Findings(t.Context(), item)
				if len(other) != 1 || other[0].Fingerprint != f.Fingerprint {
					t.Fatal("escape spelling changed identity")
				}
				opts.RevealSecrets = false
				masked := New(opts).Findings(t.Context(), item)
				encoded, _ := json.Marshal(masked)
				if len(masked) != 1 || strings.Contains(string(encoded), c.value) || strings.Contains(string(encoded), raw) {
					t.Fatal("redacted report leaked canonical or encoded value")
				}
			}
		})
	}
}

func TestJSONPragmasDuplicatesAndCanonicalAllowlist(t *testing.T) {
	const value = "AKIANAFGYOEYPXU1DSYP"
	raw := escapedJSON(value)
	text := `{"note":"prowl:allow","key":"` + raw + `","key":"` + raw + `"}`
	it := model.Item{Path: "production.json", Source: "code", Text: text}
	fs := New(Options{Detector: detector(t)}).Findings(t.Context(), it)
	if len(fs) != 3 || fs[0].Fingerprint != fs[1].Fingerprint || fs[0].ByteStart == fs[1].ByteStart || !model.IsIncompleteFinding(fs[2]) {
		t.Fatalf("duplicates or data pragma lost: %+v", fs)
	}
	calls := 0
	p := New(Options{Detector: detector(t), Allow: func(v, path string) bool {
		calls++
		if v != value || path != it.Path {
			t.Fatal("allowlist received source spelling or wrong locator")
		}
		return true
	}})
	fs = p.Findings(t.Context(), it)
	if calls != 2 || len(fs) != 1 || !model.IsIncompleteFinding(fs[0]) {
		t.Fatal("allowlist hid parser uncertainty or lost canonical values")
	}
}

func TestJSONPlaceholdersBindingsAndMalformedInput(t *testing.T) {
	for _, c := range []struct{ name, value string }{
		{"password", "${PASSWORD}"}, {"password", "{{PASSWORD}}"}, {"password", "<PASSWORD>"},
		{"password", "example"}, {"password", "abc"}, {"bypass", "Winter42!Autumn"},
		{"password\"fake", "Winter42!Autumn"},
	} {
		text := `{"` + escapedJSON(c.name) + `":"` + escapedJSON(c.value) + `"}`
		if fs := New(Options{Detector: detector(t)}).Findings(t.Context(), model.Item{Path: "production.json", Text: text}); len(fs) != 0 {
			t.Fatalf("fabricated binding or placeholder became credential: %+v", fs)
		}
	}
	for _, text := range []string{`{"password":"Winter42\ud800Autumn"}`, `{"password":"Winter42\udc00Autumn"}`, `{"password":`, strings.Repeat(" ", 1<<20+1)} {
		fs := New(Options{Detector: detector(t), Allow: func(string, string) bool { return true }}).Findings(t.Context(), model.Item{Path: "production.json", Text: text})
		if len(fs) != 1 || !model.IsIncompleteFinding(fs[0]) {
			t.Fatal("invalid or bounded JSON reported as complete")
		}
	}
}

func TestJSONIndexAndVerificationObservationUseOriginalCoordinates(t *testing.T) {
	id, err := secretindex.LoadIdentity(filepath.Join(t.TempDir(), "index"), true)
	if err != nil {
		t.Fatal(err)
	}
	const value = "AKIANAFGYOEYPXU1DSYP"
	raw := escapedJSON(value)
	it := model.Item{Source: "code", Path: "prod/" + raw + ".json", Text: "{\n\"🚀key\":\"" + raw + "\"\n}"}
	p := New(Options{Detector: detector(t), ValueFingerprint: id.Fingerprint, LocationFingerprint: id.Location})
	fs := p.Findings(t.Context(), it)
	if len(fs) != 1 {
		t.Fatalf("unexpected findings: %+v", fs)
	}
	f := fs[0]
	if f.Line != 2 || f.Col != len(`"🚀key":"`)+1 || f.UTF16Col != f.Col-2 || f.IndexLocationID != id.Location(it.Source, it.Path, f.Line, f.Col) || f.ValueFingerprint != id.Fingerprint(value) || strings.Contains(f.IndexPath, raw) {
		t.Fatal("logical value, physical source coordinates or index privacy lost")
	}
}

func TestJSONEmbeddedMLReceivesTypedCanonicalValue(t *testing.T) {
	t.Setenv("PROWL_HOME", t.TempDir())
	ml, err := mlscore.NewEmbedded(.3, "")
	if err != nil {
		t.Fatal(err)
	}
	const value = "AKIANAFGYOEYPXU1DSYP"
	fs := New(Options{Detector: detector(t), ML: ml}).Findings(t.Context(), model.Item{Path: "production.json", Text: `{"api_key":"` + escapedJSON(value) + `"}`})
	if len(fs) != 1 || fs[0].Type != "aws_access_key_id" {
		t.Fatal("embedded ML lost normalized typed credential")
	}
}
