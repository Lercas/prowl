package scan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/rules"
	bundledrules "github.com/Lercas/prowl/tool/rules"
)

func TestDecodedSecretIdentityEvidenceAndML(t *testing.T) {
	const value = "AKIANAFGYOEYPXU1DSYP"
	const second = "AKIAZ7M4Q9N2W8K5R3VX"
	blob := base64.StdEncoding.EncodeToString([]byte("first=" + value + "\nsecond=" + second))
	text := "direct=" + value + "\npayload=\"" + blob + "\"\npayload=\"" + blob + "\""
	eng, err := rules.LoadEmbedded(bundledrules.Files)
	if err != nil {
		t.Fatal(err)
	}
	ml, err := mlscore.NewEmbedded(.5, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, scorer := range []mlscore.Scorer{nil, ml} {
		ctx := WithOptions(context.Background(), Options{IdentityKey: []byte(strings.Repeat("k", 32))})
		fs := Findings(ctx, detector(t), eng, nil, model.Item{Path: "config.env", Text: text, Source: "code"}, nil, scorer)
		if len(fs) != 5 {
			t.Fatalf("raw + two decoded occurrences of two secrets: expected 5, got %d", len(fs))
		}
		ids, occurrences := map[string]bool{}, map[string]bool{}
		for _, f := range fs {
			ids[f.SecretID] = true
			occurrences[f.OccurrenceID] = true
			if strings.HasPrefix(f.Stage, "L1-base64") {
				if len(f.Evidence) != 1 || f.Evidence[0].Transform != "base64-decode" || text[f.Evidence[0].Start:f.Evidence[0].End] != blob || f.ByteStart < f.Evidence[0].Start || f.ByteEnd > f.Evidence[0].End {
					t.Fatal("encoded evidence is not the exact original blob")
				}
			}
		}
		if len(ids) != 2 || len(occurrences) != 5 {
			t.Fatal("decoded identity differs from plaintext or shared spans lost distinct occurrences")
		}
		raw, err := json.Marshal(fs)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), value) || strings.Contains(string(raw), second) || strings.Contains(string(raw), blob) {
			t.Fatal("decoded/source credentials leaked through redacted JSON")
		}
	}
}

func TestDecodedChecksumRetainsSeverityInCommentsAndFixtures(t *testing.T) {
	const value = "\x67hp_kP9aZ2bYwcX4dWqeV8fUmgThS6iRnj2XYtQi"
	blob := base64.StdEncoding.EncodeToString([]byte(value))
	for _, item := range []model.Item{
		{Path: "production.env", Text: "# payload=" + blob, Source: "code"},
		{Path: "fixtures/config.env", Text: "payload=" + blob, Source: "code"},
	} {
		fs := Findings(context.Background(), detector(t), nil, nil, item, nil, nil)
		if len(fs) != 1 || fs[0].Type != "github_pat_classic" || fs[0].Severity != "high" || fs[0].Stage != "L1-base64-checksum" {
			t.Fatal("Base64 transformation demoted a checksum-valid typed token")
		}
	}
}

func TestNestedAndRepeatedDecodedValuesKeepDistinctOriginalOccurrences(t *testing.T) {
	const raw = "AKIANAFGYOEYPXU1DSYP"
	eng, err := rules.LoadEmbedded(bundledrules.Files)
	if err != nil {
		t.Fatal(err)
	}
	ml, err := mlscore.NewEmbedded(.5, "")
	if err != nil {
		t.Fatal(err)
	}
	inner := base64.StdEncoding.EncodeToString([]byte("key=" + raw))
	for _, decoded := range []string{"first=" + raw + "\nsecond=" + raw, "first='" + inner + "'\nsecond='" + inner + "'"} {
		blob := base64.StdEncoding.EncodeToString([]byte(decoded))
		for _, scorer := range []mlscore.Scorer{nil, ml} {
			ctx := WithOptions(context.Background(), Options{IdentityKey: []byte(strings.Repeat("k", 32))})
			text := "payload='" + blob + "'"
			fs := Findings(ctx, detector(t), eng, nil, model.Item{Path: "production.env", Text: text, Source: "code"}, nil, scorer)
			if len(fs) != 2 || fs[0].SecretID != fs[1].SecretID || fs[0].OccurrenceID == fs[1].OccurrenceID || fs[0].ByteStart == fs[1].ByteStart {
				t.Fatal("repeated decoded values lost distinct source occurrences or canonical identity")
			}
			for _, f := range fs {
				if len(f.Evidence) < 1 || text[f.Evidence[0].Start:f.Evidence[0].End] != blob || f.ByteStart < f.Evidence[0].Start || f.ByteEnd > f.Evidence[0].End {
					t.Fatal("nested decoding proof escaped the original blob")
				}
				for _, e := range f.Evidence {
					if e.Start < 0 || e.End > len(text) || e.Start >= e.End {
						t.Fatal("nested decoding proof points into a synthetic document")
					}
				}
			}
			serialized, _ := json.Marshal(fs)
			if strings.Contains(string(serialized), raw) || strings.Contains(string(serialized), blob) {
				t.Fatal("nested decoding evidence leaked a credential or its encoding")
			}
		}
	}
}

func TestEncodedOccurrencesThroughAnAliasRetainDeclarationRegions(t *testing.T) {
	const raw = "AKIANAFGYOEYPXU1DSYP"
	blob := base64.StdEncoding.EncodeToString([]byte("first=" + raw + "\nsecond=" + raw))
	text := "value: &a '" + blob + "'\ncopy: *a\n"
	ctx := WithOptions(context.Background(), Options{IdentityKey: []byte(strings.Repeat("k", 32))})
	fs := Findings(ctx, detector(t), nil, nil, model.Item{Path: "production.yaml", Text: text}, nil, nil)
	if len(fs) != 4 {
		t.Fatal("encoded declarations/alias uses collapsed their inner occurrences")
	}
	ids, copies := map[string]bool{}, 0
	for _, f := range fs {
		ids[f.OccurrenceID] = true
		if text[f.ByteStart:f.ByteEnd] == "*a" {
			copies++
		}
	}
	if len(ids) != 4 || copies != 2 {
		t.Fatal("alias occurrence identity omitted its physical declaration region")
	}
}

func TestJWTStructureRetainedByMLWithoutAuthenticityClaim(t *testing.T) {
	const token = "\x65yJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmNkZWZnIn0.dozjgNryP4Jq3mNHl9wYZQ"
	for _, value := range []string{token, base64.StdEncoding.EncodeToString([]byte(token))} {
		fs := Findings(context.Background(), detector(t), nil, nil, model.Item{Path: "production.env", Text: "payload=" + value, Source: "code"}, nil, rejectingScorer{})
		if len(fs) != 1 || fs[0].Type != "jwt" || isChecksumProven(fs[0]) || fs[0].Verified != nil {
			t.Fatal("ML removed a structured JWT candidate or raised it to cryptographic/provider proof")
		}
	}
}

func TestYAMLScalarsHaveCanonicalValuesAndOriginalSpans(t *testing.T) {
	for _, c := range []struct{ text, value, source string }{
		{`{password: hunter2abc99}`, "hunter2abc99", "hunter2abc99"},
		{`[{password: Winter42, other: Autumn53}]`, "Winter42", "Winter42"},
		{"password: Winter42,Autumn53\n", "Winter42,Autumn53", "Winter42,Autumn53"},
		{`password: "two words with winter 42"`, "two words with winter 42", "two words with winter 42"},
		{`password: "  two words with winter 42"`, "  two words with winter 42", "  two words with winter 42"},
		{`password: ",;Winter42Autumn"`, ",;Winter42Autumn", ",;Winter42Autumn"},
		{`password: "Winter\u0034\u0032!Autumn"`, "Winter42!Autumn", `Winter\u0034\u0032!Autumn`},
		{`password: 'Winter42''Autumn53'`, "Winter42'Autumn53", "Winter42''Autumn53"},
		{`{пароль: "Winter\u0034\u0032!Autumn"}`, "Winter42!Autumn", `Winter\u0034\u0032!Autumn`},
		{"password: one two three four\n", "one two three four", "one two three four"},
		{"пароль: ЖукЖук\n", "ЖукЖук", "ЖукЖук"},
		{"password: &vaultKey \x57inter42Autumn53", "\x57inter42Autumn53", "\x57inter42Autumn53"},
		{"password: !!str \x57inter42Autumn53", "\x57inter42Autumn53", "\x57inter42Autumn53"},
		{"password: |\n  two words with winter 42\n", "two words with winter 42\n", "two words with winter 42\n"},
	} {
		fs := Findings(context.Background(), detector(t), nil, nil, model.Item{Path: "config.yaml", Text: c.text, Source: "code"}, nil, nil)
		if len(fs) != 1 || fs[0].Fingerprint != model.ComputeFingerprint("generic_password", "config.yaml", c.value) || c.text[fs[0].ByteStart:fs[0].ByteEnd] != c.source {
			t.Fatalf("YAML scalar lost canonical identity or source span: %q, findings=%d", c.text, len(fs))
		}
		if len(fs[0].Evidence) != 1 || fs[0].Evidence[0].Transform != "yaml-scalar" {
			t.Fatal("YAML scalar transformation evidence missing")
		}
	}
	for _, text := range []string{"password: *vaultKey", `password: "${PASSWORD}"`, `password: "abc"`, `пароль: "Жук"`, "password: {source: configuration}", "password: [Winter42, Autumn53]", "password: # commentText"} {
		if fs := Findings(context.Background(), detector(t), nil, nil, model.Item{Path: "config.yaml", Text: text, Source: "code"}, nil, nil); len(fs) != 0 {
			t.Fatalf("unsupported/nonliteral YAML construct reported as literal password: %q", text)
		}
	}
	// Braces and commas remain literal characters in .env files.
	const envValue = "Winter42}Autumn53,Spring64"
	fs := Findings(context.Background(), detector(t), nil, nil, model.Item{Path: "config.env", Text: "password=" + envValue, Source: "code"}, nil, nil)
	if len(fs) != 1 || fs[0].Fingerprint != model.ComputeFingerprint("generic_password", "config.env", envValue) {
		t.Fatal("YAML delimiters changed .env scalar semantics")
	}
}

func TestEncodingLimitsMakeScanIncomplete(t *testing.T) {
	for _, c := range []struct{ text, path, code string }{
		{strings.Repeat("A", 8193), "payload.env", "base64_limit"},
		{strings.Repeat("# comment\n", (1<<20)/10+1), "config.yaml", "yaml_scalar_limit"},
		{"{password: [", "config.yaml", "yaml_scalar_parse"},
	} {
		coverage := model.NewCoverage()
		ctx := model.WithCoverage(context.Background(), coverage)
		Findings(ctx, detector(t), nil, nil, model.Item{Path: c.path, Text: c.text, Source: "code"}, nil, nil)
		complete, _, diagnostics := coverage.Snapshot()
		if complete {
			t.Fatalf("%s did not mark the scan incomplete", c.code)
		}
		found := false
		for _, diagnostic := range diagnostics {
			found = found || diagnostic.Code == c.code
		}
		if !found {
			t.Fatalf("missing structured diagnostic %s", c.code)
		}
	}
}

func TestYAMLUnicodeFlowPositionsHaveBoundedCost(t *testing.T) {
	text := "[" + strings.Repeat("{пароль: hunter2abc99},", 9000) + "]"
	started := time.Now()
	scalars := yamlPasswordScalars(context.Background(), model.Item{Text: text, Path: "dense.yaml"})
	if time.Since(started) > 5*time.Second {
		t.Fatal("YAML position mapping repeatedly walked a dense line prefix")
	}
	if len(scalars) != 18000 { // password keys and their scalar values
		t.Fatalf("source scalar inventory changed: %d", len(scalars))
	}
	for start, scalar := range scalars {
		if text[start:scalar.End] != scalar.Value {
			t.Fatal("YAML rune columns were used as byte offsets")
		}
	}
}

func TestBarePasswordsOnOneLineKeepAllOccurrences(t *testing.T) {
	text := strings.Repeat("password=hunter2abc99 ", 100)
	fs := Findings(context.Background(), detector(t), nil, nil, model.Item{Text: text, Path: "config.env", Source: "code"}, nil, nil)
	if len(fs) != 100 {
		t.Fatalf("scalar nomination swallowed later assignments: %d findings", len(fs))
	}
}
