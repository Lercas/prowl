package scan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
	bundledrules "github.com/Lercas/prowl/tool/rules"
)

func TestReleasedJSONCanonicalMLIdentityAndSourceSpans(t *testing.T) {
	eng, err := rules.LoadEmbedded(bundledrules.Files)
	if err != nil {
		t.Fatal(err)
	}
	ml, err := mlscore.NewEmbedded(.3, filepath.Join("..", "mlmodel", "model_binary_go_literal_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, value, typ string }{
		{"password", "Winter42!Autumn", "generic_password"},
		{"пароль", "ЖукЖук🚀", "generic_password"},
		{"password", "\"Winter42\"\nAutumn\\53", "generic_password"},
		{"password", "Winter<42>Autumn", "generic_password"},
		{"password", "Winter${42}Autumn", "generic_password"},
		{"password", "Winter{{42}}Autumn", "generic_password"},
		{"api_key", "\x41KIANAFGYOEYPXU1DSYP", "aws_access_key_id"},
		{"token", "\x73k_live_Q5t7U9i2O4p6A8s0D3f5G7h9", "stripe_secret_key"},
	} {
		for _, scorer := range []mlscore.Scorer{nil, ml} {
			raw := escapedJSON(c.value)
			text := "{\"" + escapedJSON(c.name) + "\":\"" + raw + "\"}"
			ctx := context.Background()
			p := New(Options{Detector: detector(t), Rules: eng, ML: scorer, IdentityKey: []byte(strings.Repeat("k", 32)), AllOccurrences: true})
			item := model.Item{Path: "production.json", Text: text, Source: "code"}
			fs := p.Findings(ctx, item)
			if len(fs) != 1 || fs[0].Type != c.typ || text[fs[0].ByteStart:fs[0].ByteEnd] != raw {
				t.Fatalf("canonical JSON credential/type/source span lost for %s: %+v", c.name, fs)
			}
			plain, _ := json.Marshal(map[string]string{c.name: c.value})
			// Compare identities against the canonical value directly; plaintext JSON may itself
			// need normalization for control characters and escaped quotes.
			other := p.Findings(ctx, model.Item{Path: item.Path, Text: string(plain), Source: item.Source})
			if len(other) != 1 || fs[0].SecretID != other[0].SecretID || fs[0].Fingerprint != other[0].Fingerprint {
				t.Fatal("lexical escape spelling changed secret identity")
			}
			if len(fs[0].Evidence) != 1 || fs[0].Evidence[0].Transform != "json-string" || fs[0].Context != nil {
				t.Fatal("original transformation evidence missing or synthetic context exposed")
			}
			serialized, _ := json.Marshal(fs)
			if strings.Contains(string(serialized), c.value) || strings.Contains(string(serialized), raw) {
				t.Fatal("raw or canonical value leaked through redacted output")
			}
		}
	}
}

func TestJSONDuplicatesPragmasAndCanonicalAllowlist(t *testing.T) {
	const value = "\x41KIANAFGYOEYPXU1DSYP"
	raw := escapedJSON(value)
	text := "{\"note\":\"\\u0070rowl:allow\",\"key\":\"" + raw + "\",\"key\":\"" + raw + "\"}"
	ctx := context.Background()
	p := New(Options{Detector: detector(t), IdentityKey: []byte(strings.Repeat("k", 32)), AllOccurrences: true})
	item := model.Item{Path: "production.json", Text: text, Source: "code"}
	fs := p.Findings(ctx, item)
	if len(fs) != 3 || !model.IsIncompleteFinding(fs[2]) {
		t.Fatal("duplicate-key uncertainty was hidden")
	}
	fs = fs[:2]
	if len(fs) != 2 || fs[0].SecretID != fs[1].SecretID || fs[0].OccurrenceID == fs[1].OccurrenceID {
		t.Fatal("duplicate JSON keys lost occurrences or decoded text manufactured an allow pragma")
	}
	calls := 0
	allow := func(raw, path string) bool {
		calls++
		if raw != value || path != item.Path {
			t.Fatal("allowlist received lexical spelling or wrong source path")
		}
		return true
	}
	cov := model.NewCoverage()
	if fs := New(Options{Detector: detector(t), Allow: allow, AllOccurrences: true}).Findings(model.WithCoverage(ctx, cov), item); len(fs) != 1 || !model.IsIncompleteFinding(fs[0]) || calls != 2 || !model.NewResult(nil, cov).Filtered {
		t.Fatal("canonical allowlist suppression lost filtering evidence")
	}
	item.Text = strings.Replace(text, "\\u0070rowl:allow", "prowl:allow", 1)
	if fs := p.Findings(ctx, item); len(fs) != 3 || !model.IsIncompleteFinding(fs[2]) {
		t.Fatal("ordinary JSON string manufactured an operator allow pragma")
	}
}

func TestJSONEscapedPlaceholdersAndNonBindings(t *testing.T) {
	for _, c := range []struct{ name, value string }{
		{"password", "${PASSWORD}"}, {"password", "{{PASSWORD}}"}, {"password", "<PASSWORD>"},
		{"password", "example"}, {"password", "abc"}, {"bypass", "Winter42!Autumn"},
		{"password\"fake", "Winter42!Autumn"},
	} {
		text := "{\"" + escapedJSON(c.name) + "\":\"" + escapedJSON(c.value) + "\"}"
		if fs := restoredFindings(context.Background(), detector(t), nil, nil, model.Item{Path: "production.json", Text: text}, nil, nil); len(fs) != 0 {
			t.Fatalf("placeholder or fabricated binding became a credential: %s", c.name)
		}
	}
}

func TestJSONComposedEncodingKeepsOriginalEvidence(t *testing.T) {
	const value = "\x41KIANAFGYOEYPXU1DSYP"
	blob := base64.StdEncoding.EncodeToString([]byte(value))
	raw := escapedJSON(blob)
	text := "{\"payload\":\"" + raw + "\"}"
	fs := restoredFindings(context.Background(), detector(t), nil, nil, model.Item{Path: "production.json", Text: text}, nil, nil)
	if len(fs) != 1 || len(fs[0].Evidence) != 2 {
		t.Fatal("JSON-to-Base64 composition lost the credential or its transformation chain")
	}
	for _, e := range fs[0].Evidence {
		if text[e.Start:e.End] != raw {
			t.Fatal("evidence offset points into synthetic decoded text")
		}
	}
}

func TestJSONRepeatedCredentialInsideOneStringKeepsPositions(t *testing.T) {
	const value = "\x41KIANAFGYOEYPXU1DSYP"
	raw := escapedJSON("first=" + value + " second=" + value)
	text := `{"note":"🚀","message":"` + raw + `"}`
	ctx := context.Background()
	p := New(Options{Detector: detector(t), IdentityKey: []byte(strings.Repeat("k", 32)), AllOccurrences: true})
	fs := p.Findings(ctx, model.Item{Path: "production.json", Text: text})
	if len(fs) != 2 || fs[0].OccurrenceID == fs[1].OccurrenceID || fs[0].SecretID != fs[1].SecretID {
		t.Fatal("inner occurrences collapsed onto their containing JSON string")
	}
	for _, finding := range fs {
		if text[finding.ByteStart:finding.ByteEnd] != escapedJSON(value) {
			t.Fatal("inner occurrence does not select its exact original escape sequence")
		}
	}
}

func TestJSONCredentialsInObjectKeysSurviveNormalization(t *testing.T) {
	const key = "\x41KIANAFGYOEYPXU1DSYP"
	for _, raw := range []string{key, escapedJSON(key)} {
		text := `{"` + raw + `":"not a secret","note":"\\t"}`
		fs := restoredFindings(context.Background(), detector(t), nil, nil, model.Item{Path: "production.json", Text: text}, nil, nil)
		if len(fs) != 1 || fs[0].Fingerprint != model.ComputeFingerprint("aws_access_key_id", "production.json", key) || text[fs[0].ByteStart:fs[0].ByteEnd] != raw {
			t.Fatal("a JSON key credential vanished or duplicated after another string was normalized")
		}
	}
}

func TestJSONTypedRulesRetainExistingCorpusRecall(t *testing.T) {
	raw, err := os.ReadFile("testdata/noise-1.4.0.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name, Text, Truth, Value string
		Types                    []string
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	eng, err := rules.LoadEmbedded(bundledrules.Files)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		if c.Truth != "positive" || len(c.Types) == 0 || taxonomy.GenericLast[c.Types[0]] {
			continue
		}
		text := `{"message":"` + escapedJSON(c.Text) + `"}`
		fs := restoredFindings(context.Background(), detector(t), eng, nil, model.Item{Path: "production.json", Text: text, Source: "code"}, nil, nil)
		found := false
		for _, f := range fs {
			for _, typ := range c.Types {
				found = found || f.Type == typ && f.Fingerprint == model.ComputeFingerprint(typ, "production.json", c.Value)
			}
		}
		if !found {
			t.Fatalf("existing typed rule lost canonical JSON recall: %s", c.Name)
		}
	}
}

func TestJSONLimitsAndInvalidUnicodeAreExplicit(t *testing.T) {
	for _, text := range []string{
		`{"password":"Winter42\uD800Autumn"}`, `{"password":"Winter42\uDC00Autumn"}`,
		`{"password":"Winter42\uD800\u0041"}`, `{"password":"Winter42\q"}`,
		`{"password":"\u0041` + strings.Repeat("x", 4096) + `"}`,
		`{"password":"\u0041","huge":"` + strings.Repeat("x", 1<<20) + `"}`,
	} {
		cov := model.NewCoverage()
		ctx := model.WithCoverage(context.Background(), cov)
		if doc := jsonLiteralsWithPublic(ctx, model.Item{Text: text, Path: "production.json"}, false); doc != nil {
			t.Fatal("invalid/lossy/unbounded JSON accepted as a canonical document")
		}
		complete, _, ds := cov.Snapshot()
		if complete || len(ds) == 0 {
			t.Fatal("JSON normalization failure could masquerade as a complete scan")
		}
	}
	if !validJSONSurrogates(`\uD83D\uDE80`) || !validJSONSurrogates(`\\uD800`) {
		t.Fatal("valid Unicode or literal backslash rejected")
	}
}

func TestJSONDensePositionsAndCancellationAreBounded(t *testing.T) {
	text := "[" + strings.Repeat(`{"пароль":"Winter\u0034\u0032"},`, 4000) + `{"password":"Autumn53"}]`
	started := time.Now()
	doc := jsonLiteralsWithPublic(context.Background(), model.Item{Text: text, Path: "production.json"}, false)
	if doc == nil || len(doc.values) != 8002 || time.Since(started) > 5*time.Second {
		t.Fatal("JSON positions repeatedly walked a dense Unicode source line")
	}
	for i, v := range doc.values {
		if doc.locate(v.preparedStart, v.preparedEnd) != &doc.values[i] || text[v.start:v.end] == "" {
			t.Fatal("source inventory is inconsistent")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if jsonLiteralsWithPublic(ctx, model.Item{Text: text, Path: "production.json"}, false) != nil {
		t.Fatal("cancelled JSON normalization continued")
	}
}
