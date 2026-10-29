package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/rules"
	bundledrules "github.com/Lercas/prowl/tool/rules"
)

func TestTOMLCanonicalPasswordsAndTypedCredentials(t *testing.T) {
	eng, err := rules.LoadEmbedded(bundledrules.Files)
	if err != nil {
		t.Fatal(err)
	}
	ml, err := mlscore.NewEmbedded(.5, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ text, value, typ, source string }{
		{`password = 'Winter42\'`, `Winter42\`, "generic_password", `Winter42\`},
		{"\ufeffpassword = 'Winter42!Autumn'", "Winter42!Autumn", "generic_password", "Winter42!Autumn"},
		{`password = "Winter\u0034\u0032!Autumn"`, "Winter42!Autumn", "generic_password", `Winter\u0034\u0032!Autumn`},
		{`password = 'Winter\u0034\u0032!Autumn'`, `Winter\u0034\u0032!Autumn`, "generic_password", `Winter\u0034\u0032!Autumn`},
		{`"\u0070assword" = "Winter42!Autumn"`, "Winter42!Autumn", "generic_password", "Winter42!Autumn"},
		{"password = \"\"\"\nWinter42!Autumn\nSpring53\"\"\"", "Winter42!Autumn\nSpring53", "generic_password", "Winter42!Autumn\nSpring53"},
		{"password = '''\nWinter42!Autumn\nSpring53'''", "Winter42!Autumn\nSpring53", "generic_password", "Winter42!Autumn\nSpring53"},
		{"password = \"\"\"Winter\\\n   42!Autumn\"\"\"", "Winter42!Autumn", "generic_password", "Winter\\\n   42!Autumn"},
		{"password = \"\"\"\r\nWinter42!Autumn\r\nSpring53\"\"\"", "Winter42!Autumn\r\nSpring53", "generic_password", "Winter42!Autumn\r\nSpring53"},
		{`password = "\"Winter42\"\\Autumn"`, `"Winter42"\Autumn`, "generic_password", `\"Winter42\"\\Autumn`},
		{`password = "Winter42\U0001F680Autumn"`, "Winter42🚀Autumn", "generic_password", `Winter42\U0001F680Autumn`},
		{`password = ''''Winter42!Autumn''''`, `'Winter42!Autumn'`, "generic_password", `'Winter42!Autumn'`},
		{`api_key = "\u0041\u004b\u0049\u0041NAFGYOEYPXU1DSYP"`, "\x41KIANAFGYOEYPXU1DSYP", "aws_access_key_id", `\u0041\u004b\u0049\u0041NAFGYOEYPXU1DSYP`},
		{`api_key = ["\u0041\u004b\u0049\u0041NAFGYOEYPXU1DSYP"]`, "\x41KIANAFGYOEYPXU1DSYP", "aws_access_key_id", `\u0041\u004b\u0049\u0041NAFGYOEYPXU1DSYP`},
		{`"\u0041\u004b\u0049\u0041NAFGYOEYPXU1DSYP" = "unrelated"`, "\x41KIANAFGYOEYPXU1DSYP", "aws_access_key_id", `\u0041\u004b\u0049\u0041NAFGYOEYPXU1DSYP`},
		{`auth = {password = "Winter\u0034\u0032!Autumn"}`, "Winter42!Autumn", "generic_password", `Winter\u0034\u0032!Autumn`},
		{`auth.password = "Winter\u0034\u0032!Autumn"`, "Winter42!Autumn", "generic_password", `Winter\u0034\u0032!Autumn`},
	} {
		for _, scorer := range []mlscore.Scorer{nil, ml} {
			ctx := WithOptions(context.Background(), Options{IdentityKey: []byte(strings.Repeat("k", 32))})
			fs := Findings(ctx, detector(t), eng, nil, model.Item{Path: "production.toml", Text: c.text, Source: "code"}, nil, scorer)
			if len(fs) != 1 || fs[0].Type != c.typ || fs[0].Fingerprint == "" || c.text[fs[0].ByteStart:fs[0].ByteEnd] != c.source {
				t.Fatalf("TOML value/type/span lost: %q, %+v", c.text, fs)
			}
			want := model.Finding{Type: c.typ}
			annotateIdentity(ctx, &want, c.value, model.Item{Path: "production.toml"})
			if fs[0].SecretID != want.SecretID || fs[0].Fingerprint != want.Fingerprint {
				t.Fatalf("TOML identity uses escape syntax rather than canonical value: %q", c.text)
			}
			serialized, _ := json.Marshal(fs)
			if strings.Contains(string(serialized), c.value) || strings.Contains(string(serialized), c.source) {
				t.Fatal("TOML findings disclosed literal source or canonical credentials")
			}
		}
	}
}

func TestTOMLNormalizationPreservesCommentsAndOccurrences(t *testing.T) {
	const key = "\x41KIANAFGYOEYPXU1DSYP"
	text := "# first=" + key + "\npassword='Winter42\\'\n# second=" + key + "\n"
	ctx := WithOptions(context.Background(), Options{IdentityKey: []byte(strings.Repeat("k", 32))})
	fs := Findings(ctx, detector(t), nil, nil, model.Item{Path: "production.toml", Text: text}, nil, nil)
	if len(fs) != 3 {
		t.Fatal("TOML normalization discarded comment credentials")
	}
	occurrences := map[string]bool{}
	for _, f := range fs {
		if occurrences[f.OccurrenceID] {
			t.Fatal("different TOML source occurrences were collapsed")
		}
		occurrences[f.OccurrenceID] = true
	}
	text = "# password='Winter42Autumn'\nnote='normal'\n"
	if fs := Findings(context.Background(), detector(t), nil, nil, model.Item{Path: "production.toml", Text: text}, nil, nil); len(fs) != 1 || fs[0].Severity != "low" {
		t.Fatal("literal password in a TOML comment vanished or lost comment severity")
	}
}

func TestTOMLTemplatesNonliteralAndCoverageBoundaries(t *testing.T) {
	for _, text := range []string{`password = "${PASSWORD}"`, `password = '{{PASSWORD}}'`, `password = '<PASSWORD>'`, `password = 'example'`, `password = 'abc'`, `password = true`, `password = 123456`, `password = ["Winter42!Autumn"]`, `bypass = "Winter42!Autumn"`, `password = {source="configuration"}`} {
		if fs := Findings(context.Background(), detector(t), nil, nil, model.Item{Path: "production.toml", Text: text}, nil, nil); len(fs) != 0 {
			t.Fatalf("TOML nonliteral/placeholder produced findings: %q", text)
		}
	}
	for _, text := range []string{`password="Winter42\uD800"`, `password="Winter42\q"`, `password='unclosed`, strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65), `password="` + strings.Repeat("x", 4097) + `"`, strings.Repeat("# comment\n", (1<<20)/10+1), `password='Winter42Autumn'` + "\n" + `password='Spring53Summer'`} {
		cov := model.NewCoverage()
		ctx := model.WithCoverage(context.Background(), cov)
		Findings(ctx, detector(t), nil, nil, model.Item{Path: "production.toml", Text: text}, nil, nil)
		complete, _, ds := cov.Snapshot()
		if complete || len(ds) == 0 {
			t.Fatalf("TOML parse/limit failure could certify a complete scan: %q", text[:min(80, len(text))])
		}
	}
}

func TestTOMLCompanionGroupsRespectTablesArraysAndDottedKeys(t *testing.T) {
	for _, text := range []string{
		"[first]\naccount='account-A'\ntoken='\x73k_live_Q5t7U9i2O4p6A8s0D3f5G7h9'\n[second]\naccount='account-B'\ntoken='\x73k_live_W1e3R5t7Y9u2I4o6P8a0S3d5'",
		"[[accounts]]\naccount='account-A'\ntoken='\x73k_live_Q5t7U9i2O4p6A8s0D3f5G7h9'\n[[accounts]]\naccount='account-B'\ntoken='\x73k_live_W1e3R5t7Y9u2I4o6P8a0S3d5'",
		"first.account='account-A'\nfirst.token='\x73k_live_Q5t7U9i2O4p6A8s0D3f5G7h9'\nsecond.account='account-B'\nsecond.token='\x73k_live_W1e3R5t7Y9u2I4o6P8a0S3d5'",
		"accounts=[{account='account-A', token='\x73k_live_Q5t7U9i2O4p6A8s0D3f5G7h9'}, {account='account-B', token='\x73k_live_W1e3R5t7Y9u2I4o6P8a0S3d5'}]",
	} {
		doc := tomlLiterals(context.Background(), model.Item{Path: "production.toml", Text: text})
		if doc == nil {
			t.Fatal("valid TOML companion fixture rejected")
		}
		for _, v := range doc.values {
			if v.name != "token" {
				continue
			}
			context := doc.contexts[v.group]
			want, forbidden := "account-A", "account-B"
			if strings.Contains(v.value, "W1e3") {
				want, forbidden = forbidden, want
			}
			if !strings.Contains(context, want) || strings.Contains(context, forbidden) {
				t.Fatal("TOML companion context borrowed fields from another object")
			}
		}
	}
}

func TestTOMLInventoryBudgetIncludesCommentsAndHeaders(t *testing.T) {
	for _, text := range []string{
		strings.Repeat("# comment\n", 10001),
		strings.Repeat("[[accounts]]\n", 10001),
	} {
		cov := model.NewCoverage()
		ctx := model.WithCoverage(context.Background(), cov)
		if doc := tomlLiterals(ctx, model.Item{Path: "production.toml", Text: text}); doc != nil {
			t.Fatal("TOML comments or table names bypassed the literal inventory budget")
		}
		complete, _, ds := cov.Snapshot()
		if complete || len(ds) != 1 || ds[0].Code != "toml_literal_limit" {
			t.Fatal("TOML inventory budget did not make the scan incomplete")
		}
	}
}

func TestTOMLQualifiedNamespaceBudgetPrecedesParserExpansion(t *testing.T) {
	var rows, inline []string
	for i := range 800 {
		entry := fmt.Sprintf("entry%d={password='Winter42!Autumn'}", i)
		rows, inline = append(rows, entry), append(inline, entry)
	}
	a, b := strings.Repeat("a", 4000), strings.Repeat("b", 4000)
	for _, text := range []string{
		"[" + strings.Repeat("namespace.", 80) + "root]\n" + strings.Join(rows, "\n"),
		"[" + a + "." + b + "]\n" + strings.Join(rows, "\n"),
		"root={" + a + "={" + b + "={" + strings.Join(inline, ",") + "}}}",
	} {
		cov := model.NewCoverage()
		ctx := model.WithCoverage(context.Background(), cov)
		if doc := tomlLiterals(ctx, model.Item{Path: "production.toml", Source: "code", Text: text}); doc != nil {
			t.Fatal("large qualified namespace bypassed parser work limit")
		}
		complete, _, ds := cov.Snapshot()
		if complete || len(ds) == 0 || ds[0].Code != "toml_literal_limit" {
			t.Fatal("namespace work limit was reached after parser or lost incompleteness")
		}
	}
}

func FuzzTOMLLiteralInventory(f *testing.F) {
	for _, text := range []string{`password='Winter42\'`, "password=\"\"\"Winter\\\n  42!Autumn\"\"\"", `api_key="\u0041\u004b\u0049\u0041NAFGYOEYPXU1DSYP"`, "[first]\npassword='Winter42Autumn'"} {
		f.Add(text)
	}
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > 8192 {
			return
		}
		doc := tomlLiterals(context.Background(), model.Item{Path: "production.toml", Text: text})
		if doc == nil {
			return
		}
		for i, v := range doc.values {
			if v.start < 0 || v.end > len(text) || v.start > v.end || doc.locate(v.preparedStart, v.preparedEnd) != &doc.values[i] {
				t.Fatal("TOML inventory contains invalid source coordinates")
			}
			if !v.raw && len(v.sourceStarts) != len(v.value) {
				t.Fatal("TOML source mapping lost canonical bytes")
			}
		}
	})
}
