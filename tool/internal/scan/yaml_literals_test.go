package scan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/rules"
	bundledrules "github.com/Lercas/prowl/tool/rules"
)

func TestYAMLCanonicalMultilineAndAnchoredPasswords(t *testing.T) {
	eng, err := rules.LoadEmbedded(bundledrules.Files)
	if err != nil {
		t.Fatal(err)
	}
	ml, err := mlscore.NewEmbedded(.5, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ text, value, source string }{
		{"password: |-\n  Winter42!Autumn\n  Spring53\n", "Winter42!Autumn\nSpring53", "Winter42!Autumn\n  Spring53"},
		{"password: >-\n  Winter42!Autumn\n  Spring53\n", "Winter42!Autumn Spring53", "Winter42!Autumn\n  Spring53"},
		{"password: |+\n  Winter42!Autumn\n\n", "Winter42!Autumn\n\n", "Winter42!Autumn\n\n"},
		{"password: |2-\n    Winter42!Autumn\n", "  Winter42!Autumn", "    Winter42!Autumn"},
		{"password: Winter42!Autumn\n  Spring53\n", "Winter42!Autumn Spring53", "Winter42!Autumn\n  Spring53"},
		{"password: \"Winter42!Autumn\n  Spring53\"\n", "Winter42!Autumn Spring53", "Winter42!Autumn\n  Spring53"},
		{"password: 'Winter42!Autumn\n  Spring53'\n", "Winter42!Autumn Spring53", "Winter42!Autumn\n  Spring53"},
		{"password: \"Winter\\\n  42!Autumn\"\n", "Winter42!Autumn", "Winter\\\n  42!Autumn"},
		{"password: !!str &a \"Winter42!Autumn\"\n", "Winter42!Autumn", "Winter42!Autumn"},
		{"\ufeffpassword: Winter42!Autumn\n", "Winter42!Autumn", "Winter42!Autumn"},
		{"password: |-\r\n  Winter42!Autumn\r\n  Spring53\r\n", "Winter42!Autumn\nSpring53", "Winter42!Autumn\r\n  Spring53"},
	} {
		for _, scorer := range []mlscore.Scorer{nil, ml} {
			cov := model.NewCoverage()
			ctx := WithOptions(model.WithCoverage(context.Background(), cov), Options{IdentityKey: []byte(strings.Repeat("k", 32))})
			fs := Findings(ctx, detector(t), eng, nil, model.Item{Path: "production.yaml", Text: c.text, Source: "code"}, nil, scorer)
			complete, _, ds := cov.Snapshot()
			if !complete || len(fs) != 1 || fs[0].Type != "generic_password" || c.text[fs[0].ByteStart:fs[0].ByteEnd] != c.source {
				t.Fatalf("YAML multiline value/span lost: %q findings=%+v diagnostics=%+v", c.text, fs, ds)
			}
			want := model.Finding{Type: "generic_password"}
			annotateIdentity(ctx, &want, c.value, model.Item{Path: "production.yaml"})
			if fs[0].SecretID != want.SecretID || fs[0].Fingerprint != want.Fingerprint {
				t.Fatal("YAML multiline identity did not use the parser-established value")
			}
		}
	}
}

func TestYAMLPresentationDoesNotHideTypedCredentials(t *testing.T) {
	const raw = "AKIANAFGYOEYPXU1DSYP"
	blob := base64.StdEncoding.EncodeToString([]byte(raw))
	for _, text := range []string{
		"# " + raw + "\nvalue: ordinary\n",
		"empty: |\n# " + raw + "\nvalue: ordinary\n",
		"value: ordinary\n  # " + raw + "\n",
		"value: [ordinary,\n  # " + raw + "\n  continuation]\n",
		"value: |-\n  before\n  ---" + raw + "\n",
		"|-\n before\n " + raw + "\n",
		"value: \"\\x41\\u004b" + raw[2:] + "\"\n",
		"value: !!binary |\n  " + blob[:12] + "\n  " + blob[12:] + "\n",
		"value: !!binary '" + blob[:12] + " " + blob[12:] + "'\n",
		"value: !!binary '" + blob + "'\n",
		"definition: &" + raw + " ordinary\ncopy: *" + raw + "\n",
		"definition: &" + raw + " " + raw + "\ncopy: *" + raw + "\n",
	} {
		cov := model.NewCoverage()
		ctx := model.WithCoverage(context.Background(), cov)
		fs := Findings(ctx, detector(t), nil, nil, model.Item{Path: "production.yaml", Text: text, Source: "code"}, nil, nil)
		complete, _, ds := cov.Snapshot()
		want := 1
		if strings.Contains(text, "&"+raw) {
			want = 2
			if strings.Contains(text, "&"+raw+" "+raw) {
				want = 3
			}
		}
		if !complete || len(fs) != want {
			t.Fatalf("YAML presentation lost a typed credential or completeness: %q findings=%+v diagnostics=%+v", text, fs, ds)
		}
		for _, f := range fs {
			if f.Type != "aws_access_key_id" || f.Fingerprint != model.ComputeFingerprint("aws_access_key_id", "production.yaml", raw) || f.ByteEnd <= f.ByteStart || f.ByteStart < 0 || f.ByteEnd > len(text) {
				t.Fatal("YAML presentation changed credential identity or source coordinates")
			}
		}
	}
}

func TestYAMLPragmasFollowParserLinesAndCommentRoles(t *testing.T) {
	const raw = "AKIANAFGYOEYPXU1DSYP"
	for _, sep := range []string{"\n", "\r\n", "\r", "\u0085", "\u2028", "\u2029"} {
		for _, c := range []struct {
			text  string
			count int
		}{
			{"key: " + raw + sep + "# prowl:allow" + sep, 1},
			{"key: " + raw + " # prowl:allow" + sep, 0},
			{"key: '" + raw + " # prowl:allow'" + sep, 1},
			{"key: |-" + sep + "  " + raw + " # prowl:allow" + sep, 1},
		} {
			cov := model.NewCoverage()
			fs := Findings(model.WithCoverage(context.Background(), cov), detector(t), nil, nil, model.Item{Path: "production.yaml", Text: c.text, Source: "code"}, nil, nil)
			complete, _, ds := cov.Snapshot()
			if !complete || len(fs) != c.count {
				t.Fatalf("YAML comment role/line drift: %q findings=%+v diagnostics=%+v", c.text, fs, ds)
			}
		}
	}
}

func TestYAMLInlineMergeSequenceHasUseProvenance(t *testing.T) {
	text := "copy: {<<: [{password: Winter42!Autumn}, {password: Spring53!Summer}]}\n"
	fs := Findings(context.Background(), detector(t), nil, nil, model.Item{Path: "production.yaml", Text: text}, nil, nil)
	if len(fs) != 3 {
		t.Fatalf("inline merge sequence lost its winning use: %+v", fs)
	}
	uses := 0
	for _, f := range fs {
		if text[f.ByteStart:f.ByteEnd] == "<<" {
			uses++
		}
	}
	if uses != 1 {
		t.Fatal("inline merge sequence use has no merge-reference source span")
	}
}

func TestYAMLScalarAndCollectionAliasesKeepDefinitionAndUseEvidence(t *testing.T) {
	for _, text := range []string{
		"definition: &a Winter42!Autumn\npassword: *a\n",
		"definition: &a {password: Winter42!Autumn}\ncopy: *a\n",
		"definition: &a {password: Winter42!Autumn}\ncopy: {<<: *a}\n",
	} {
		cov := model.NewCoverage()
		ctx := WithOptions(model.WithCoverage(context.Background(), cov), Options{IdentityKey: []byte(strings.Repeat("k", 32))})
		fs := Findings(ctx, detector(t), nil, nil, model.Item{Path: "production.yaml", Text: text, Source: "code"}, nil, nil)
		complete, _, ds := cov.Snapshot()
		want := 2
		if strings.Contains(text, "&a Winter") {
			want = 1
		}
		if !complete || len(fs) != want {
			t.Fatalf("YAML alias declarations/uses lost: %q findings=%+v diagnostics=%+v", text, fs, ds)
		}
		var use *model.Finding
		for i := range fs {
			if text[fs[i].ByteStart:fs[i].ByteEnd] == "*a" {
				use = &fs[i]
			}
		}
		if use == nil || len(use.Evidence) < 2 {
			t.Fatal("YAML alias source reference or definition proof missing")
		}
		found := false
		for _, e := range use.Evidence {
			if e.Transform == "yaml-anchor-value" && text[e.Start:e.End] == "Winter42!Autumn" {
				found = true
			}
		}
		if !found {
			t.Fatal("YAML alias proof does not point to its physical value definition")
		}
		serialized, _ := json.Marshal(fs)
		if strings.Contains(string(serialized), "Winter42!Autumn") {
			t.Fatal("YAML alias evidence disclosed a credential")
		}
	}
}

func TestYAMLAliasGuardsAndMergeOverrides(t *testing.T) {
	for _, text := range []string{
		"definition: &a {password: Winter42!Autumn}\ncopy: {<<: *a, password: Spring53!Summer}\n",
		"copy: {<<: {password: Winter42!Autumn}, password: Spring53!Summer}\n",
	} {
		fs := Findings(context.Background(), detector(t), nil, nil, model.Item{Path: "production.yaml", Text: text, Source: "code"}, nil, nil)
		if len(fs) != 2 {
			t.Fatalf("YAML merge must retain physical defaults and override without fabricating a default use: %+v", fs)
		}
	}
	for _, c := range []struct{ text, code string }{
		{"definition: &a Winter42!Autumn\n---\npassword: *a\n", "yaml_alias_cross_document"},
		{"definition: &a {self: *a, password: Winter42!Autumn}\ncopy: *a\n", "yaml_alias_cycle"},
		{"password: !env PASSWORD\n", "yaml_tag_unresolved"},
		{"password: !<tag:example.com,2026:credential> Winter42!Autumn\n", "yaml_tag_unresolved"},
		{"password: !!external Winter42!Autumn\n", "yaml_tag_unresolved"},
		{"password: !env [PASSWORD]\n", "yaml_tag_unresolved"},
		{"password: !!binary 'not base64!'\n", "yaml_binary_parse"},
		{"password: Winter42!Autumn\npassword: Spring53!Summer\n", "yaml_duplicate_key"},
	} {
		cov := model.NewCoverage()
		Findings(model.WithCoverage(context.Background(), cov), detector(t), nil, nil, model.Item{Path: "production.yaml", Text: c.text, Source: "code"}, nil, nil)
		complete, _, ds := cov.Snapshot()
		found := false
		for _, d := range ds {
			found = found || d.Code == c.code
		}
		if complete || !found {
			t.Fatalf("unresolved YAML graph/tag/key could certify completeness: %s, %+v", c.code, ds)
		}
	}
}

func FuzzYAMLLiteralInventory(f *testing.F) {
	for _, text := range []string{
		"password: |-\n  Winter42\n  Autumn53\n", "password: !!str &a Winter42\ncopy: *a\n",
		"default: &a {password: Winter42}\ncopy: {<<: [*a]}\n", "password: \"Winter\\u0034\\u0032\"\n",
		"password: !!binary |\n  V2ludGVyNDI=\n", "empty: |\n# token\n", "&a {self: *a}\n",
		"\ufeffpassword: Winter42\r# marker\r", "password: Winter42\u2028# marker\u2028",
	} {
		f.Add(text)
	}
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > 8192 {
			return
		}
		doc := yamlLiterals(context.Background(), model.Item{Path: "production.yaml", Text: text})
		if doc == nil {
			return
		}
		for i, v := range doc.values {
			if v.start < 0 || v.end > len(text) || v.start > v.end || doc.locate(v.preparedStart, v.preparedEnd) != &doc.values[i] {
				t.Fatal("YAML inventory contains invalid source coordinates")
			}
			if !v.raw && !v.whole && len(v.sourceStarts) != len(v.value) {
				t.Fatal("YAML mapping lost canonical bytes")
			}
			for j := range v.sourceStarts {
				if !v.whole && (v.sourceStarts[j] < v.start || v.sourceEnds[j] > v.end || v.sourceStarts[j] >= v.sourceEnds[j]) {
					t.Fatal("YAML source byte mapping escaped its literal")
				}
			}
			for _, e := range v.proof {
				if e.Start < 0 || e.End > len(text) || e.Start > e.End {
					t.Fatal("YAML graph evidence escaped its source")
				}
			}
		}
	})
}

func TestYAMLAliasExpansionHasSharedBoundAndRetainsDeclarations(t *testing.T) {
	var text strings.Builder
	text.WriteString("a0: &a0 {password: Winter42!Autumn}\n")
	for i := 1; i <= 20; i++ {
		fmt.Fprintf(&text, "a%d: &a%d [*a%d, *a%d]\n", i, i, i-1, i-1)
	}
	cov := model.NewCoverage()
	doc := yamlLiterals(model.WithCoverage(context.Background(), cov), model.Item{Path: "production.yaml", Text: text.String()})
	complete, _, ds := cov.Snapshot()
	found := false
	for _, d := range ds {
		found = found || d.Code == "yaml_scalar_limit"
	}
	if doc == nil || complete || !found || len(doc.values) > 10000 {
		t.Fatal("YAML exponential aliases escaped their shared producer budget")
	}
	declaration := false
	for _, v := range doc.values {
		declaration = declaration || v.name == "password" && !v.whole && v.value == "Winter42!Autumn"
	}
	if !declaration {
		t.Fatal("bounded alias expansion lost the actual declaration")
	}
}
