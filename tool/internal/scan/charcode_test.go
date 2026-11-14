package scan

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/secretindex"
)

func scanCharCodeFixture(value string) string {
	units := utf16.Encode([]rune(value))
	args := make([]string, len(units))
	for i, u := range units {
		args[i] = fmt.Sprint(u)
	}
	return "String.fromCharCode(" + strings.Join(args, ",") + ")"
}

func TestCharCodePipelineIdentityOriginalContextAndDisclosure(t *testing.T) {
	id, err := secretindex.LoadIdentity(filepath.Join(t.TempDir(), "index"), true)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ value, field, typ string }{
		{"AKIANAFGYOEYPXU1DSYP", "api_key", "aws_access_key_id"},
		{`"Kx7;mPq2"`, "db_password", "generic_password"},
	} {
		expr := scanCharCodeFixture(c.value)
		line := "const " + c.field + "=" + expr + ";"
		text := "header\n" + line + "\n"
		scorer := &tableRecordScorer{}
		p := New(Options{Detector: detector(t), ML: scorer, ValueFingerprint: id.Fingerprint, LocationFingerprint: id.Location})
		it := model.Item{Source: "code", Path: "prod/" + expr + ".js", Text: text}
		fs := p.Findings(t.Context(), it)
		if len(fs) != 1 {
			t.Fatalf("unexpected charcode findings: %+v", fs)
		}
		f := fs[0]
		if f.Type != c.typ || f.Line != 2 || f.Col != strings.Index(line, expr)+1 || f.ValueFingerprint != id.Fingerprint(c.value) || f.Fingerprint != model.ComputeFingerprint(f.Type, it.Path, c.value) {
			t.Fatalf("charcode source or identity lost: %+v", f)
		}
		if strings.Contains(f.IndexPath, c.value) || strings.Contains(f.IndexPath, expr) {
			t.Fatal("decoded or observed expression leaked into private index metadata")
		}
		if len(scorer.records) != 1 || scorer.records[0].Value != c.value || scorer.records[0].Context.Line != "const "+c.field+"="+strconv.Quote(c.value)+";" {
			t.Fatal("charcode ML value or literal context lost")
		}
		if c.typ == "generic_password" && scorer.records[0].Context.Name != c.field {
			t.Fatal("charcode generic ML name lost")
		}
		raw, err := json.Marshal(fs)
		if err != nil {
			t.Fatal(err)
		}
		if f.Context != nil || f.Redacted == c.value || strings.Contains(string(raw), c.value) {
			t.Fatal("charcode secret disclosed without explicit flag")
		}
		shown := p.WithRevealSecrets(true).Findings(t.Context(), it)
		if len(shown) != 1 || shown[0].Redacted != c.value || shown[0].Context == nil || shown[0].Context.OriginalLine != line || shown[0].Context.Line != scorer.records[0].Context.Line {
			t.Fatal("explicit charcode disclosure lost logical value or original line")
		}
	}
}

func TestCharCodeBrokenUTF16SurvivesPipelineFiltering(t *testing.T) {
	expr := strings.Replace(scanCharCodeFixture("AKIANAFGYOEYPXU1DSYP"), "(", "(55296,", 1)
	p := New(Options{Detector: detector(t), ML: fixedMLScorer{results: []mlscore.Result{{Score: 0}}, threshold: .3}})
	fs := p.Findings(t.Context(), model.Item{Source: "code", Path: "prod/config.js", Text: "payload=" + expr})
	if len(fs) != 1 || fs[0].Type != ResultsTruncatedType {
		t.Fatal("broken UTF-16 uncertainty was lost after ML suppressed the typed candidate")
	}
}

func TestCharCodeEmbeddedMLUsesLogicalLiteralContext(t *testing.T) {
	t.Setenv("PROWL_HOME", t.TempDir())
	scorer, err := mlscore.NewEmbedded(.3, "")
	if err != nil {
		t.Fatal(err)
	}
	const uri = "postgresql://svc:Kx7\ufffdmPq2@prod.internal"
	p := New(Options{Detector: detector(t), ML: scorer})
	var fingerprint string
	for _, text := range []string{"blob=" + strconv.Quote(uri), "blob=" + scanCharCodeFixture(uri)} {
		fs := p.Findings(t.Context(), model.Item{Source: "code", Path: "prod/config.js", Text: text})
		if len(fs) != 1 || fs[0].Type != "db_connection_string" {
			t.Fatal("ML filtered logical URI because of source encoding")
		}
		if fingerprint != "" && fs[0].Fingerprint != fingerprint {
			t.Fatal("plain/numeric logical identity changed under ML")
		}
		fingerprint = fs[0].Fingerprint
	}
}

func TestCharCodeModelContextIsBoundedAndDoesNotExpandPayload(t *testing.T) {
	const value = "Kx7;mPq2"
	const unseen = "DO_NOT_SEND_NEXT_STATEMENT"
	text := strings.Repeat("界", 150) + ";password=" + scanCharCodeFixture(value) + ";extra=" + strconv.Quote(unseen)
	scorer := &tableRecordScorer{}
	p := New(Options{Detector: detector(t), ML: scorer})
	fs := p.Findings(t.Context(), model.Item{Source: "code", Path: "prod/config.js", Text: text})
	if len(fs) != 1 || len(scorer.records) != 1 {
		t.Fatal("bounded context fixture lost candidate")
	}
	line := scorer.records[0].Context.Line
	if len(line) > 400 || !utf8.ValidString(line) || !strings.Contains(line, value) || strings.Contains(line, unseen) {
		t.Fatal("model context exceeded bounds or exposed extra source")
	}
	if fs[0].Context != nil {
		t.Fatal("scoring context disclosed without explicit flag")
	}
}
