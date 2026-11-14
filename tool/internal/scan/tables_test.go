package scan

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/secretindex"
)

type tableRecordScorer struct{ records []mlscore.Record }

func (s *tableRecordScorer) Local() bool        { return true }
func (s *tableRecordScorer) Threshold() float64 { return .3 }
func (s *tableRecordScorer) Score(_ context.Context, records []mlscore.Record) ([]mlscore.Result, error) {
	s.records = append(s.records, records...)
	out := make([]mlscore.Result, len(records))
	for i := range out {
		out[i].Score = 1
	}
	return out, nil
}

func TestTablePipelineIdentityContextAndML(t *testing.T) {
	const value = "Kx7|mPq2"
	const spelling = `Kx7\|mPq2`
	text := "| User | DB Password |\n| --- | --- |\n| service | " + spelling + " |\n"
	id, err := secretindex.LoadIdentity(filepath.Join(t.TempDir(), "index"), true)
	if err != nil {
		t.Fatal(err)
	}
	scorer := &tableRecordScorer{}
	p := New(Options{Detector: detector(t), ML: scorer, ValueFingerprint: id.Fingerprint, LocationFingerprint: id.Location})
	it := model.Item{Source: "code", Path: "prod/" + spelling + ".md", Text: text}
	fs := p.Findings(t.Context(), it)
	if len(fs) != 1 {
		t.Fatalf("unexpected findings: %+v", fs)
	}
	f := fs[0]
	if f.Type != "generic_password" || f.Line != 3 || f.Col != 13 || f.ValueFingerprint != id.Fingerprint(value) || f.Fingerprint != model.ComputeFingerprint(f.Type, it.Path, value) {
		t.Fatalf("identity or source position lost: %+v", f)
	}
	if len(scorer.records) != 1 || scorer.records[0].Value != value || scorer.records[0].Context.Name != "db_password" || scorer.records[0].Context.Line != "| service | "+spelling+" |" {
		t.Fatalf("ML lost semantic name or original line: %+v", scorer.records)
	}
	if strings.Contains(f.IndexPath, value) || strings.Contains(f.IndexPath, spelling) {
		t.Fatal("observed spelling leaked into index metadata")
	}
	raw, err := json.Marshal(fs)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), value) || f.Context != nil {
		t.Fatal("value or context disclosed without explicit flag")
	}
	shown := p.WithRevealSecrets(true).Findings(t.Context(), it)
	if len(shown) != 1 || shown[0].Redacted != value || shown[0].Context == nil || shown[0].Context.Name != "db_password" || shown[0].Context.Line != "| service | "+spelling+" |" {
		t.Fatal("explicit disclosure lost logical value or original context")
	}
}

func TestTableLimitBecomesIncompleteFinding(t *testing.T) {
	text := "| User | Password |\n| --- | --- |\n| svc | " + strings.Repeat("x", 9000) + " |"
	fs := New(Options{Detector: detector(t)}).Findings(t.Context(), model.Item{Source: "code", Path: "prod/credentials.md", Text: text})
	for _, f := range fs {
		if f.Type == ResultsTruncatedType {
			return
		}
	}
	t.Fatal("table parse limit presented as complete scan")
}
