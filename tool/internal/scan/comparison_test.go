package scan

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/secretindex"
)

func TestComparisonIdentityDisclosureAndML(t *testing.T) {
	const value = "Kx7#mPq2"
	id, err := secretindex.LoadIdentity(filepath.Join(t.TempDir(), "index"), true)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{`if password == "Kx7#mPq2":`, `if "Kx7#mPq2" == cfg['password']:`, `if "Kx7\u0023mPq2" == cfg.password:`} {
		scorer := &tableRecordScorer{}
		p := New(Options{Detector: detector(t), ML: scorer, ValueFingerprint: id.Fingerprint, LocationFingerprint: id.Location})
		text := "header\n" + line + "\n"
		it := model.Item{Source: "code", Path: "prod/auth.py", Text: text}
		fs := p.Findings(t.Context(), it)
		if len(fs) != 1 {
			t.Fatalf("unexpected comparison findings: %+v", fs)
		}
		f := fs[0]
		if f.Type != "generic_password" || f.Line != 2 || f.ValueFingerprint != id.Fingerprint(value) || f.Fingerprint != model.ComputeFingerprint(f.Type, it.Path, value) {
			t.Fatalf("comparison identity/source lost: %+v", f)
		}
		if len(scorer.records) != 1 || scorer.records[0].Value != value || scorer.records[0].Context.Name != "password" || scorer.records[0].Context.Line != line {
			t.Fatalf("comparison ML context lost: %+v", scorer.records)
		}
		raw, err := json.Marshal(fs)
		if err != nil {
			t.Fatal(err)
		}
		if f.Context != nil || strings.Contains(string(raw), value) {
			t.Fatal("comparison value disclosed without explicit flag")
		}
		shown := p.WithRevealSecrets(true).Findings(t.Context(), it)
		if len(shown) != 1 || shown[0].Redacted != value || shown[0].Context == nil || shown[0].Context.Name != "password" || shown[0].Context.Line != line {
			t.Fatal("explicit comparison disclosure lost original context")
		}
	}
}
