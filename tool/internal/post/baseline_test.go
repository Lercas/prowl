package post

import (
	"path/filepath"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestBaselineRoundTrip(t *testing.T) {
	known := []model.Finding{
		{Type: "aws_access_key_id", Path: "config.py", Redacted: "AKIA****1234"},
		{Type: "github_pat_classic", Path: "ci.yml", Redacted: "ghp_****abcd"},
	}
	bl := filepath.Join(t.TempDir(), "baseline.json")
	if err := WriteBaseline(bl, known); err != nil {
		t.Fatal(err)
	}
	b := LoadBaseline(bl)

	if got := b.Suppress(known); len(got) != 0 {
		t.Errorf("known findings not suppressed: %d remain", len(got))
	}
	novel := []model.Finding{{Type: "stripe_secret_key", Path: "pay.go", Redacted: "sk_l****wxyz"}}
	if got := b.Suppress(append(append([]model.Finding{}, known...), novel...)); len(got) != 1 {
		t.Errorf("expected 1 novel finding to survive, got %d", len(got))
	}
}

func TestFingerprintStableAcrossLineShift(t *testing.T) {
	// fingerprint excludes line -> a secret that moved lines is still recognised
	a := model.Finding{Type: "aws_access_key_id", Path: "c.py", Redacted: "AKIA****1234", Line: 10}
	b := model.Finding{Type: "aws_access_key_id", Path: "c.py", Redacted: "AKIA****1234", Line: 42}
	if Fingerprint(a) != Fingerprint(b) {
		t.Error("fingerprint changed when only the line number moved")
	}
}

func TestEmptyBaselineNoOp(t *testing.T) {
	fs := []model.Finding{{Type: "x", Path: "p", Redacted: "r"}}
	if got := (&Baseline{}).Suppress(fs); len(got) != 1 {
		t.Error("empty baseline should suppress nothing")
	}
}
