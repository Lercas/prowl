package scan

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestBase64EvidenceRemainsInsideOriginalStructuredSource(t *testing.T) {
	const value = "AKIANAFGYOEYPXU1DSYP"
	blob := base64.StdEncoding.EncodeToString([]byte(value))
	for _, row := range []struct {
		path, text string
		count      int
	}{
		{"production.json", `{"note":"🚀","payload":"\u0051` + blob[1:] + `"}`, 1},
		{"production.toml", `note="🚀"` + "\npayload=\"\\u0051" + blob[1:] + "\"", 1},
		{"production.yaml", "note: 🚀\npayload: &x " + blob + "\ncopy: *x\n", 2},
	} {
		t.Run(row.path, func(t *testing.T) {
			coverage := model.NewCoverage()
			fs := New(Options{Detector: detector(t)}).Findings(model.WithCoverage(t.Context(), coverage), model.Item{Source: "code", Path: row.path, Text: row.text})
			if len(fs) != row.count || !model.NewResult(fs, coverage).Complete {
				t.Fatalf("lost structured encoded occurrence: count=%d", len(fs))
			}
			for _, f := range fs {
				if f.Type != "aws_access_key_id" || f.Context != nil || strings.Contains(f.Redacted, value) || f.ByteStart < 0 || f.ByteEnd > len(row.text) || f.ByteStart >= f.ByteEnd {
					t.Fatal("encoded finding lost its original masked source range")
				}
				proof := false
				for _, e := range f.Evidence {
					proof = proof || e.Transform == "base64-decode"
					if e.Path != row.path || e.Start < 0 || e.End > len(row.text) || e.Start >= e.End {
						t.Fatal("encoding evidence escaped the original structured document")
					}
				}
				if !proof {
					t.Fatal("encoded occurrence lost its decoding proof")
				}
			}
		})
	}
}
