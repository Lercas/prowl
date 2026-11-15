package scan

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/secretindex"
)

func shortKeyDocuments(value string) map[string]string {
	body, _ := json.Marshal(map[string]string{"note": "🚀", "api_key": value})
	return map[string]string{
		"escaped.json": `{"note":"🚀","api_key":"\u0071` + value[1:] + `"}`,
		"prod.json":    string(body), "prod.yaml": "note: 🚀\napi_key: '" + value + "'\n",
		"prod.toml": "note='🚀'\napi_key='" + value + "'\n", "prod.env": "# 🚀\nDEPLOY_TOKEN=" + value + "\n",
		"prod.py": "# 🚀\napi_key='" + value + "'\n", "prod.md": "🚀\n| api_key | " + value + " |\n",
	}
}

func TestShortKeyPipelineIdentityPrivacyAndML(t *testing.T) {
	id, err := secretindex.LoadIdentity(filepath.Join(t.TempDir(), "index"), true)
	if err != nil {
		t.Fatal(err)
	}
	scorer, err := mlscore.NewEmbedded(.3, "../mlmodel/model_binary_go_literal_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	for n := 12; n < 20; n++ {
		value := "q7Vx9mK2rP5nC8aH4zL"[:n]
		for path, text := range shortKeyDocuments(value) {
			t.Run(fmt.Sprintf("%d/%s", n, path), func(t *testing.T) {
				var records []mlscore.Record
				fs := New(Options{Detector: detector(t), ML: publicRecordScorer{&records}, ValueFingerprint: id.Fingerprint, LocationFingerprint: id.Location}).Findings(t.Context(), model.Item{Source: "code", Path: path, Text: text})
				found := jwtRuleFindings(fs, "generic_api_key")
				if len(found) != 1 || len(records) != 1 {
					t.Fatal("short key missing or duplicated", len(found), len(records))
				}
				f := found[0]
				if f.ValueFingerprint != id.Fingerprint(value) || f.Redacted == value || f.Context != nil || f.Verified != nil || f.ByteStart < 0 || f.ByteStart >= f.ByteEnd || f.ByteEnd > len(text) {
					t.Fatal("privacy or keyed identity changed")
				}
				line, col := newLineIndex(text).cols(f.ByteStart)
				if f.Line != line || f.Col != col || f.UTF16Col != newLineIndex(text).utf16Col(f.ByteStart) {
					t.Fatal("physical coordinates lost")
				}
				if records[0].Value != value || !(strings.Contains(strings.ToLower(records[0].Context.Name), "key") || strings.Contains(strings.ToLower(records[0].Context.Name), "token")) {
					t.Fatal("logical ML context lost")
				}
				p := func(s mlscore.Scorer) []model.Finding {
					return New(Options{Detector: detector(t), ML: s}).Findings(t.Context(), model.Item{Source: "code", Path: path, Text: text})
				}
				if len(jwtRuleFindings(p(fixedMLScorer{results: []mlscore.Result{{Score: 0}}, threshold: .3}), "generic_api_key")) != 0 {
					t.Fatal("short key bypassed ML")
				}
				scores, err := scorer.Score(t.Context(), records)
				if err != nil || len(scores) != 1 || !mlscore.ValidScore(scores[0].Score) {
					t.Fatal("invalid model score")
				}
				kept := len(jwtRuleFindings(p(scorer), "generic_api_key")) == 1
				if kept != (scores[0].Score >= scorer.Threshold()) {
					t.Fatal("model decision bypassed")
				}
				t.Logf("short-key-model length=%d path=%s score=%.9f retained=%t", n, path, scores[0].Score, kept)
			})
		}
	}
}
