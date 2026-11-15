package scan

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/secretindex"
)

func shortPasswordDocuments(value string) map[string]string {
	body, _ := json.Marshal(map[string]string{"note": "🚀", "password": value})
	return map[string]string{
		"prod.json": string(body),
		"prod.yaml": "note: 🚀\npassword: '" + strings.ReplaceAll(value, "'", "''") + "'\n",
		"prod.toml": "note='🚀'\npassword='" + value + "'\n",
		"prod.env":  "# 🚀\nPOSTGRES_PASSWORD='" + value + "'\n",
		"prod.py":   "# 🚀\npassword='" + value + "'\n",
		"prod.md":   "🚀\n| password | " + value + " |\n",
	}
}

func TestShortPasswordPipelineIdentityPrivacyAndMLContext(t *testing.T) {
	id, err := secretindex.LoadIdentity(filepath.Join(t.TempDir(), "index"), true)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"r", "47", "jsfg", "aB9!", "白", "q🙂"} {
		for path, text := range shortPasswordDocuments(value) {
			t.Run(fmt.Sprintf("%s-%d", path, len(value)), func(t *testing.T) {
				var records []mlscore.Record
				fs := New(Options{Detector: detector(t), ML: publicRecordScorer{&records}, ValueFingerprint: id.Fingerprint, LocationFingerprint: id.Location}).Findings(t.Context(), model.Item{Source: "code", Path: path, Text: text})
				found := jwtRuleFindings(fs, "generic_password")
				if len(found) != 1 || len(records) != 1 {
					t.Fatal("short credential missing or duplicated", len(found), len(records))
				}
				f := found[0]
				if f.Redacted != strings.Repeat("*", utf8.RuneCountInString(value)) || f.Context != nil || f.Verified != nil || f.ValueFingerprint != id.Fingerprint(value) || f.ByteStart < 0 || f.ByteStart >= f.ByteEnd || f.ByteEnd > len(text) {
					t.Fatal("privacy, source or keyed identity changed")
				}
				line, col := newLineIndex(text).cols(f.ByteStart)
				if f.Line != line || f.Col != col || f.UTF16Col != newLineIndex(text).utf16Col(f.ByteStart) || f.IndexLocationID != id.Location("code", path, line, col) {
					t.Fatal("original source coordinates lost")
				}
				row := records[0]
				if row.Value != value || !strings.Contains(strings.ToLower(row.Context.Name), "password") {
					t.Fatal("model did not receive the logical value/binding")
				}
				rejected := New(Options{Detector: detector(t), ML: fixedMLScorer{results: []mlscore.Result{{Score: 0}}, threshold: .3}}).Findings(t.Context(), model.Item{Source: "code", Path: path, Text: text})
				if len(jwtRuleFindings(rejected, "generic_password")) != 0 {
					t.Fatal("short password bypassed ML")
				}
			})
		}
	}
}

func TestShortPasswordKeepsNonStringAndCodeControlsOutOfPipeline(t *testing.T) {
	for path, text := range map[string]string{
		"a.json": `{"password":true,"pwd":null,"require_password":false,"password_length":4}`,
		"a.yaml": "password: true\npwd: null\npassword_length: 4\n",
		"a.toml": "password=true\npassword_length=4\n",
		"a.py":   "password = token\npwd = None\npassword = 42\npassword = str\n",
		"a.js":   "const password = value; const pwd = true; const passwordLength = 4;",
	} {
		for _, f := range New(Options{Detector: detector(t)}).Findings(t.Context(), model.Item{Source: "code", Path: path, Text: text}) {
			if f.Type == "generic_password" {
				t.Fatal("typed metadata or code became a short password", path)
			}
		}
	}
}

func TestShortPasswordFrozenEmbeddedRetention(t *testing.T) {
	scorer, err := mlscore.NewEmbedded(.3, "../mlmodel/model_binary_go_literal_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	for index, value := range []string{"r", "47", "jsfg", "aB9!", "白", "q🙂"} {
		var records []mlscore.Record
		text := shortPasswordDocuments(value)["prod.json"]
		New(Options{Detector: detector(t), ML: publicRecordScorer{&records}}).Findings(t.Context(), model.Item{Source: "code", Path: "prod.json", Text: text})
		if len(records) != 1 {
			t.Fatal("L1 did not nominate the short scalar")
		}
		scores, err := scorer.Score(t.Context(), records)
		if err != nil || len(scores) != 1 || !mlscore.ValidScore(scores[0].Score) {
			t.Fatal("invalid short-value model score")
		}
		fs := New(Options{Detector: detector(t), ML: scorer}).Findings(t.Context(), model.Item{Source: "code", Path: "prod.json", Text: text})
		kept := len(jwtRuleFindings(fs, "generic_password")) == 1
		if kept != (scores[0].Score >= scorer.Threshold()) {
			t.Fatal("short-value model decision was bypassed")
		}
		t.Logf("short-model-case=%d score=%.9f retained=%t", index, scores[0].Score, kept)
	}
}
