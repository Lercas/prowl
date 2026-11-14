package scan

import (
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestCanonicalScoringProofRequiresWholeParserBoundPassword(t *testing.T) {
	for _, c := range []struct {
		path, text string
		count      int
		proof, ui  bool
	}{
		{"production.json", `{"password":"Quartz${19}Mango"}`, 1, true, false},
		{"production.json", `{"password":"Quartz19!Mango"}`, 1, false, false},
		{"production.json", `{"пароль":"Quartz19!Mango"}`, 1, true, false},
		{"messages.json", `{"validation":{"password":"Quartz${19}Mango"}}`, 1, true, true},
		{"production.toml", `[auth]` + "\n" + `password="Quartz${19}Mango"`, 1, true, false},
		{"production.yaml", "definition: &a Quartz${19}Mango\npassword: *a\n", 1, true, false},
		{"production.go", `password="Quartz19!Mango"`, 1, false, false},
		{"production.yaml", "# password='Quartz19!Mango'\nvalue: ordinary\n", 1, false, false},
		{"production.json", `{"api_key":"AKIANAFGYOEYPXU1DSYP"}`, 1, false, false},
		{"production.json", `{"note":"password=Quartz${19}Mango"}`, 0, false, false},
		{"production.json", `{"password_hash":"Quartz${19}Mango"}`, 0, false, false},
	} {
		scorer := &tableRecordScorer{}
		New(Options{Detector: detector(t), ML: scorer}).Findings(t.Context(), model.Item{Path: c.path, Text: c.text, Source: "code"})
		if len(scorer.records) != c.count {
			t.Fatalf("unexpected candidate inventory for %s: %d", c.path, len(scorer.records))
		}
		for _, r := range scorer.records {
			if r.Context.ParserLiteralSensitive != c.proof || r.Context.UINamespace != c.ui {
				t.Fatal("scoring proof was guessed from text rather than established by parser")
			}
		}
	}
}
