package scan

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/rules"
)

type publicRecordScorer struct{ rows *[]mlscore.Record }

func (s publicRecordScorer) Score(_ context.Context, rows []mlscore.Record) ([]mlscore.Result, error) {
	*s.rows = append(*s.rows, rows...)
	out := make([]mlscore.Result, len(rows))
	for i := range out {
		out[i].Score = 1
	}
	return out, nil
}
func (publicRecordScorer) Threshold() float64 { return .3 }
func (publicRecordScorer) Local() bool        { return true }

func TestPublicBindingCapturePreservesMLInputsAndFindingIdentity(t *testing.T) {
	engine, err := rules.Load("../../rules/cloud/gcp-api-key.yaml")
	if err != nil {
		t.Fatal(err)
	}
	const key = "AIzaSy9Qw7Er5Ty3Ui1Op8As6Df4Gh2Jk0Lz5Xc"
	for _, fixture := range []struct{ path, text string }{
		{"prod.json", `{"projectId":"owned-project","project_id":42,"databaseURL":"https://owned-project.firebaseio.com","apiKey":"KEY"}`},
		{"prod.yaml", "projectId: owned-project\nproject_id: 42\ndatabaseURL: 'https://owned-project.firebaseio.com'\napiKey: 'KEY'\n"},
		{"prod.toml", "projectId='owned-project'\nproject_id=42\ndatabaseURL='https://owned-project.firebaseio.com'\napiKey='KEY'\n"},
	} {
		var records [2][]mlscore.Record
		var results [2][]model.Finding
		for mode := 0; mode < 2; mode++ {
			options := Options{Detector: detector(t), Rules: engine, ML: publicRecordScorer{&records[mode]}}
			if mode == 1 {
				options.PublicAuditor = auditFunc(func(context.Context, string, string, map[string]string) *model.PublicKeyAudit { return nil })
			}
			results[mode] = New(options).Findings(t.Context(), model.Item{Source: "code", Path: fixture.path, Text: strings.ReplaceAll(fixture.text, "KEY", key)})
		}
		if len(results[0]) != 1 || !reflect.DeepEqual(results[0], results[1]) || !reflect.DeepEqual(records[0], records[1]) {
			t.Fatal("public binding capture changed L1 identities, coordinates or ML records", fixture.path)
		}
	}
}
