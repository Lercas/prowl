package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/mlfeatures"
	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/scan"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

func TestLoadedModelPolicyInEmptyWorkerResponses(t *testing.T) {
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "model.json")
	write := func(bias int) {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"baseline": bias, "feature_names": mlfeatures.FeatureNames, "trees": []map[string]any{{"feature_idx": []int{-1}, "threshold": []int{0}, "left": []int{0}, "right": []int{0}, "value": []int{0}, "missing_left": []int{0}, "is_leaf": []int{1}}}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(1)
	first, err := mlscore.NewEmbedded(.3, path)
	if err != nil {
		t.Fatal(err)
	}
	server := New(scan.New(scan.Options{ML: first, Detector: detect.New(tax)}), 1)
	snapshot := func(server *Server, body string) model.Scope {
		t.Helper()
		response := do(server, http.MethodPost, "/scan/batch", body)
		if response.Code != http.StatusOK {
			t.Fatal("worker failed", response.Code)
		}
		var result model.ScanResult
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || !result.Complete {
			t.Fatal("worker lost complete empty response", err)
		}
		for _, s := range result.Scope {
			if s.Kind == "ml_model" {
				return s
			}
		}
		t.Fatal("empty worker response omitted loaded model")
		return model.Scope{}
	}
	initial := snapshot(server, `[]`)
	write(2)
	second, err := mlscore.NewEmbedded(.3, path)
	if err != nil {
		t.Fatal(err)
	}
	if initial != snapshot(server, `[]`) {
		t.Fatal("worker reread replaced model")
	}
	if initial == snapshot(New(scan.New(scan.Options{ML: second, Detector: detect.New(tax)}), 1), `[]`) {
		t.Fatal("another loaded model received same policy")
	}
	if initial != snapshot(server, `[{"content":"","path":"owned.env"}]`) {
		t.Fatal("empty item lost same model snapshot")
	}
}
