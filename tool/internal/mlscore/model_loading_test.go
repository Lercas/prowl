package mlscore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Lercas/prowl/tool/internal/mlfeatures"
)

func ownedModelJSON(t *testing.T, names []string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"baseline": -100, "feature_names": names,
		"trees": []map[string]any{{"feature_idx": []int{-1}, "threshold": []float64{0}, "left": []int{0}, "right": []int{0}, "value": []float64{0}, "missing_left": []int{0}, "is_leaf": []int{1}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestEmbeddedRejectsIncompatibleFeatureOrder(t *testing.T) {
	if !mlfeatures.BuiltWithCgo() {
		t.Skip("in-process scorer requires cgo")
	}
	for _, mode := range []string{"reordered", "unknown", "duplicate", "empty"} {
		t.Run(mode, func(t *testing.T) {
			names := append([]string(nil), mlfeatures.FeatureNames...)
			switch mode {
			case "reordered":
				names[0], names[1] = names[1], names[0]
			case "unknown":
				names[0] = "private_model_metadata"
			case "duplicate":
				names[0] = names[1]
			case "empty":
				names[0] = ""
			}
			path := filepath.Join(t.TempDir(), "model.json")
			if err := os.WriteFile(path, ownedModelJSON(t, names), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewEmbedded(0.3, path); err == nil {
				t.Fatal("model feature schema does not match the extractor but scoring was enabled")
			}
		})
	}
}

func TestInstalledModelBrokenLinkCannotFallBackToEmbedded(t *testing.T) {
	home := t.TempDir()
	t.Setenv("PROWL_HOME", home)
	if err := os.Symlink(filepath.Join(home, "missing.json"), filepath.Join(home, "model_binary.json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := resolveModel(""); err == nil {
		t.Fatal("a selected broken model link silently activated the embedded model")
	}
}
