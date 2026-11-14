package mlmodel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validOwnedModel(t *testing.T) map[string]any {
	t.Helper()
	names := make([]string, NumFeatures)
	for i := range names {
		names[i] = "owned_feature"
	}
	return map[string]any{"baseline": 0.0, "feature_names": names, "trees": []any{map[string]any{
		"feature_idx": []any{-1}, "threshold": []any{0.0}, "left": []any{0}, "right": []any{0}, "value": []any{0.0}, "missing_left": []any{0}, "is_leaf": []any{1},
	}}}
}

func TestModelByteAndTreeBudgets(t *testing.T) {
	raw, err := json.Marshal(validOwnedModel(t))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "model.json")
	for _, size := range []int{maxModelBytes, maxModelBytes + 1} {
		payload := append(append([]byte(nil), raw...), []byte(strings.Repeat(" ", size-len(raw)))...)
		if err := os.WriteFile(path, payload, 0o600); err != nil {
			t.Fatal(err)
		}
		model, err := LoadFile(path)
		if size == maxModelBytes && (err != nil || model == nil) {
			t.Fatalf("model exactly at byte limit was rejected: %v", err)
		}
		if size > maxModelBytes && (err == nil || model != nil) {
			t.Fatal("oversized model was accepted")
		}
	}
	model := validOwnedModel(t)
	leaf := model["trees"].([]any)[0]
	trees := make([]any, maxModelTrees+1)
	for i := range trees {
		trees[i] = leaf
	}
	model["trees"] = trees
	raw, err = json.Marshal(model)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parse(raw); err == nil {
		t.Fatal("tree count limit was ignored")
	}
}

func TestModelNodeBudget(t *testing.T) {
	for _, n := range []int{maxModelNodes, maxModelNodes + 1} {
		model := validOwnedModel(t)
		zeros, leaves := make([]int, n), make([]int, n)
		for i := range leaves {
			leaves[i] = 1
		}
		model["trees"] = []any{map[string]any{"feature_idx": zeros, "threshold": zeros,
			"left": zeros, "right": zeros, "value": zeros, "missing_left": zeros, "is_leaf": leaves}}
		raw, err := json.Marshal(model)
		if err != nil {
			t.Fatal(err)
		}
		loaded, err := parse(raw)
		if n == maxModelNodes && (err != nil || loaded == nil) {
			t.Fatalf("model at node limit rejected: %v", err)
		}
		if n > maxModelNodes && (err == nil || loaded != nil) {
			t.Fatal("model node limit was ignored")
		}
	}
}

func TestModelRejectsUnreachableCyclesButAcceptsSharedChildren(t *testing.T) {
	for _, cycle := range []bool{false, true} {
		model := validOwnedModel(t)
		model["trees"] = []any{map[string]any{
			"feature_idx": []int{0, -1, 0}, "threshold": []float64{0, 0, 0},
			"left": []int{1, 0, 1}, "right": []int{1, 0, 1},
			"value": []float64{0, 1, 0}, "missing_left": []int{0, 0, 0}, "is_leaf": []int{0, 1, 0},
		}}
		if cycle {
			model["trees"].([]any)[0].(map[string]any)["left"] = []int{1, 0, 2}
		}
		raw, err := json.Marshal(model)
		if err != nil {
			t.Fatal(err)
		}
		loaded, err := parse(raw)
		if cycle && err == nil {
			t.Fatal("unreachable model cycle was accepted")
		}
		if !cycle {
			if err != nil {
				t.Fatal(err)
			}
			if _, err := loaded.Predict(make([]float64, NumFeatures)); err != nil {
				t.Fatalf("shared child could not be evaluated: %v", err)
			}
		}
	}
}

func TestModelRejectsMissingNullAndInvalidNumericFields(t *testing.T) {
	for _, field := range []string{"baseline", "feature_idx", "threshold", "left", "right", "value", "missing_left", "is_leaf"} {
		for _, mode := range []string{"missing", "null", "null element"} {
			if field == "baseline" && mode == "null element" {
				continue
			}
			t.Run(field+"/"+mode, func(t *testing.T) {
				model := validOwnedModel(t)
				object := model
				if field != "baseline" {
					object = model["trees"].([]any)[0].(map[string]any)
				}
				switch mode {
				case "missing":
					delete(object, field)
				case "null":
					object[field] = nil
				case "null element":
					object[field] = []any{nil}
				}
				raw, err := json.Marshal(model)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := parse(raw); err == nil {
					t.Fatal("malformed numeric model data became inference values")
				}
			})
		}
	}
}

func TestModelRejectsDuplicateFieldsAndInvalidFlags(t *testing.T) {
	raw, err := json.Marshal(validOwnedModel(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string]string{
		"baseline":     strings.Replace(string(raw), `"baseline":0`, `"baseline":0,"BASELINE":-100`, 1),
		"leaf flag":    strings.Replace(string(raw), `"is_leaf":[1]`, `"is_leaf":[2]`, 1),
		"missing flag": strings.Replace(string(raw), `"missing_left":[0]`, `"missing_left":[-1]`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parse([]byte(input)); err == nil {
				t.Fatal("ambiguous or invalid model schema was accepted")
			}
		})
	}
}
