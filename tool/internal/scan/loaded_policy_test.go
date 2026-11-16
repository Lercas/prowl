package scan

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Lercas/prowl/tool/internal/mlfeatures"
	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/verify"
)

func writePolicyModel(t *testing.T, path string, bias float64) {
	t.Helper()
	data, err := json.Marshal(map[string]any{"baseline": bias, "feature_names": mlfeatures.FeatureNames, "trees": []map[string]any{{"feature_idx": []int{-1}, "threshold": []int{0}, "left": []int{0}, "right": []int{0}, "value": []int{0}, "missing_left": []int{0}, "is_leaf": []int{1}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func loadedPolicyScopes(t *testing.T, options Options) []model.Scope {
	t.Helper()
	coverage := model.NewCoverage()
	New(options).RegisterPolicy(model.WithCoverage(t.Context(), coverage))
	result := model.NewResult(nil, coverage)
	if !result.Complete {
		t.Fatal("policy-only registration marked valid processing incomplete")
	}
	return result.Scope
}
func scopeOfKind(scopes []model.Scope, kind string) model.Scope {
	for _, s := range scopes {
		if s.Kind == kind {
			return s
		}
	}
	return model.Scope{}
}
func TestLoadedMLPolicySnapshotThresholdAndPrivacy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private-model-path-marker.json")
	writePolicyModel(t, path, 1)
	first, err := mlscore.NewEmbedded(.3, path)
	if err != nil {
		t.Fatal(err)
	}
	initial := scopeOfKind(loadedPolicyScopes(t, Options{ML: first}), "ml_model")
	if initial.Kind == "" {
		t.Fatal("model identity not registered")
	}
	writePolicyModel(t, path, 2)
	second, err := mlscore.NewEmbedded(.3, path)
	if err != nil {
		t.Fatal(err)
	}
	if initial == scopeOfKind(loadedPolicyScopes(t, Options{ML: second}), "ml_model") {
		t.Fatal("same-path model replacement reused policy")
	}
	if initial != scopeOfKind(loadedPolicyScopes(t, Options{ML: first}), "ml_model") {
		t.Fatal("old snapshot identity reread source")
	}
	if first.PolicyID() != first.WithThreshold(.8).PolicyID() || initial == scopeOfKind(loadedPolicyScopes(t, Options{ML: first.WithThreshold(.8)}), "ml_model") {
		t.Fatal("model snapshot and threshold were conflated or threshold omitted")
	}
	wrapper := comparisonScorer{scorer: first, threshold: .3}
	if initial != scopeOfKind(loadedPolicyScopes(t, Options{ML: wrapper}), "ml_model") {
		t.Fatal("comparison wrapper hid loaded identity")
	}
	scopes := loadedPolicyScopes(t, Options{ML: first, IdentityKey: []byte(strings.Repeat("a", 32))})
	encoded, _ := json.Marshal(scopes)
	if strings.Contains(string(encoded), "private-model-path-marker") || strings.Contains(string(encoded), first.PolicyID()) || initial == scopeOfKind(scopes, "ml_model") {
		t.Fatal("scope leaked loaded metadata or ignored keyed policy identity")
	}
}

type identifiedPolicyScorer struct {
	fixedMLScorer
	id    string
	calls *atomic.Int32
}

func (s identifiedPolicyScorer) PolicyID() string {
	if s.calls != nil {
		s.calls.Add(1)
	}
	return s.id
}
func TestLoadedMLUnknownIdentityAndInvalidThresholdRemainUnversioned(t *testing.T) {
	for _, scorer := range []mlscore.Scorer{
		fixedMLScorer{threshold: .3},
		mlscore.New("https://private-user:private-password@owned.invalid", .3),
		identifiedPolicyScorer{fixedMLScorer: fixedMLScorer{threshold: .3}, id: ""},
		identifiedPolicyScorer{fixedMLScorer: fixedMLScorer{threshold: .3}, id: "not-a-digest"},
		identifiedPolicyScorer{fixedMLScorer: fixedMLScorer{threshold: math.NaN()}, id: strings.Repeat("a", 64)},
	} {
		scopes := loadedPolicyScopes(t, Options{ML: scorer})
		if scopeOfKind(scopes, "unversioned_policy").Kind == "" || scopeOfKind(scopes, "ml_model").Kind != "" {
			t.Fatal("unidentified scorer claimed immutable identity", scopes)
		}
		serialized, _ := json.Marshal(scopes)
		if strings.Contains(string(serialized), "private-password") {
			t.Fatal("endpoint secret disclosed")
		}
	}
}
func TestLoadedPolicySharedByWorkers(t *testing.T) {
	var calls atomic.Int32
	scorer := identifiedPolicyScorer{fixedMLScorer: fixedMLScorer{threshold: .3}, id: strings.Repeat("a", 64), calls: &calls}
	coverage := model.NewCoverage()
	p := New(Options{Detector: detector(t), ML: scorer, Workers: 4})
	items := make([]model.Item, 32)
	for i := range items {
		items[i] = model.Item{Source: "code", Path: "owned.env", Text: "ordinary text"}
	}
	p.Run(model.WithCoverage(context.Background(), coverage), feed(items...))
	if calls.Load() != 1 || scopeOfKind(model.NewResult(nil, coverage).Scope, "ml_model").Kind == "" {
		t.Fatal("workers rehashed or lost loaded snapshot identity", calls.Load())
	}
}
func TestLoadedVerifierPolicyRegisteredWithoutSourceDisclosure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private-verifier-path-marker.yaml")
	text := "id: owned\nmatch: [aws_access_key_id]\nrequests:\n - url: https://owned.invalid/private-endpoint-marker\n   headers: {Authorization: private-header-marker}\n   matchers:\n    - type: status\n      status: [200]\n"
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	first, err := verify.Load(0, path)
	if err != nil {
		t.Fatal(err)
	}
	initial := scopeOfKind(loadedPolicyScopes(t, Options{Verifiers: first}), "verifiers")
	if initial.Kind == "" {
		t.Fatal("verifier identity missing")
	}
	if err := os.WriteFile(path, []byte(strings.Replace(text, "[200]", "[201]", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	second, err := verify.Load(0, path)
	if err != nil {
		t.Fatal(err)
	}
	if initial == scopeOfKind(loadedPolicyScopes(t, Options{Verifiers: second}), "verifiers") || initial != scopeOfKind(loadedPolicyScopes(t, Options{Verifiers: first}), "verifiers") {
		t.Fatal("loaded verifier snapshot was replaced or omitted")
	}
	raw, _ := json.Marshal(initial)
	for _, marker := range []string{"private-verifier-path-marker", "private-endpoint-marker", "private-header-marker"} {
		if strings.Contains(string(raw), marker) {
			t.Fatal("policy disclosed source content")
		}
	}
}
