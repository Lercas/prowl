package scan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/semantic"
)

func TestSemanticGeneratesCandidateOutsideL1WithLiteralEvidence(t *testing.T) {
	const text = "Код доступа для архива завтра: tulip-moon"
	const value = "tulip-moon"
	item := model.Item{Text: text, Source: "confluence", Path: "ARCHIVE-42"}
	det := detector(t)
	if fs := New(Options{Detector: det}).Findings(context.Background(), item); len(fs) != 0 {
		t.Fatal("test candidate already detected by L1")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Deliberately wrong character offsets: the unique literal is located by Go.
		content, _ := json.Marshal(map[string]any{"candidates": []semantic.Candidate{{Start: 1, End: 2, Value: value}}})
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]string{"content": string(content)}}}})
	}))
	defer srv.Close()
	e, err := semantic.New(semantic.Config{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	pipeline := New(Options{Detector: detector(t), Semantic: true, SemanticEngine: e})
	fs := pipeline.Findings(context.Background(), item)
	if len(fs) != 1 || fs[0].Type != "generic_semantic_secret" || len(fs[0].Evidence) != 1 || fs[0].Evidence[0].Start != strings.Index(text, value) || fs[0].Verified != nil {
		t.Fatal("semantic candidate missing or claimed as confirmed")
	}
}

func TestSemanticPreservedAcrossStructuredNormalization(t *testing.T) {
	const value = "tulip-moon"
	for _, c := range []struct{ path, text, source string }{
		{"config.json", `{"note":"tulip\u002dmoon"}`, `tulip\u002dmoon`},
		{"config.toml", `note="tulip\u002dmoon"`, `tulip\u002dmoon`},
	} {
		calls := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			content, _ := json.Marshal(map[string]any{"candidates": []semantic.Candidate{{Value: value}}})
			_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]string{"content": string(content)}}}})
		}))
		e, err := semantic.New(semantic.Config{URL: srv.URL})
		if err != nil {
			t.Fatal(err)
		}
		pipeline := New(Options{Detector: detector(t), Semantic: true, SemanticEngine: e})
		item := model.Item{Text: c.text, Path: c.path, Source: "code"}
		fs := pipeline.Findings(context.Background(), item)
		srv.Close()
		if calls != 1 || len(fs) != 1 || fs[0].Type != "generic_semantic_secret" || fs[0].Verified != nil || c.text[fs[0].ByteStart:fs[0].ByteEnd] != c.source || len(fs[0].Evidence) != 2 {
			t.Fatalf("structured semantic option/value/evidence lost: %s, calls=%d, findings=%+v", c.path, calls, fs)
		}
		if fs[0].Fingerprint != model.ComputeFingerprint("generic_semantic_secret", c.path, value) {
			t.Fatal("semantic structured candidate used lexical escape syntax as its identity")
		}
	}
}

func TestSemanticFailureAndOptOutAreVisible(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "private model response", 500)
	}))
	defer server.Close()
	e, err := semantic.New(semantic.Config{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	item := model.Item{Text: "ordinary text", Path: "production.txt", Source: "code"}
	for _, enabled := range []bool{false, true} {
		coverage := model.NewCoverage()
		p := New(Options{Detector: detector(t), Semantic: enabled, SemanticEngine: e})
		fs := p.Findings(model.WithCoverage(context.Background(), coverage), item)
		complete, _, _ := coverage.Snapshot()
		if complete == enabled || hasIncompleteFinding(fs) != enabled {
			t.Fatalf("semantic error disappeared: enabled=%v complete=%v", enabled, complete)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("disabled semantic stage contacted the model")
	}
	coverage := model.NewCoverage()
	fs := New(Options{Detector: detector(t), Semantic: true}).Findings(model.WithCoverage(context.Background(), coverage), item)
	if complete, _, _ := coverage.Snapshot(); complete || !hasIncompleteFinding(fs) {
		t.Fatal("missing configured semantic dependency looked clean")
	}
}

func TestSemanticDoesNotRescanReconstructedExpressions(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]string{"content": `{"candidates":[]}`}}}})
	}))
	defer server.Close()
	e, err := semantic.New(semantic.Config{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	item := model.Item{Text: `const head='AKIA';const key=head+'NAFGYOEYPXU1DSYP';`, Path: "bundle.js", Source: "code"}
	fs := New(Options{Detector: detector(t), Semantic: true, SemanticEngine: e, Reconstruct: true}).Findings(context.Background(), item)
	if calls.Load() != 1 || len(fs) != 1 || !strings.HasPrefix(fs[0].Stage, "reconstructed/") {
		t.Fatalf("semantic rescanned generated fragments: calls=%d findings=%v", calls.Load(), fs)
	}
}
