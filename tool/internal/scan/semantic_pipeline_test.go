package scan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/semantic"
)

func TestSemanticGeneratesCandidateOutsideL1WithLiteralEvidence(t *testing.T) {
	const text = "Код доступа для архива завтра: tulip-moon"
	const value = "tulip-moon"
	item := model.Item{Text: text, Source: "confluence", Path: "ARCHIVE-42"}
	det := detector(t)
	if fs := Findings(context.Background(), det, nil, nil, item, nil, nil); len(fs) != 0 {
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
	ctx := WithOptions(context.Background(), Options{Semantic: true, SemanticEngine: e})
	fs := Findings(ctx, det, nil, nil, item, nil, nil)
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
		ctx := WithOptions(context.Background(), Options{Semantic: true, SemanticEngine: e})
		item := model.Item{Text: c.text, Path: c.path, Source: "code"}
		fs := Findings(ctx, detector(t), nil, nil, item, nil, nil)
		srv.Close()
		if calls != 1 || len(fs) != 1 || fs[0].Type != "generic_semantic_secret" || fs[0].Verified != nil || c.text[fs[0].ByteStart:fs[0].ByteEnd] != c.source || len(fs[0].Evidence) != 2 {
			t.Fatalf("structured semantic option/value/evidence lost: %s, calls=%d, findings=%+v", c.path, calls, fs)
		}
		if fs[0].Fingerprint != model.ComputeFingerprint("generic_semantic_secret", c.path, value) {
			t.Fatal("semantic structured candidate used lexical escape syntax as its identity")
		}
	}
}
