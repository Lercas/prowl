package semantic

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLiteralSpanValidation(t *testing.T) {
	text := "Пароль для входа завтра: Autumn!7Road"
	start := strings.Index(text, "Autumn")
	for _, bad := range []bool{false, true} {
		t.Run(map[bool]string{false: "literal", true: "hallucinated"}[bad], func(t *testing.T) {
			value := "Autumn!7Road"
			if bad {
				value = "Invented!42"
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				content, _ := json.Marshal(map[string]any{"candidates": []Candidate{{start, len(text), value}}})
				_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]string{"content": string(content)}}}})
			}))
			defer srv.Close()
			e, err := New(Config{URL: srv.URL})
			if err != nil {
				t.Fatal(err)
			}
			cs, limited, err := e.Discover(context.Background(), text)
			if bad {
				if err == nil || len(cs) != 0 {
					t.Fatal("invented value accepted")
				}
			} else if err != nil || limited || len(cs) != 1 || cs[0].Start != start {
				t.Fatalf("lost literal candidate: %v", err)
			}
		})
	}
}
func TestRemotePolicy(t *testing.T) {
	for _, url := range []string{"https://example.invalid/v1/chat/completions", "http://192.168.1.1/v1/chat/completions"} {
		if _, err := New(Config{URL: url}); err == nil {
			t.Fatal("remote inference without opt-in")
		}
	}
}

func TestAbsentOrNullCandidateArrayIsNotACleanModelVerdict(t *testing.T) {
	for _, content := range []string{`{"other":"candidates"}`, `{"candidates":null}`, `{}`} {
		t.Run(content, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]string{"content": content}}}})
			}))
			defer srv.Close()
			e, err := New(Config{URL: srv.URL})
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := e.Discover(context.Background(), "a nonempty document"); err == nil {
				t.Fatal("malformed model result was accepted as clean")
			}
		})
	}
}
