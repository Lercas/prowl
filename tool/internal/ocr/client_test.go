package ocr

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var onePixelPNG, _ = base64.StdEncoding.DecodeString(
	"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
)

func TestEngineExtractImageOpenAICompatible(t *testing.T) {
	var authorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get("Authorization")
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["model"] != "test-model" || body["temperature"] != float64(0) {
			t.Errorf("body = %+v", body)
		}
		messages := body["messages"].([]any)
		content := messages[0].(map[string]any)["content"].([]any)
		image := content[1].(map[string]any)["image_url"].(map[string]any)["url"].(string)
		if !strings.HasPrefix(image, "data:image/png;base64,") {
			t.Errorf("image URL = %q", image)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"` +
			"```text\\naws_access_key_id = \\\"AKIA4MNQ2RST7UVWX9YZ\\\"\\n```" +
			`"}}]}`))
	}))
	defer server.Close()

	engine, err := New(Config{
		URL: server.URL, Model: "test-model", APIKey: "local-token", Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	text, err := engine.ExtractImage(context.Background(), onePixelPNG)
	if err != nil {
		t.Fatal(err)
	}
	if authorization != "Bearer local-token" || !strings.Contains(text, "AKIA4MNQ2RST7UVWX9YZ") ||
		strings.Contains(text, "```") {
		t.Fatalf("authorization=%q text=%q", authorization, text)
	}
	stats := engine.Stats()
	if stats.Calls != 1 || stats.Failures != 0 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestEndpointSafety(t *testing.T) {
	for _, raw := range []string{
		"http://example.com/v1/chat/completions",
		"http://10.0.0.2/v1/chat/completions",
		"http://user:pass@127.0.0.1/v1/chat/completions",
	} {
		if _, err := New(Config{URL: raw}); err == nil {
			t.Errorf("New(%q) should fail", raw)
		}
	}
	if _, err := New(Config{
		URL: "http://example.com/v1/chat/completions", AllowRemote: true,
	}); err == nil {
		t.Error("remote plain HTTP should fail even with AllowRemote")
	}
	if _, err := New(Config{
		URL: "https://example.com/v1/chat/completions", AllowRemote: true,
	}); err != nil {
		t.Fatalf("explicit remote HTTPS: %v", err)
	}
}

func TestResponseLimitsAndFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"too long"}}]}`))
	}))
	defer server.Close()
	engine, err := New(Config{URL: server.URL, MaxOutput: 3})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.ExtractImage(context.Background(), onePixelPNG); err == nil {
		t.Fatal("oversized OCR output should fail")
	}
	if stats := engine.Stats(); stats.Failures != 1 || stats.Calls != 1 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestImageFormatsAndSkipAccounting(t *testing.T) {
	engine, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.ExtractImage(context.Background(), []byte("not an image")); err == nil {
		t.Fatal("non-image should fail")
	}
	engine.Skip(4, "page limit")
	stats := engine.Stats()
	if stats.Failures != 1 || stats.Skipped != 4 || stats.LastError != "page limit" {
		t.Fatalf("stats = %+v", stats)
	}
}
