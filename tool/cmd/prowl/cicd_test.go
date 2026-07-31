package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/safehttp"
)

func TestCmdCICDGitHubEndToEnd(t *testing.T) {
	safehttp.AllowPrivate.Store(true)
	t.Cleanup(func() { safehttp.AllowPrivate.Store(false) })
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer command-token" {
			t.Errorf("Authorization = %q", got)
		}
		switch r.URL.Path {
		case "/repos/acme/app/actions/runs":
			_ = json.NewEncoder(w).Encode(map[string]any{"workflow_runs": []map[string]any{{
				"id": 7, "name": "CI", "html_url": "https://github.example/acme/app/actions/runs/7",
			}}})
		case "/repos/acme/app/actions/runs/7/logs":
			_, _ = io.WriteString(w, `aws_access_key_id = "AKIA4MNQ2RST7UVWX9YZ"`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()

	t.Setenv("GITHUB_TOKEN", "command-token")
	t.Setenv("GITHUB_API", api.URL)
	t.Setenv("PROWL_HOME", t.TempDir())
	out := filepath.Join(t.TempDir(), "report.json")
	code := cmdCICD([]string{
		"github:acme/app", "--logs-only", "--max-runs", "1",
		"--format", "json", "--output", out,
	})
	if code != 0 {
		t.Fatalf("cmdCICD returned %d", code)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"aws_access_key_id"`) ||
		!strings.Contains(string(raw), `github:acme/app/actions/CI-7/logs`) {
		t.Fatalf("report = %s", raw)
	}
}

func TestCmdCICDRequiresTokenAndOneTarget(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	if code := cmdCICD([]string{"github:acme/app"}); code != 2 {
		t.Fatalf("missing token returned %d", code)
	}
	if code := cmdCICD([]string{"github:acme/app", "github:acme/other"}); code != 2 {
		t.Fatalf("multiple targets returned %d", code)
	}
}
