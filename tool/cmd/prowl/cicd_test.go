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

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/safehttp"
)

func TestCmdCICDPartialFailureCannotCreateBaseline(t *testing.T) {
	safehttp.AllowPrivate.Store(true)
	t.Cleanup(func() { safehttp.AllowPrivate.Store(false) })
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/app/actions/runs":
			_ = json.NewEncoder(w).Encode(map[string]any{"workflow_runs": []map[string]any{
				{"id": 7, "name": "CI"}, {"id": 8, "name": "missing"},
			}})
		case "/repos/acme/app/actions/runs/7/logs":
			_, _ = io.WriteString(w, `AWS = "AKIANAFGYOEYPXU1DSYP"`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("GITHUB_TOKEN", "command-token")
	t.Setenv("GITHUB_API", api.URL)
	t.Setenv("PROWL_HOME", filepath.Join(dir, "home"))
	for _, baseline := range []bool{false, true} {
		out := filepath.Join(t.TempDir(), "report.json")
		baselinePath := filepath.Join(t.TempDir(), "baseline.json")
		args := []string{"github:acme/app", "--logs-only", "--max-runs", "2", "--fail-on", "high", "--silence", "--format", "json", "--output", out}
		if baseline {
			args = append(args, "--write-baseline", baselinePath)
		}
		if code := cmdCICD(args); code != 2 {
			t.Errorf("baseline=%v: incomplete CI collection returned %d", baseline, code)
		}
		if baseline {
			if _, err := os.Stat(baselinePath); !os.IsNotExist(err) {
				t.Errorf("baseline created from partial CI collection: %v", err)
			}
			continue
		}
		raw, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		var report struct {
			Truncated bool
			Findings  []model.Finding
		}
		if err := json.Unmarshal(raw, &report); err != nil {
			t.Fatal(err)
		}
		if !report.Truncated || len(report.Findings) < 2 {
			t.Errorf("partial CI JSON was certified complete: %+v", report)
		}
	}
}

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
