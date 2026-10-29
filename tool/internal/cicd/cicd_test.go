package cicd

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/safehttp"
)

func allowLoopback(t *testing.T) {
	t.Helper()
	safehttp.AllowPrivate.Store(true)
	t.Cleanup(func() { safehttp.AllowPrivate.Store(false) })
}

func zipBytes(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(w, body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func drain(items <-chan model.Item) []model.Item {
	var out []model.Item
	for item := range items {
		out = append(out, item)
	}
	return out
}

func TestGitHubCollectLogsAndArtifactsStripsAuthOnRedirect(t *testing.T) {
	allowLoopback(t)
	logZip := zipBytes(t, map[string]string{"build/job.txt": `token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"`})
	artifactZip := zipBytes(t, map[string]string{"dist/config.env": `OPENAI_API_KEY="sk-proj-abcdefghijklmnopqrstuvwxyz123456"`})

	var mu sync.Mutex
	var leakedHeaders []string
	assets := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if v := r.Header.Get("Authorization"); v != "" {
			leakedHeaders = append(leakedHeaders, "Authorization="+v)
		}
		if v := r.Header.Get("PRIVATE-TOKEN"); v != "" {
			leakedHeaders = append(leakedHeaders, "PRIVATE-TOKEN="+v)
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/zip")
		switch r.URL.Path {
		case "/logs":
			_, _ = w.Write(logZip)
		case "/artifact":
			_, _ = w.Write(artifactZip)
		default:
			http.NotFound(w, r)
		}
	}))
	defer assets.Close()

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("%s Authorization = %q", r.URL.Path, got)
		}
		switch r.URL.Path {
		case "/repos/acme/app/actions/runs":
			_ = json.NewEncoder(w).Encode(map[string]any{"workflow_runs": []map[string]any{{
				"id": 7, "name": "CI", "html_url": "https://github.example/acme/app/actions/runs/7",
			}}})
		case "/repos/acme/app/actions/runs/7/logs":
			http.Redirect(w, r, assets.URL+"/logs", http.StatusFound)
		case "/repos/acme/app/actions/runs/7/artifacts":
			_ = json.NewEncoder(w).Encode(map[string]any{"artifacts": []map[string]any{{
				"id": 9, "name": "bundle", "expired": false,
			}}})
		case "/repos/acme/app/actions/artifacts/9/zip":
			http.Redirect(w, r, assets.URL+"/artifact", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()

	items, done, err := Collect(context.Background(), "github:acme/app", Options{
		BaseURL: api.URL, Token: "test-token", MaxRuns: 1, MaxArtifacts: 2,
		MaxDownload: 1 << 20, MaxItem: 1 << 20, IncludeLogs: true, IncludeArtifacts: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := drain(items)
	result := <-done
	if result.Failures != 0 || result.Runs != 1 || result.Artifacts != 1 || result.Items != 2 {
		t.Fatalf("result = %+v", result)
	}
	if len(got) != 2 {
		t.Fatalf("items = %d, want 2", len(got))
	}
	if !strings.Contains(got[0].Path, "/logs!/build/job.txt") || !strings.Contains(got[0].Text, "ghp_") {
		t.Fatalf("log item = %+v", got[0])
	}
	if !strings.Contains(got[1].Path, "/artifacts/bundle-9!/dist/config.env") || !strings.Contains(got[1].Text, "sk-proj-") {
		t.Fatalf("artifact item = %+v", got[1])
	}
	if got[0].Source != "ci" || got[0].Meta["url"] != "https://github.example/acme/app/actions/runs/7" {
		t.Fatalf("metadata = %+v", got[0])
	}
	mu.Lock()
	defer mu.Unlock()
	if len(leakedHeaders) != 0 {
		t.Fatalf("forge credentials leaked to redirect target: %v", leakedHeaders)
	}
}

func TestGitLabCollectTraceAndArtifact(t *testing.T) {
	allowLoopback(t)
	artifactZip := zipBytes(t, map[string]string{"reports/debug.txt": `password = "` + "\x50" + `rodPass-123456789"`})
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("PRIVATE-TOKEN"); got != "gl-token" {
			t.Errorf("%s PRIVATE-TOKEN = %q", r.URL.Path, got)
		}
		switch r.URL.EscapedPath() {
		case "/projects/group%2Fapp/pipelines":
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id": 11, "ref": "main", "web_url": "https://gitlab.example/group/app/-/pipelines/11",
			}})
		case "/projects/group%2Fapp/pipelines/11/jobs":
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id": 12, "name": "test", "web_url": "https://gitlab.example/group/app/-/jobs/12",
				"artifacts_file": map[string]any{"filename": "artifacts.zip", "size": len(artifactZip)},
			}})
		case "/projects/group%2Fapp/jobs/12/trace":
			_, _ = io.WriteString(w, `AWS_SECRET_ACCESS_KEY="abcdefghijklmnopqrstuvwxyz1234567890ABCD"`)
		case "/projects/group%2Fapp/jobs/12/artifacts":
			_, _ = w.Write(artifactZip)
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()

	items, done, err := Collect(context.Background(), "gitlab:group/app", Options{
		BaseURL: api.URL, Token: "gl-token", MaxRuns: 1, MaxArtifacts: 1,
		MaxDownload: 1 << 20, MaxItem: 1 << 20, IncludeLogs: true, IncludeArtifacts: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := drain(items)
	result := <-done
	if result.Failures != 0 || result.Runs != 1 || result.Artifacts != 1 || result.Items != 2 {
		t.Fatalf("result = %+v", result)
	}
	if len(got) != 2 || !strings.HasSuffix(got[0].Path, "/trace.log") ||
		!strings.Contains(got[1].Path, "/artifacts!/reports/debug.txt") {
		t.Fatalf("items = %+v", got)
	}
}

func TestCollectionReportsPartialFailure(t *testing.T) {
	allowLoopback(t)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/app/actions/runs":
			_ = json.NewEncoder(w).Encode(map[string]any{"workflow_runs": []map[string]any{{"id": 7, "name": "CI"}}})
		case "/repos/acme/app/actions/runs/7/logs":
			http.Error(w, "retention expired", http.StatusNotFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	items, done, err := Collect(context.Background(), "github:acme/app", Options{
		BaseURL: api.URL, Token: "token", MaxRuns: 1, MaxDownload: 1 << 20, MaxItem: 1 << 20,
		IncludeLogs: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := drain(items); len(got) != 1 || got[0].Error == nil || got[0].Source != "ci" {
		t.Fatalf("missing collection failure diagnostic: %+v", got)
	}
	result := <-done
	if result.Failures != 1 || result.LastError == nil {
		t.Fatalf("result = %+v", result)
	}
}

func TestOversizedCIContentIsAnIncompleteCollection(t *testing.T) {
	c := collector{opts: Options{MaxItem: 64, MaxDownload: 1 << 20}}
	for _, raw := range [][]byte{
		[]byte(strings.Repeat("x", 100)),
		zipBytes(t, map[string]string{"large.txt": strings.Repeat("x", 100), "keep.txt": "visible content"}),
	} {
		out := make(chan model.Item, 4)
		var result Result
		err := c.emitPayload(context.Background(), out, "ci/logs", "", raw, &result)
		close(out)
		items := drain(out)
		if err == nil || result.Skipped == 0 {
			t.Fatalf("oversized CI content silently skipped: err=%v result=%+v", err, result)
		}
		if len(raw) > 100 && (len(items) != 1 || items[0].Text != "visible content") {
			t.Fatalf("partial archive content lost: %+v", items)
		}
	}
}

func TestSignedRedirectErrorDoesNotLeakQuery(t *testing.T) {
	allowLoopback(t)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/app/actions/runs":
			_ = json.NewEncoder(w).Encode(map[string]any{"workflow_runs": []map[string]any{{"id": 7, "name": "CI"}}})
		case "/repos/acme/app/actions/runs/7/logs":
			http.Redirect(w, r, "http://127.0.0.1:1/archive.zip?sig=TOPSECRET", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	items, done, err := Collect(context.Background(), "github:acme/app", Options{
		BaseURL: api.URL, Token: "token", MaxRuns: 1, MaxDownload: 1 << 20, MaxItem: 1 << 20,
		IncludeLogs: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = drain(items)
	result := <-done
	if result.LastError == nil || strings.Contains(result.LastError.Error(), "TOPSECRET") {
		t.Fatalf("signed redirect leaked in error: %v", result.LastError)
	}
}

func TestCollectRejectsBadTargetAndMissingToken(t *testing.T) {
	if _, _, err := Collect(context.Background(), "github:owner", Options{Token: "x"}); err == nil {
		t.Fatal("target without owner/repo separator accepted")
	}
	if _, _, err := Collect(context.Background(), "github:owner/repo", Options{}); err == nil {
		t.Fatal("missing token accepted")
	}
}
