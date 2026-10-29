package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/safehttp"
)

func TestAtlassianConnectionLogsDoNotExposeBaseURL(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("PROWL_HOME", t.TempDir())
	t.Setenv("PROWL_ALLOW_PRIVATE_IPS", "1")
	old := safehttp.AllowPrivate.Swap(true)
	t.Cleanup(func() { safehttp.AllowPrivate.Store(old) })
	for _, key := range []string{"ATLASSIAN_BASE_URL", "ATLASSIAN_EMAIL", "ATLASSIAN_API_TOKEN", "ATLASSIAN_USER", "ATLASSIAN_PASS", "ATLASSIAN_PASSWORD"} {
		t.Setenv(key, "")
	}
	t.Setenv("ATLASSIAN_PAT", "synthetic-owned-auth-token")
	const secret = "OWNED_CLI_BASE_SECRET_SENTINEL"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/rest/api/2/serverInfo") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"deploymentType":"Cloud"}`))
			return
		}
		// Confluence recognizes an auth-gated probe, then the listing fails. Jira connects via
		// serverInfo before its search fails. Both paths exercise the successful connection log.
		http.Error(w, secret, http.StatusForbidden)
	}))
	defer server.Close()
	base := strings.Replace(server.URL, "://", "://user:"+secret+"@", 1) + "/" + secret + "?token=" + secret
	for _, product := range []string{"jira", "confluence"} {
		for _, format := range []string{"console", "json"} {
			t.Run(product+"/"+format, func(t *testing.T) {
				f, err := os.CreateTemp(t.TempDir(), "output")
				if err != nil {
					t.Fatal(err)
				}
				stdout, stderr := os.Stdout, os.Stderr
				os.Stdout, os.Stderr = f, f
				defer func() { os.Stdout, os.Stderr = stdout, stderr; logx.Setup(logx.Options{}); f.Close() }()
				code := cmdAtlassian([]string{base, "--current-only", "--project", "P", "--format", "json", "--log-format", format}, product)
				b, err := os.ReadFile(f.Name())
				if err != nil {
					t.Fatal(err)
				}
				if code != 2 || !strings.Contains(string(b), "connected") || strings.Contains(string(b), secret) || strings.Contains(string(b), "synthetic-owned-auth-token") {
					t.Errorf("connection diagnostics exposed input or lost failure state: code=%d output=%s", code, b)
				}
			})
		}
	}
}
