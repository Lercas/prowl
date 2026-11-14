package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/model"
)

func TestRepoFailureDiagnosticsAndBaselineRemainSafe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake Git command is POSIX-only")
	}
	const secret = "OWNED_REPO_URL_SECRET"
	const separate = "OWNED_REPO_HELPER_SECRET"
	bin := t.TempDir()
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" >&2\nprintf '%s\\n' '" + separate + "' >&2\nexit 7\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PROWL_HOME", t.TempDir())
	t.Chdir(t.TempDir())
	for _, format := range []string{"console", "json"} {
		for _, show := range []bool{false, true} {
			t.Run(format+map[bool]string{true: "/show", false: "/redacted"}[show], func(t *testing.T) {
				dir := t.TempDir()
				out, baseline := filepath.Join(dir, "report.json"), filepath.Join(dir, "baseline.json")
				const previous = "owned baseline must remain byte-identical"
				if err := os.WriteFile(baseline, []byte(previous), 0o600); err != nil {
					t.Fatal(err)
				}
				log, err := os.Create(filepath.Join(dir, "log"))
				if err != nil {
					t.Fatal(err)
				}
				stderr := os.Stderr
				os.Stderr = log
				defer func() { os.Stderr = stderr; logx.Setup(logx.Options{}); log.Close() }()
				args := []string{"https://user:" + secret + "@owned.invalid?mail=a@b", "--format", "json", "--output", out, "--write-baseline", baseline, "--log-format", format}
				if show {
					args = append(args, "--show-secrets")
				}
				if code := cmdRepo(args); code != 2 {
					t.Fatalf("incomplete clone returned %d", code)
				}
				data, err := os.ReadFile(log.Name())
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(data), secret) || strings.Contains(string(data), separate) || !strings.Contains(string(data), "exit status 7") {
					t.Fatalf("unsafe or incomplete clone diagnostics: %s", data)
				}
				truncated, fs := readBucketReport(t, out)
				if !truncated || len(fs) != 1 || !model.IsIncompleteFinding(fs[0]) || fs[0].Path != "https://***@owned.invalid?mail=a@b" {
					t.Fatalf("clone error lost provenance or completeness: truncated=%v findings=%+v", truncated, fs)
				}
				data, err = os.ReadFile(baseline)
				if err != nil || string(data) != previous {
					t.Fatalf("incomplete clone modified baseline: %q %v", data, err)
				}
			})
		}
	}
}
