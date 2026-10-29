package main

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func fakeBucketCLI(t *testing.T, exit string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake cloud CLI is POSIX-only")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\nif [ -n \"$PROWL_BUCKET_STARTED\" ]; then printf started > \"$PROWL_BUCKET_STARTED\"; fi\nif [ \"${0##*/}\" = gcloud ]; then dest=\"$5\"; else dest=\"$4\"; fi\nprintf 'AWS = \"AKIANAFGYOEYPXU1DSYP\"\\n' > \"$dest/${PROWL_BUCKET_FILE:-prod.env}\"\nexit " + exit + "\n"
	for _, name := range []string{"aws", "gcloud"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PROWL_HOME", t.TempDir())
}

func TestBucketInvalidVerifierSetupPrecedesDownload(t *testing.T) {
	fakeBucketCLI(t, "0")
	marker := filepath.Join(t.TempDir(), "started")
	t.Setenv("PROWL_BUCKET_STARTED", marker)
	if code := cmdBucket([]string{"s3://owned/prefix", "--verified-only", "--verifiers", t.TempDir(), "--silence"}); code != 2 {
		t.Fatal("empty verifier set was accepted")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("cloud acquisition happened before verifier preflight failed")
	}
}

func TestBucketOperatorConfigPathsAndGoogleCLI(t *testing.T) {
	fakeBucketCLI(t, "0")
	t.Chdir(t.TempDir())
	if err := os.WriteFile("operator.yaml", []byte("version: 1\nallowlist:\n  paths: ['prod.env']\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := cmdBucket([]string{"gs://owned/prefix", "--config", "operator.yaml", "--format", "json", "--output", "report.json", "--silence"}); code != 0 {
		t.Fatalf("relative operator config failed: %d", code)
	}
	truncated, fs := readBucketReport(t, "report.json")
	if truncated || len(fs) != 0 {
		t.Fatalf("operator config was ignored: %+v", fs)
	}
	for _, flags := range [][]string{{"--staged"}, {"--since", "HEAD"}, {"--history"}} {
		if code := cmdBucket(append([]string{"s3://owned/prefix", "--silence"}, flags...)); code != 2 {
			t.Fatalf("unsupported Git source mode was ignored: %v", flags)
		}
	}
}

func readBucketReport(t *testing.T, path string) (bool, []model.Finding) {
	t.Helper()
	raw, err := os.ReadFile(path)
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
	return report.Truncated, report.Findings
}

func TestBucketRelativeOutputAndBaselineSurviveDownloadCleanup(t *testing.T) {
	fakeBucketCLI(t, "0")
	t.Chdir(t.TempDir())
	if code := cmdBucket([]string{"s3://owned/prefix", "--format", "json", "--output", "report.json", "--silence"}); code != 0 {
		t.Fatalf("bucket scan returned %d", code)
	}
	truncated, fs := readBucketReport(t, "report.json")
	if truncated || len(fs) != 1 || fs[0].Path != "s3://owned/prefix/prod.env" {
		t.Fatalf("unexpected successful report: truncated=%v findings=%+v", truncated, fs)
	}
	if code := cmdBucket([]string{"s3://owned/prefix", "--write-baseline", "baseline.json", "--silence"}); code != 0 {
		t.Fatalf("baseline scan returned %d", code)
	}
	if _, err := os.Stat("baseline.json"); err != nil {
		t.Fatalf("relative baseline disappeared: %v", err)
	}
	if code := cmdBucket([]string{"s3://owned/prefix", "--format", "json", "--output", "suppressed.json", "--baseline", "baseline.json", "--silence"}); code != 0 {
		t.Fatalf("baseline readback returned %d", code)
	}
	truncated, fs = readBucketReport(t, "suppressed.json")
	if truncated || len(fs) != 0 {
		t.Fatalf("bucket identity changed between downloads: %+v", fs)
	}
}

func TestBucketDownloadFailureRetainsFindingsAndRejectsBaseline(t *testing.T) {
	fakeBucketCLI(t, "1")
	dir := t.TempDir()
	out, base := filepath.Join(dir, "report.json"), filepath.Join(dir, "baseline.json")
	if code := cmdBucket([]string{"s3://owned/prefix", "--format", "json", "--output", out, "--write-baseline", base, "--silence"}); code != 2 {
		t.Fatalf("incomplete download returned %d", code)
	}
	truncated, fs := readBucketReport(t, out)
	found, diagnostic := false, false
	for _, f := range fs {
		found = found || f.Type == "aws_access_key_id"
		diagnostic = diagnostic || model.IsIncompleteFinding(f)
		if strings.Contains(f.Path, "prowl-bucket-") {
			t.Fatal("temporary download path leaked into report identity")
		}
	}
	if !truncated || !found || !diagnostic {
		t.Fatalf("partial download lost evidence: truncated=%v findings=%+v", truncated, fs)
	}
	if _, err := os.Stat(base); !os.IsNotExist(err) {
		t.Fatalf("baseline written for a partial download: %v", err)
	}
}

func TestBucketSARIFLiteralObjectKeys(t *testing.T) {
	for _, scheme := range []string{"s3", "gs"} {
		for _, exit := range []string{"0", "1"} {
			t.Run(scheme+"/exit-"+exit, func(t *testing.T) {
				fakeBucketCLI(t, exit)
				const filename = "Ключ #?%20.env"
				t.Setenv("PROWL_BUCKET_FILE", filename)
				uri := scheme + "://owned/prefix#?%20"
				dir := t.TempDir()
				jsonPath, sarifPath := filepath.Join(dir, "report.json"), filepath.Join(dir, "report.sarif")
				wantCode := 0
				if exit == "1" {
					wantCode = 2
				}
				for _, output := range []struct{ format, path string }{{"json", jsonPath}, {"sarif", sarifPath}} {
					if code := cmdBucket([]string{uri, "--format", output.format, "--output", output.path, "--silence"}); code != wantCode {
						t.Fatalf("%s returned %d, want %d", output.format, code, wantCode)
					}
				}
				_, fs := readBucketReport(t, jsonPath)
				wantPaths := map[string]string{}
				for _, f := range fs {
					wantPaths[f.Type] = strings.TrimPrefix(f.Path, scheme+"://owned")
					if f.Type == "aws_access_key_id" && f.Path != uri+"/"+filename {
						t.Fatal("public path identity changed")
					}
				}
				data, err := os.ReadFile(sarifPath)
				if err != nil {
					t.Fatal(err)
				}
				var doc struct {
					Runs []struct {
						Results []struct {
							RuleID    string
							Locations []struct {
								PhysicalLocation struct{ ArtifactLocation struct{ URI string } }
							}
						}
					}
				}
				if err := json.Unmarshal(data, &doc); err != nil {
					t.Fatal(err)
				}
				if len(doc.Runs[0].Results) != len(wantPaths) || len(wantPaths) == 0 {
					t.Fatal("fixture lost findings or diagnostics")
				}
				for _, r := range doc.Runs[0].Results {
					address := r.Locations[0].PhysicalLocation.ArtifactLocation.URI
					u, err := url.Parse(address)
					if err != nil || u.Scheme != scheme || u.Host != "owned" || u.Path != wantPaths[r.RuleID] || u.RawQuery != "" || u.Fragment != "" {
						t.Errorf("object key was reinterpreted: %q (%v)", address, err)
					}
				}
			})
		}
	}
}
