package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/safehttp"
)

const (
	mobAWSKey  = "AKIA4MNQ2RST7UVWX9YZ"
	mobAizaKey = "AIzaSyEXAMPLEplaceholder"
)

// writeAPK builds an in-memory ZIP from name->body and writes it to a temp .apk, returning the path.
func writeAPK(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range entries {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "fixture.apk")
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// findingsJSON is the shape of the json report (count + findings[]); only the fields we assert on.
type findingsJSON struct {
	Findings []struct {
		Type string `json:"type"`
		Path string `json:"path"`
	} `json:"findings"`
}

// TestCmdMobileLocalAPK: scanning a local APK with a planted AWS key writes a json report containing the
// finding (with the archive!/ path) and gates to exit 1 under --fail-on high.
func TestCmdMobileLocalAPK(t *testing.T) {
	body := []byte(fmt.Sprintf(`{"api_key":"%s"}`, mobAWSKey))
	apk := writeAPK(t, map[string][]byte{
		"res/raw/config.json":  body,
		"google-services.json": []byte(fmt.Sprintf(`{"client":[{"api_key":[{"current_key":"%s"}]}]}`, mobAizaKey)),
	})
	out := filepath.Join(t.TempDir(), "report.json")

	code := cmdMobile([]string{apk, "--format", "json", "--output", out, "--fail-on", "high"})
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (a high-severity AWS key was planted)", code)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var rep findingsJSON
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("report is not valid json: %v\n%s", err, raw)
	}
	var sawAWS bool
	for _, f := range rep.Findings {
		if strings.Contains(f.Type, "aws") {
			sawAWS = true
			if !strings.Contains(f.Path, ".apk!/") {
				t.Errorf("finding path %q lacks the .apk!/ archive prefix", f.Path)
			}
		}
	}
	if !sawAWS {
		t.Fatalf("no aws finding in the report; got %+v", rep.Findings)
	}
}

// TestCmdMobileMissingFile: a nonexistent local path exits 2.
func TestCmdMobileMissingFile(t *testing.T) {
	if code := cmdMobile([]string{filepath.Join(t.TempDir(), "no-such.apk")}); code != 2 {
		t.Fatalf("exit = %d, want 2 for a missing file", code)
	}
}

// TestCmdMobileNoTarget: no positional target exits 2.
func TestCmdMobileNoTarget(t *testing.T) {
	if code := cmdMobile([]string{"--no-strings"}); code != 2 {
		t.Fatalf("exit = %d, want 2 when no target is given", code)
	}
}

// TestCmdMobileUnknownFlagAccepted: the mobile-only flags must be in knownFlags (else checkUnknownFlags
// exits the process). Parsing a fixture with --min-run / --no-strings must NOT die on
// flag parse — a successful scan returns 0 here (no --fail-on).
func TestCmdMobileUnknownFlagAccepted(t *testing.T) {
	for _, f := range []string{"--min-run", "--no-strings"} {
		if !knownFlags[f] {
			t.Fatalf("%s missing from knownFlags; checkUnknownFlags would kill cmdMobile", f)
		}
	}
	apk := writeAPK(t, map[string][]byte{"res/raw/x.json": []byte(`{"k":"v"}`)})
	out := filepath.Join(t.TempDir(), "r.json")
	code := cmdMobile([]string{apk, "--min-run", "6", "--no-strings", "--format", "json", "--output", out})
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (clean fixture, flags should parse)", code)
	}
}

// TestDownloadToTempSSRF: a URL pointing at an internal address must be refused at dial by safehttp's
// guarded transport (NOT http.DefaultClient), surfacing the SSRF guard error.
func TestDownloadToTempSSRF(t *testing.T) {
	defer safehttp.AllowPrivate.Store(false)
	safehttp.AllowPrivate.Store(false)

	_, err := downloadToTemp(context.Background(), "http://127.0.0.1:9/app.apk", t.TempDir(), 10<<20, 2*time.Second)
	if err == nil {
		t.Fatal("download from an internal address should fail (SSRF guard)")
	}
	if !strings.Contains(err.Error(), "refusing to connect to internal address") {
		t.Fatalf("error %q does not show the SSRF dial guard fired; an unguarded client was used", err)
	}
}

func TestIsURL(t *testing.T) {
	cases := map[string]bool{
		"http://x/app.apk":  true,
		"https://x/app.ipa": true,
		"app.apk":           false,
		"/tmp/app.apk":      false,
		"ftp://x/app.apk":   false,
	}
	for in, want := range cases {
		if got := isURL(in); got != want {
			t.Errorf("isURL(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestDownloadName(t *testing.T) {
	cases := map[string]string{
		"https://x/build/app.apk":     "app.apk",
		"https://x/build/myapp.ipa":   "myapp.ipa",
		"https://x/build/app.apk?v=2": "app.apk",
		"https://x/":                  "app.apk",
		"https://x/path.ipa/":         "app.ipa",
	}
	for in, want := range cases {
		if got := downloadName(in); got != want {
			t.Errorf("downloadName(%q) = %q, want %q", in, got, want)
		}
	}
}
