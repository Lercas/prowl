package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"

	"github.com/Lercas/prowl/tool/internal/safehttp"
	"path/filepath"
	"testing"
)

func partialVerifierSet(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	good := `id: owned
match: [aws_access_key_id]
requests:
  - url: https://owned.invalid/identity
    headers:
      Authorization: "Bearer {{secret}}"
    matchers:
      - type: status
        status: [200]
`
	bad := `id: broken
match: [broken]
requests:
  - url: https://owned.invalid/identity
    matchers:
      - type: regex
        regex: ['[']
`
	for name, body := range map[string]string{"good.yaml": good, "bad.yaml": bad} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestPartialVerifierRegistryCannotPretendSetupSucceeded(t *testing.T) {
	dir := partialVerifierSet(t)
	if set, err := loadVerifySet(commonFlags{verify: true, verifiers: []string{dir}}); err == nil || set != nil {
		t.Fatalf("partial verifier registry accepted: set=%v err=%v", set, err)
	}
}

func TestPartialVerifierRegistryFailsBeforeBucketAcquisition(t *testing.T) {
	fakeBucketCLI(t, "0")
	marker := filepath.Join(t.TempDir(), "started")
	t.Setenv("PROWL_BUCKET_STARTED", marker)
	if code := cmdBucket([]string{"s3://owned/prefix", "--verify", "--verifiers", partialVerifierSet(t), "--silence"}); code != 2 {
		t.Fatalf("partial verifier registry returned %d", code)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("acquisition preceded verifier setup error")
	}
}

func TestVerifierSetupPrecedesMobileAndCICDAcquisition(t *testing.T) {
	for _, command := range []string{"mobile", "cicd"} {
		t.Run(command, func(t *testing.T) {
			previous := safehttp.AllowPrivate.Swap(true)
			t.Cleanup(func() { safehttp.AllowPrivate.Store(previous) })
			var calls atomic.Int64
			apk := writeAPK(t, map[string][]byte{"config.json": []byte(`{"clean":true}`)})
			raw, err := os.ReadFile(apk)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if command == "mobile" {
					_, _ = w.Write(raw)
				} else {
					_, _ = w.Write([]byte(`{"workflow_runs":[]}`))
				}
			}))
			t.Cleanup(server.Close)
			t.Setenv("PROWL_HOME", t.TempDir())
			t.Setenv("GITHUB_TOKEN", "owned-api-token")
			t.Setenv("GITHUB_API", server.URL)
			flags := []string{"--verify", "--verifiers", partialVerifierSet(t), "--silence"}
			code := 0
			if command == "mobile" {
				code = cmdMobile(append([]string{server.URL + "/app.apk"}, flags...))
			} else {
				code = cmdCICD(append([]string{"github:owned/app", "--logs-only"}, flags...))
			}
			if code != 2 || calls.Load() != 0 {
				t.Fatalf("%s acquisition preceded setup: code=%d requests=%d", command, code, calls.Load())
			}
		})
	}
}
