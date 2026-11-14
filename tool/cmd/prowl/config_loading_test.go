package main

import (
	"os"
	"testing"
)

func TestDiscoveredConfigFailsBeforeSourceAndBaseline(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("PROWL_HOME", t.TempDir())
	if err := os.WriteFile(".prowl.yaml", []byte("detectors: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("prod.env", []byte("credential=EDITOR_Q7K8M9N0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := cmdScan([]string{"prod.env", "--output", "report.json", "--write-baseline", "baseline.json", "--silence"}); code != 2 {
		t.Fatalf("invalid discovered config returned %d", code)
	}
	for _, file := range []string{"report.json", "baseline.json"} {
		if _, err := os.Stat(file); !os.IsNotExist(err) {
			t.Errorf("created %s after policy failure", file)
		}
	}
}

func TestInvalidExplicitConfigPrecedesBucketAcquisition(t *testing.T) {
	t.Chdir(t.TempDir())
	fakeBucketCLI(t, "0")
	marker := "started"
	t.Setenv("PROWL_BUCKET_STARTED", marker)
	if err := os.WriteFile("operator.yaml", []byte("allowlist: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := cmdBucket([]string{"s3://owned/prefix", "--config", "operator.yaml", "--silence"}); code != 2 {
		t.Fatalf("invalid operator config returned %d", code)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("bucket acquired before config validation")
	}
}
