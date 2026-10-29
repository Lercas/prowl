package main

import (
	"os"
	"testing"
)

func TestInvalidMLConfigPrecedesAcquisitionAndPreservesArtifacts(t *testing.T) {
	for _, override := range []bool{false, true} {
		t.Run(map[bool]string{false: "configured", true: "overridden"}[override], func(t *testing.T) {
			t.Chdir(t.TempDir())
			fakeBucketCLI(t, "0")
			t.Setenv("PROWL_BUCKET_STARTED", "started")
			if err := os.WriteFile("operator.yaml", []byte("performance:\n  ml_threshold: .inf\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"report.json", "baseline.json"} {
				if err := os.WriteFile(name, []byte("owned previous artifact"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			args := []string{"s3://owned/prefix", "--config", "operator.yaml", "--output", "report.json", "--write-baseline", "baseline.json", "--format", "json", "--silence"}
			if override {
				args = append(args, "--ml-threshold", "0.3")
			}
			if code := cmdBucket(args); code != 2 {
				t.Fatalf("invalid config returned %d", code)
			}
			if _, err := os.Stat("started"); !os.IsNotExist(err) {
				t.Fatal("source acquisition preceded config validation")
			}
			for _, name := range []string{"report.json", "baseline.json"} {
				if raw, err := os.ReadFile(name); err != nil || string(raw) != "owned previous artifact" {
					t.Fatalf("invalid config replaced %s: %q %v", name, raw, err)
				}
			}
		})
	}
}
