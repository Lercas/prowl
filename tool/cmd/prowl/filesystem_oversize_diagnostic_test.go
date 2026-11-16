package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestFilesystemOversizeReportsMaxSizeDiagnostic(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PROWL_HOME", filepath.Join(dir, "home"))
	input := filepath.Join(dir, "inputs")
	if err := os.Mkdir(input, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(input, "large.txt")
	if err := os.WriteFile(file, []byte("oversized synthetic content"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, path string }{{"file", file}, {"directory", input}} {
		t.Run(tc.name, func(t *testing.T) {
			output := filepath.Join(dir, tc.name+".json")
			if code := cmdScan([]string{tc.path, "--bundled", "--max-size", "4", "--strict", "--format", "json", "--output", output, "--silence"}); code != 2 {
				t.Fatalf("oversize scan exit = %d, want 2", code)
			}
			data, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			var report model.ScanResult
			if err := json.Unmarshal(data, &report); err != nil {
				t.Fatal(err)
			}
			if report.Complete {
				t.Fatal("oversize scan reported complete")
			}
			for _, diagnostic := range report.Diagnostics {
				if diagnostic.Code == "max_size" && diagnostic.Incomplete {
					return
				}
			}
			t.Fatalf("missing max_size diagnostic: %+v", report.Diagnostics)
		})
	}
}
