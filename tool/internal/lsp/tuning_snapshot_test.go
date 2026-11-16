package lsp

import (
	"github.com/Lercas/prowl/tool/internal/detect"
	"os"
	"testing"
)

func TestWorkspaceTuningIsIndependentOfOtherWorkspaces(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("PROWL_HOME", t.TempDir())
	defer detect.ApplyTuning(3.5, 4.2, 50000)
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(".prowl.yaml", []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("detection:\n  generic_entropy_min: 7.5\n  placeholder_max_entropy: 8\n  max_matches_per_file: 1\n")
	tuned, err := buildWithBundled(true)
	if err != nil {
		t.Fatal(err)
	}
	write("{}\n")
	defaults, err := buildWithBundled(true)
	if err != nil {
		t.Fatal(err)
	}
	detect.ApplyTuning(2, 2, 2)
	if len(scanDiagnostics(tuned, "file:///owned.py", genericSecretLine)) != 0 || len(scanDiagnostics(defaults, "file:///owned.py", genericSecretLine)) == 0 {
		t.Fatal("workspace detector inherited another workspace's thresholds")
	}
	if tuned.det.Tuning() != detect.DefaultTuning().With(7.5, 8, 1) || defaults.det.Tuning() != detect.DefaultTuning() {
		t.Fatal("workspace settings changed after construction")
	}
}
