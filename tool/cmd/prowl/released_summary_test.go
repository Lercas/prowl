package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/post"
)

func TestReleasedSummaryCountsAfterSuppressionAndLiveRestore(t *testing.T) {
	for _, policy := range []string{"baseline", "gitleaksignore"} {
		for _, liveGuard := range []bool{false, true} {
			t.Run(policy+map[bool]string{false: "/suppressed", true: "/live-restored"}[liveGuard], func(t *testing.T) {
				t.Chdir(t.TempDir())
				live := true
				finding := model.Finding{Type: "stripe_secret", Path: "input.env", Line: 1, Severity: "high", Fingerprint: "owned-fingerprint", Verified: &live}
				flags := commonFlags{coverage: model.NewCoverage(), format: "json", output: "report.json", failOnVerified: liveGuard}
				if policy == "baseline" {
					flags.baseline = "baseline.json"
					if err := post.WriteBaseline(flags.baseline, []model.Finding{finding}); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(".gitleaksignore", []byte("input.env:stripe_secret:1\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				var logs bytes.Buffer
				logx.Setup(logx.Options{Out: &logs})
				t.Cleanup(func() { logx.Setup(logx.Options{}) })
				want := 0
				if liveGuard {
					want = 1
				}
				if code := reportFindings(flags, []model.Finding{finding}, 0); code != want {
					t.Fatalf("gate = %d, want %d", code, want)
				}
				data, err := os.ReadFile(flags.output)
				if err != nil {
					t.Fatal(err)
				}
				var report struct {
					Count int `json:"count"`
				}
				if err := json.Unmarshal(data, &report); err != nil || report.Count != want {
					t.Fatalf("report count = %d, want %d; error %v", report.Count, want, err)
				}
				summary := "scan complete findings=0"
				if liveGuard {
					summary = "scan complete findings=1"
				}
				if !strings.Contains(logs.String(), summary) || strings.Count(logs.String(), "scan complete") != 1 {
					t.Fatalf("summary disagrees with final report: %s", logs.String())
				}
			})
		}
	}
}
