package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Lercas/prowl/tool/internal/config"
	"github.com/Lercas/prowl/tool/internal/model"
)

func TestFinalizationCancellationCannotCreateBaselineOrCleanReport(t *testing.T) {
	for _, baseline := range []bool{true, false} {
		t.Run(map[bool]string{true: "baseline", false: "report"}[baseline], func(t *testing.T) {
			t.Chdir(t.TempDir())
			c := commonFlags{format: "json", output: "report.json", failOn: "high", workers: 1,
				minConfidence: 0.8, minSeverity: "high", disable: "response_truncated"}
			path := filepath.Join(".", "accepted.json")
			if baseline {
				c.writeBaseline = path
				if err := os.WriteFile(path, []byte(`["previous"]`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			items := make(chan model.Item)
			close(items) // Acquisition completed, then final-image/provenance processing is interrupted.
			called := false
			code := runPreparedScan(ctx, c, &config.Config{}, nil, nil, nil, items, false, func(_ []model.Finding) []model.Finding {
				called = true
				cancel()
				return []model.Finding{{Type: "owned", Path: "owned.env", Severity: "high", Confidence: 1, Fingerprint: "owned"}}
			})
			if !called || code != 2 {
				t.Fatalf("called=%v exit=%d", called, code)
			}
			if baseline {
				raw, err := os.ReadFile(path)
				if err != nil || string(raw) != `["previous"]` {
					t.Fatal("late cancellation replaced baseline")
				}
			}
			raw, err := os.ReadFile(c.output)
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
			known, incomplete := false, false
			for _, f := range report.Findings {
				known = known || f.Type == "owned"
				incomplete = incomplete || model.IsIncompleteFinding(f)
			}
			if !report.Truncated || !known || !incomplete {
				t.Fatalf("late cancellation lost partial result or marker: %+v", report)
			}
		})
	}
}

func TestCancellationExitTakesPrecedenceOverFindingExit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, previous := range []int{0, 1, 2} {
		if got := failClosedIfIncomplete(ctx, previous); got != 2 {
			t.Fatalf("cancelled finding exit=%d returned %d", previous, got)
		}
	}
}
