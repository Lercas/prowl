package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestLedgerOnlyFailureCannotCertifyOrReplaceBaseline(t *testing.T) {
	t.Chdir(t.TempDir())
	baseline := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(baseline, []byte("owned sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	c := commonFlags{coverage: model.NewCoverage(), format: "json", silence: true, noAutoPolicy: true, writeBaseline: baseline, output: "report.json"}
	c.coverage.Note("owned_source_limit", "source", true)
	if code := reportScan(t.Context(), c, nil, 0); code != 2 {
		t.Fatal("ledger-only incompleteness became success")
	}
	data, err := os.ReadFile(baseline)
	if err != nil || string(data) != "owned sentinel" {
		t.Fatal("incomplete ledger replaced an existing baseline")
	}
	data, err = os.ReadFile(c.output)
	if err != nil {
		t.Fatal(err)
	}
	var result model.ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Complete || !result.Truncated || len(result.Diagnostics) != 1 || len(result.Findings) != 1 {
		t.Fatal("output file did not receive the shared coverage ledger")
	}
}

func TestSourceCompletionEvidenceIsResolvedOnceForReportingAndIndex(t *testing.T) {
	t.Chdir(t.TempDir())
	calls := 0
	c := commonFlags{coverage: model.NewCoverage(), format: "json", silence: true, noAutoPolicy: true, output: "report.json", indexCoverageComplete: func() bool { calls++; return false }}
	if code := reportScan(t.Context(), c, nil, 0); code != 2 || calls != 1 {
		t.Fatal("source acquisition completion was ignored or consumed more than once")
	}
}
