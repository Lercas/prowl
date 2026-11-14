package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestComparisonReportSchemaAndAtomicOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	c := commonFlags{format: "json", output: path, dedupe: true}
	raw := []model.Finding{{Type: "aws_access_key_id", Severity: "high", Confidence: .9, Redacted: "masked"}, {Type: "generic_password", Severity: "low", Confidence: .2}}
	if err := writeComparison(context.Background(), c, raw, raw[:1]); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report comparisonReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != "1.5.0-compare-v1" || !report.Complete || report.Before != 2 || report.After != 1 || report.Suppressed != 1 || report.SuppressionPercent != 50 || !report.Deduplicated || report.SecretsRevealed || len(report.Raw) != 2 {
		t.Fatalf("invalid comparison: %+v", report)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("report is not private")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := writeComparison(ctx, c, nil, nil); err == nil {
		t.Fatal("cancelled output succeeded")
	}
	unchanged, _ := os.ReadFile(path)
	if string(unchanged) != string(data) {
		t.Fatal("cancelled output replaced existing report")
	}
	if err := writeComparison(context.Background(), c, nil, nil); err != nil {
		t.Fatal(err)
	}
	empty, _ := os.ReadFile(path)
	if !strings.Contains(string(empty), `"raw":[]`) || !strings.Contains(string(empty), `"kept":[]`) || !strings.Contains(string(empty), `"suppression_percent":0`) {
		t.Fatal(string(empty))
	}
	c.format, c.silence = "pretty", true
	if err := writeComparison(context.Background(), c, raw, raw[:1]); err != nil {
		t.Fatal(err)
	}
	pretty, _ := os.ReadFile(path)
	if !strings.Contains(string(pretty), "fixed candidates") {
		t.Fatal("explicit output suppressed by silence")
	}
}

func TestComparisonCommandSpecificFlags(t *testing.T) {
	for _, command := range []string{"compare", "index", "diff"} {
		for _, format := range []string{"sarif", "dojo", "defectdojo"} {
			if _, _, err := parseCommand(command, []string{"--format=" + format}); err == nil {
				t.Fatalf("%s accepted %s", command, format)
			}
		}
		if _, _, err := parseCommand(command, append([]string{"--format=json"}, comparisonRequiredArgs(command)...)); err != nil {
			t.Fatal(err)
		}
	}
	for _, format := range []string{"sarif", "dojo", "defectdojo"} {
		if _, _, err := parseCommand("scan", []string{"--format=" + format}); err != nil {
			t.Fatal(err)
		}
	}
	for _, flag := range []string{"--baseline=owned", "--write-baseline=owned", "--ci=false", "--fail-on=high", "--max-per-file=0", "--ml=false"} {
		if _, _, err := parseCommand("compare", []string{flag}); err == nil {
			t.Fatalf("accepted ignored flag %s", flag)
		}
	}
	if _, _, err := parseCommand("compare", []string{"--ml=true"}); err != nil {
		t.Fatal(err)
	}
	help := commandFlagHelp("compare")
	if strings.Contains(help, "sarif") || strings.Contains(help, "--baseline") || !strings.Contains(help, "pretty|json") {
		t.Fatal(help)
	}
	for _, f := range completionFlags("compare") {
		if f.names[0] == "--format" && strings.Join(enumValues(f), "|") != "pretty|json" {
			t.Fatal("completion choices diverged")
		}
	}
}

func TestComparisonReportFiltersPreserveSubset(t *testing.T) {
	for _, c := range []commonFlags{{minConfidence: .8}, {minSeverity: "high"}, {disable: "GENERIC-PASSWORD"}} {
		raw := []model.Finding{{Type: "aws_access_key_id", Severity: "high", Confidence: .9}, {Type: "generic_password", Severity: "low", Confidence: .2}}
		kept := append([]model.Finding(nil), raw...)
		a, b := applyReportFilters(c, raw), applyReportFilters(c, kept)
		if len(a) != 1 || len(b) != 1 || a[0].Type != b[0].Type || a[0].Type != "aws_access_key_id" {
			t.Fatalf("filters diverged: %+v %+v", a, b)
		}
	}
}

func comparisonRequiredArgs(command string) []string {
	if command == "index" || command == "diff" {
		return []string{"--index=owned"}
	}
	return nil
}
