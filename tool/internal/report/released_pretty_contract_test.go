package report

import (
	"bytes"
	"github.com/Lercas/prowl/tool/internal/model"
	"strings"
	"testing"
)

func TestPrettyDistinguishesEmptyFilteredAndIncomplete(t *testing.T) {
	for _, state := range []string{"empty", "scanned", "filtered", "incomplete"} {
		t.Run(state, func(t *testing.T) {
			c := model.NewCoverage()
			want := "no objects to scan"
			switch state {
			case "scanned":
				c.Processed(10)
				want = "✓ no secrets found"
			case "filtered":
				c.Processed(10)
				c.Filtered()
				want = "no findings after filters and suppressions"
			case "incomplete":
				c.Note("max_size", "large.log", true)
				want = "max_size: large.log"
			}
			var b bytes.Buffer
			if err := WriteWithCoverage(&b, nil, "pretty", false, c); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(b.String(), want) {
				t.Fatalf("missing %q: %s", want, b.String())
			}
			if state != "scanned" && strings.Contains(b.String(), "✓ no secrets found") {
				t.Fatal("empty/filtered/incomplete result presented as clean")
			}
		})
	}
}

func TestPrettySanitizesImportedTypeAndBoundsDiagnostics(t *testing.T) {
	c := model.NewCoverage()
	for i := 0; i < 12; i++ {
		c.Note("failure\x1b", "input\x1b", true)
	}
	var b bytes.Buffer
	fs := []model.Finding{{Type: "external\x1b[31m", Severity: "high", Path: "file", Redacted: "****"}}
	if err := WriteWithCoverage(&b, fs, "pretty", false, c); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "\x1b") || strings.Count(b.String(), "  failure") != 5 {
		t.Fatal("untrusted terminal bytes or unbounded diagnostics")
	}
	if !strings.Contains(b.String(), "Candidates without a provider verdict are unconfirmed") {
		t.Fatal("unverified candidates lack an explanation")
	}
}

func TestPrettyDoesNotRepeatCoverageAlreadyShownAsInputGap(t *testing.T) {
	c := model.NewCoverage()
	c.Note("source_error", "missing.env", true)
	c.Note("source_error", "missing.env", true)
	var out bytes.Buffer
	if err := WriteWithCoverage(&out, []model.Finding{{Type: "source_error", Path: "missing.env"}}, "pretty", false, c); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), "missing.env") != 1 || strings.Contains(out.String(), "coverage diagnostics:") {
		t.Fatal("one missing input was displayed repeatedly")
	}
}
