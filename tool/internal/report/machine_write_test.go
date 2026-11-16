package report

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

type shortMachineWriter struct {
	calls   int
	written int
}

func (w *shortMachineWriter) Write(p []byte) (int, error) {
	w.calls++
	n := len(p) / 2
	w.written += n
	return n, nil
}

func TestAllReportFormatsRejectShortWrites(t *testing.T) {
	for _, format := range []string{"pretty", "", "json", "sarif", "defectdojo", "dojo"} {
		for _, fs := range [][]model.Finding{nil, {{Type: "owned", Path: "owned.env", Severity: "high", Redacted: "OWNED_****"}}} {
			writer := &shortMachineWriter{}
			err := WriteWithCoverage(writer, fs, format, false, model.NewCoverage())
			if !errors.Is(err, io.ErrShortWrite) || writer.calls != 1 {
				t.Errorf("format=%q findings=%d: short write succeeded or lost cause: %v", format, len(fs), err)
			}
		}
	}
}

func TestAllReportEntrypointsPreserveWriteCauses(t *testing.T) {
	failure := errors.New("owned report destination failure")
	for _, format := range []string{"pretty", "", "json", "sarif", "defectdojo", "dojo"} {
		for _, findings := range [][]model.Finding{nil, sample} {
			for _, budget := range []int{0, 12} {
				for _, cause := range []error{nil, failure} {
					want := cause
					if want == nil {
						want = io.ErrShortWrite
					}
					for _, coverage := range []bool{false, true} {
						writer := &failingReportWriter{remaining: budget, err: cause}
						fs := append([]model.Finding(nil), findings...)
						var err error
						if coverage {
							err = WriteWithCoverage(writer, fs, format, false, model.NewCoverage())
						} else {
							err = Write(writer, fs, format, false)
						}
						if !errors.Is(err, want) {
							t.Errorf("format=%q budget=%d coverage=%v: lost write cause: %v", format, budget, coverage, err)
						}
					}
				}
			}
		}
	}
}

func TestReportUnsupportedFormatDoesNotWriteOrLoseError(t *testing.T) {
	writer := &shortMachineWriter{}
	err := WriteWithCoverage(writer, nil, "unsupported-owned-format", false, model.NewCoverage())
	if err == nil || !strings.Contains(err.Error(), "unsupported report format") || writer.calls != 0 {
		t.Fatal("writer guard masked validation error or wrote unsupported output", err, writer.calls)
	}
}
