package lsp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

func completenessEngine(t *testing.T, mode string) *engine {
	t.Helper()
	tax := &taxonomy.Taxonomy{}
	if mode != "template" {
		tax.Types = append(tax.Types, taxonomy.SecretType{ID: "owned_cap_cascade", Category: "cloud", RE: regexp.MustCompile(`OWNED_[A-Za-z0-9]{12}`)})
	}
	if mode == "overlap" {
		tax.Types = append(tax.Types, taxonomy.SecretType{ID: "owned_cap_overlap", Category: "cloud", RE: regexp.MustCompile(`OWNED_[A-Za-z0-9]{12}`)})
	}
	e := &engine{det: detect.New(tax), maxBytes: defaultMaxScanBytes}
	if mode == "template" || mode == "both" {
		dir := t.TempDir()
		body := "id: owned-cap-template\ninfo:\n  name: Owned cap fixture\n  severity: high\nmatchers:\n  - type: regex\n    regex:\n      - TEMPLATE_[A-Za-z0-9]{12}\n"
		if err := os.WriteFile(filepath.Join(dir, "owned.yaml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		var err error
		e.eng, err = rules.Load(dir)
		if err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func diagnosticCodeCount(diags []map[string]any, code string) int {
	count := 0
	for _, diag := range diags {
		if diag["code"] == code {
			count++
		}
	}
	return count
}

func TestDiagnosticMatchBudgetAndCompleteness(t *testing.T) {
	defer restoreDetectDefaults()
	const capN = 7
	detect.ApplyTuning(3.5, 4.2, capN)
	for _, mode := range []string{"cascade", "template", "both", "overlap"} {
		for _, allowed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/allowed=%v", mode, allowed), func(t *testing.T) {
				e := completenessEngine(t, mode)
				if allowed {
					e.allow = func(_, _ string) bool { return true }
				}
				text := strings.Repeat("Ключ😀 \x4fWNED_G7hJ9kL2mN5p TEMPLATE_R4tV8w000001\n", 30)
				diags := scanDiagnostics(e, "file:///caps.env", text)
				if len(diags) > capN+1 || diagnosticCodeCount(diags, "results_truncated") != 1 {
					t.Fatalf("incomplete/bounded result missing: total=%d truncationMarkers=%d", len(diags), diagnosticCodeCount(diags, "results_truncated"))
				}
				if allowed && len(diags) != 1 {
					t.Fatalf("allowlist hid truncation or allowed candidates: %d diagnostics", len(diags))
				}
				if !allowed && len(diags) < 2 {
					t.Fatal("candidate diagnostics were lost")
				}
			})
		}
	}
}

func TestDiagnosticRawCapSurvivesOverlapDedupe(t *testing.T) {
	defer restoreDetectDefaults()
	detect.ApplyTuning(3.5, 4.2, 2)
	e := completenessEngine(t, "overlap")
	diags := scanDiagnostics(e, "file:///caps.env", "\x4fWNED_G7hJ9kL2mN5p")
	if len(diags) != 2 || diagnosticCodeCount(diags, "results_truncated") != 1 {
		t.Fatalf("raw cap was hidden by overlap dedupe: total=%d, truncationMarkers=%d", len(diags), diagnosticCodeCount(diags, "results_truncated"))
	}
}

func TestDiagnosticBudgetSharedBetweenProducers(t *testing.T) {
	defer restoreDetectDefaults()
	detect.ApplyTuning(3.5, 4.2, 7)
	e := completenessEngine(t, "both")
	text := strings.Repeat("\x4fWNED_G7hJ9kL2mN5p ", 3)
	for i := 0; i < 20; i++ {
		text += fmt.Sprintf("TEMPLATE_R%011d ", i+10000000000)
	}
	diags := scanDiagnostics(e, "file:///caps.env", text)
	if len(diags) != 8 || diagnosticCodeCount(diags, "results_truncated") != 1 {
		t.Fatalf("combined producers did not share their budget: %d diagnostics", len(diags))
	}
	counts := map[string]int{}
	for _, diagnostic := range diags {
		message := diagnostic["message"].(string)
		if strings.Contains(message, "owned_cap_cascade") {
			counts["cascade"]++
		}
		if strings.Contains(message, "owned-cap-template") {
			counts["template"]++
		}
	}
	if counts["cascade"] != 3 || counts["template"] != 4 {
		t.Fatalf("incorrect remaining template budget: %v", counts)
	}
}

func TestIncompleteDocumentTransitions(t *testing.T) {
	for _, method := range []string{"textDocument/didOpen", "textDocument/didChange", "textDocument/didSave"} {
		t.Run(method, func(t *testing.T) {
			e := completenessEngine(t, "cascade")
			e.maxBytes = 128
			var buf bytes.Buffer
			w := newSafeWriter(bufio.NewWriter(&buf))
			d := newDebouncer(e, w, time.Hour)
			t.Cleanup(d.stop)
			const uri, secret = "file:///size.env", "\x4fWNED_G7hJ9kL2mN5p"
			if method == "textDocument/didOpen" {
				d.immediate(uri, secret)
			} else {
				dispatch(w, e, d, "textDocument/didOpen", nil, documentParams(uri, secret, 0))
			}
			buf.Reset()
			dispatch(w, e, d, method, nil, lifecycleParams(uri, secret+strings.Repeat(" x", 128)))
			if method == "textDocument/didChange" {
				awaitScan(t, firePending(d, uri))
			}
			count, last := drainPublishes(t, &buf)
			if count != 1 || !hasDiag(last) {
				t.Fatal("oversized document was published as clean")
			}
			diagnostics := last["diagnostics"].([]any)
			if len(diagnostics) != 1 || diagnostics[0].(map[string]any)["code"] != "document_too_large" {
				t.Fatal("oversized document lacks its incomplete diagnostic")
			}
			buf.Reset()
			cleanMethod := method
			if method == "textDocument/didOpen" {
				cleanMethod = "textDocument/didChange"
			}
			dispatch(w, e, d, cleanMethod, nil, documentParams(uri, "", 2))
			if cleanMethod == "textDocument/didChange" {
				awaitScan(t, firePending(d, uri))
			}
			d.stop()
			if count, last := drainPublishes(t, &buf); count != 1 || hasDiag(last) {
				t.Fatal("valid clean snapshot retained an incomplete warning")
			}
		})
	}
}

func TestDiagnosticFailureDoesNotPublishClean(t *testing.T) {
	e := completenessEngine(t, "cascade")
	const secret = "\x4fWNED_G7hJ9kL2mN5p"
	e.allow = func(_, _ string) bool { panic(secret) }
	var buf bytes.Buffer
	d := newDebouncer(e, newSafeWriter(bufio.NewWriter(&buf)), time.Hour)
	logs := captureWarn(t, func() { d.immediate("file:///failure.env", secret) })
	d.stop()
	count, last := drainPublishes(t, &buf)
	if count != 1 || !hasDiag(last) {
		t.Fatal("failed scan did not publish an incomplete diagnostic")
	}
	if strings.Contains(logs, secret) {
		t.Fatal("scan recovery logged a candidate value")
	}
	raw, err := json.Marshal(last)
	if err != nil || strings.Contains(string(raw), secret) {
		t.Fatal("scan failure diagnostics exposed a candidate")
	}
	diagnostics := last["diagnostics"].([]any)
	if len(diagnostics) != 1 || diagnostics[0].(map[string]any)["code"] != "scan_failed" {
		t.Fatal("failed scan lacks its failure diagnostic")
	}
}

func TestSupersededScanFailureCannotPublishIncompleteWarning(t *testing.T) {
	for _, event := range []string{"clean", "close", "stop"} {
		t.Run(event, func(t *testing.T) {
			e := completenessEngine(t, "cascade")
			const uri, secret = "file:///failure.env", "\x4fWNED_G7hJ9kL2mN5p"
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			e.allow = func(_, _ string) bool { close(entered); <-release; panic(secret) }
			var buf bytes.Buffer
			d := newDebouncer(e, newSafeWriter(bufio.NewWriter(&buf)), time.Hour)
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); d.stop() })
			d.schedule(uri, secret)
			done := firePending(d, uri)
			awaitScan(t, entered)
			var stopped chan struct{}
			switch event {
			case "clean":
				d.immediate(uri, "")
			case "close":
				d.close(uri)
			case "stop":
				stopped = make(chan struct{})
				go func() { d.stop(); close(stopped) }()
				deadline := time.After(5 * time.Second)
				for {
					d.mu.Lock()
					closing := d.stopped
					d.mu.Unlock()
					if closing {
						break
					}
					select {
					case <-deadline:
						t.Fatal("stop did not invalidate the running revision")
					default:
						runtime.Gosched()
					}
				}
			}
			releaseOnce.Do(func() { close(release) })
			awaitScan(t, done)
			if stopped != nil {
				awaitScan(t, stopped)
			}
			d.stop()
			want := 1
			if event == "stop" {
				want = 0
			}
			if count, last := drainPublishes(t, &buf); count != want || hasDiag(last) {
				t.Fatal("superseded failure published an obsolete incomplete warning")
			}
		})
	}
}
