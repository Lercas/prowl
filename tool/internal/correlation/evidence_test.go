package correlation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestNestedOccurrenceSuppliesArtifactLink(t *testing.T) {
	before := finding()
	before.Occurrences = []model.Occurrence{{ID: strings.Repeat("d", 64), Provenance: map[string]string{"layer_digest": strings.Repeat("e", 64)}}}
	after := finding()
	after.OccurrenceID = strings.Repeat("f", 64)
	after.Provenance = map[string]string{"layer_digest": strings.Repeat("e", 64)}
	r, err := Join([]model.ScanResult{report([]model.Finding{before}, true), report([]model.Finding{after}, true)})
	if err != nil || len(r.Groups) != 1 || len(r.Groups[0].Links) != 1 {
		t.Fatalf("nested artifact provenance was lost: %v", err)
	}
	link := r.Groups[0].Links[0]
	if link.From != before.Occurrences[0].ID || link.To != after.OccurrenceID || link.Kind != "shared_layer_digest_metadata" {
		t.Fatal("link does not identify its supporting occurrence")
	}
}

func TestLinkBudgetCannotSilentlyProduceCompleteGraph(t *testing.T) {
	f := finding()
	f.Provenance = map[string]string{"digest": strings.Repeat("d", 64)}
	for i := 0; i < 258; i++ {
		f.Occurrences = append(f.Occurrences, model.Occurrence{ID: fmt.Sprintf("%064x", i+1), Provenance: f.Provenance})
	}
	r, err := Join([]model.ScanResult{report([]model.Finding{f}, true)})
	if err != nil || r.Complete || len(r.Groups) != 1 || len(r.Groups[0].Links) != 256 || !r.Groups[0].LinksTruncated {
		t.Fatal("graph link truncation was hidden")
	}
}

func TestReadRejectsContradictoryEnvelope(t *testing.T) {
	r := report([]model.Finding{finding()}, true)
	r.CompletionReason = "completed"
	path := filepath.Join(t.TempDir(), "report.json")
	write := func() {
		t.Helper()
		data, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	if _, err := Read(path); err != nil {
		t.Fatal("valid report rejected")
	}
	r.Diagnostics = []model.Diagnostic{{Code: "max_size", Incomplete: true}}
	write()
	if _, err := Read(path); err == nil {
		t.Fatal("contradictory completeness accepted")
	}
}

func TestContradictoryCoverageCannotConfirmAbsence(t *testing.T) {
	b := report([]model.Finding{finding()}, true)
	a := report([]model.Finding{}, true)
	a.Diagnostics = []model.Diagnostic{{Code: "max_size", Incomplete: true}}
	r, err := Compare(b, a)
	if err != nil || r.Complete || r.Items[0].Presence != "inconclusive" {
		t.Fatal("complete flag overrode evidence of a partial scan")
	}
}
