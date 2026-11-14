package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestDedupeRetainsAllEvidenceAcrossFinalImageReplacement(t *testing.T) {
	yes, no := true, false
	live := &model.Verification{Status: "verified", Verifier: "owned-provider"}
	for _, reversed := range []bool{false, true} {
		fs := []model.Finding{
			{Fingerprint: "same", OccurrenceID: "a", Path: "bundle", Line: 1, InFinalImage: &no, Verified: &yes, Verification: live, Severity: "high", Confidence: .95, Evidence: []model.Evidence{{Path: "bundle", Start: 1, End: 4, Transform: "concat"}}, Provenance: map[string]string{"blob": "old"}},
			{Fingerprint: "same", OccurrenceID: "b", Path: "bundle", Line: 7, InFinalImage: &no, Severity: "medium", Confidence: .8},
			{Fingerprint: "same", OccurrenceID: "c", Path: "bundle", Line: 9, InFinalImage: &yes, Verified: &no, Verification: &model.Verification{Status: "invalid"}, Severity: "low", Confidence: .5},
		}
		if reversed {
			fs[0], fs[2] = fs[2], fs[0]
		}
		fs = dedupeFingerprints(fs)
		if len(fs) != 1 || fs[0].Line != 9 || fs[0].InFinalImage == nil || !*fs[0].InFinalImage || len(fs[0].Occurrences) != 3 || fs[0].Verified == nil || !*fs[0].Verified || fs[0].Verification != live || fs[0].Severity != "high" || fs[0].Confidence != .95 {
			t.Fatal("final image replacement dropped source evidence or weakened the summary")
		}
		found := false
		for _, o := range fs[0].Occurrences {
			if o.ID == "a" {
				found = len(o.Evidence) == 1 && o.Provenance["blob"] == "old" && o.Verification == live
			}
		}
		if !found || gate(applyReportFilters(commonFlags{minSeverity: "high", minConfidence: .9}, fs), "", true) != 1 {
			t.Fatal("live evidence was lost before report filtering or the gate")
		}
		before, _ := json.Marshal(fs)
		after, _ := json.Marshal(dedupeFingerprints(fs))
		if string(before) != string(after) {
			t.Fatal("aggregate summary verification overwrote a source occurrence")
		}
	}
}

func TestDedupeCombinesAggregatesAndIsIdempotent(t *testing.T) {
	for _, keyed := range []bool{false, true} {
		id := func(n int) string {
			if keyed {
				return fmt.Sprint(n)
			}
			return ""
		}
		fs := []model.Finding{
			{Fingerprint: "same", Path: "prod.env", Line: 1, OccurrenceID: id(1), Occurrences: []model.Occurrence{{ID: id(1), Path: "prod.env", Line: 1}, {ID: id(2), Path: "prod.env", Line: 2}}},
			{Fingerprint: "same", Path: "prod.env", Line: 3, OccurrenceID: id(3), Occurrences: []model.Occurrence{{ID: id(3), Path: "prod.env", Line: 3}, {ID: id(4), Path: "prod.env", Line: 4}}},
		}
		fs = dedupeFingerprints(fs)
		if len(fs) != 1 || len(fs[0].Occurrences) != 4 {
			t.Fatal("already aggregated locations were lost or duplicated")
		}
		before, _ := json.Marshal(fs)
		fs = dedupeFingerprints(fs)
		after, _ := json.Marshal(fs)
		if string(before) != string(after) {
			t.Fatal("a second dedupe changed complete source evidence")
		}
	}
}

func TestKeylessOccurrencesDistinguishProvenanceAndEvidence(t *testing.T) {
	fs := []model.Finding{{Fingerprint: "same", Path: "prod.env", Line: 1, Provenance: map[string]string{"blob": "a"}}, {Fingerprint: "same", Path: "prod.env", Line: 1, Provenance: map[string]string{"blob": "b"}}, {Fingerprint: "same", Path: "prod.env", Line: 1, Evidence: []model.Evidence{{Start: 1, End: 2}}}}
	fs = dedupeFingerprints(fs)
	if len(fs) != 1 || len(fs[0].Occurrences) != 3 {
		t.Fatal("keyless source metadata collapsed distinct occurrences")
	}
	unknown := []model.Finding{{Path: "prod.env", Line: 1}, {Path: "prod.env", Line: 1}}
	if len(dedupeFingerprints(unknown)) != 2 {
		t.Fatal("findings without a fingerprint were merged")
	}
	checks := []model.Finding{{Type: "source_error", Fingerprint: "same"}, {Type: "source_error", Fingerprint: "same"}}
	if len(dedupeFingerprints(checks)) != 2 {
		t.Fatal("incomplete diagnostics were merged")
	}
	invalidNames := []model.Finding{
		{Fingerprint: "same", Path: "prod.env", Evidence: []model.Evidence{{Path: "\xff"}}, Occurrences: []model.Occurrence{{Path: "prod.env", Evidence: []model.Evidence{{Path: "\xfe"}}}}},
	}
	if got := dedupeFingerprints(invalidNames); len(got) != 1 || len(got[0].Occurrences) != 2 {
		t.Fatal("JSON replacement of invalid UTF-8 collapsed distinct source paths")
	}
	entries := []model.Finding{{Fingerprint: "same", Path: "layer:prod.env", ImageEntry: 1}, {Fingerprint: "same", Path: "layer:prod.env", ImageEntry: 2}}
	if got := dedupeFingerprints(entries); len(got) != 1 || len(got[0].Occurrences) != 2 {
		t.Fatal("anonymous repeated TAR entries were silently collapsed")
	}
}

func TestOccurrenceOverflowRemainsIncompleteAndCannotReplaceBaseline(t *testing.T) {
	fs := make([]model.Finding, maxReportOccurrences+2)
	for i := range fs {
		fs[i] = model.Finding{Type: "aws_access_key_id", Fingerprint: "same", Path: "prod.env", Line: i + 1, OccurrenceID: fmt.Sprint(i)}
	}
	fs = dedupeFingerprints(fs)
	if len(fs) != 2 || len(fs[0].Occurrences) != maxReportOccurrences || !model.IsIncompleteFinding(fs[1]) || gate(fs, "", false) != 2 {
		t.Fatal("occurrence overflow looked complete")
	}
	before, _ := json.Marshal(fs)
	after, _ := json.Marshal(dedupeFingerprints(fs))
	if string(before) != string(after) {
		t.Fatal("repeated aggregation lost or duplicated its incompleteness marker")
	}
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, []byte("owned sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	if code := reportFindings(commonFlags{silence: true, writeBaseline: path, minSeverity: "critical"}, fs, time.Second); code != 2 {
		t.Fatal("report filters hid incomplete aggregation")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "owned sentinel" {
		t.Fatal("incomplete aggregation replaced a baseline")
	}
}

func TestOccurrenceAccumulatorDoesNotMutateExistingMetadata(t *testing.T) {
	original := []model.Occurrence{{ID: "a", Path: "prod.env", Line: 1}}
	fs := []model.Finding{{Fingerprint: "same", OccurrenceID: "a", Path: "prod.env", Line: 1, Occurrences: original}, {Fingerprint: "same", OccurrenceID: "b", Path: "prod.env", Line: 2}}
	_ = dedupeFingerprints(fs)
	if !reflect.DeepEqual(original, []model.Occurrence{{ID: "a", Path: "prod.env", Line: 1}}) {
		t.Fatal("dedupe mutated a caller-owned occurrence slice")
	}
}
