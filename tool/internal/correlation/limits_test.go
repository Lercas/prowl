package correlation

import (
	"encoding/json"
	"github.com/Lercas/prowl/tool/internal/model"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadBudgetsCountBytesAndNestedRows(t *testing.T) {
	r := report([]model.Finding{finding()}, true)
	r.CompletionReason = "completed"
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "owned.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	rows, err := arrayRows(data, maxArrayRows)
	if err != nil || rows < 2 {
		t.Fatal("fixture lacks nested rows")
	}
	if _, err := readMany([]string{path, path}, int64(len(data)*2), rows*2); err != nil {
		t.Fatal(err)
	}
	if _, err := readMany([]string{path, path}, int64(len(data)*2-1), rows*2); err == nil {
		t.Fatal("aggregate byte budget bypassed")
	}
	if _, err := readMany([]string{path, path}, int64(len(data)*2), rows*2-1); err == nil {
		t.Fatal("aggregate row budget bypassed")
	}
	if _, err := arrayRows([]byte(`{"findings":[0,0,0]}`), 2); err == nil {
		t.Fatal("invalid primitive rows escaped allocation budget")
	}
	if _, err := ReadMany(make([]string, 33)); err == nil {
		t.Fatal("too many inputs accepted")
	}
}

func TestReadRejectsAmbiguousJSONAndCoverage(t *testing.T) {
	r := report([]model.Finding{finding()}, true)
	r.CompletionReason = "completed"
	data, _ := json.Marshal(r)
	for _, mode := range []string{"duplicate", "source-error", "skipped"} {
		t.Run(mode, func(t *testing.T) {
			current := append([]byte(nil), data...)
			switch mode {
			case "duplicate":
				current = []byte(strings.Replace(string(current), `"complete":true`, `"complete":false,"complete":true`, 1))
			case "source-error":
				r.Findings = []model.Finding{{Type: "source_error"}}
				current, _ = json.Marshal(r)
			case "skipped":
				r.Findings = []model.Finding{finding()}
				r.Stats.Skipped = 1
				current, _ = json.Marshal(r)
			}
			path := filepath.Join(t.TempDir(), "owned.json")
			if err := os.WriteFile(path, current, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Read(path); err == nil {
				t.Fatal("contradictory or ambiguous report accepted")
			}
		})
	}
}

func TestOnlyPolicyScopesCannotProveAbsence(t *testing.T) {
	before := report([]model.Finding{finding()}, true)
	after := report([]model.Finding{}, true)
	before.Scope = []model.Scope{{Kind: "command", Target: "scan", Policy: "owned"}, {Kind: "detection_policy", Target: "1.5.0", Policy: "owned"}}
	after.Scope = before.Scope
	result, err := Compare(before, after)
	if err != nil || result.Comparable || result.Items[0].Presence != "inconclusive" {
		t.Fatal("policy scopes were treated as an acquired source")
	}
}

func TestReadRejectsConflictingProviderMetadata(t *testing.T) {
	yes, no := true, false
	for _, nested := range []bool{false, true} {
		for _, mode := range []string{"conflict", "missing-bool", "unknown", "bad-date"} {
			if nested && (mode == "conflict" || mode == "missing-bool") {
				continue
			} // Occurrence has no legacy boolean.
			t.Run(mode+map[bool]string{false: "/top", true: "/nested"}[nested], func(t *testing.T) {
				f := finding()
				detail := &model.Verification{Status: "invalid", CheckedAt: "2026-11-14T00:00:00Z"}
				value := &no
				switch mode {
				case "conflict":
					value = &yes
				case "missing-bool":
					value = nil
				case "unknown":
					detail.Status = "owned-unknown"
				case "bad-date":
					detail.CheckedAt = "not-a-time"
				}
				if nested {
					f.Occurrences = []model.Occurrence{{ID: strings.Repeat("d", 64), Verification: detail}}
				} else {
					f.Verified = value
					f.Verification = detail
				}
				r := report([]model.Finding{f}, true)
				r.CompletionReason = "completed"
				data, _ := json.Marshal(r)
				if _, err := decodeReport(data); err == nil {
					t.Fatal("contradictory verification metadata accepted")
				}
			})
		}
	}
}

func TestCanonicalIdentityCannotDisguiseAPresentSecret(t *testing.T) {
	before := report([]model.Finding{finding()}, true)
	after := report([]model.Finding{finding()}, true)
	after.Findings[0].SecretID = strings.ToUpper(after.Findings[0].SecretID)
	if _, err := Compare(before, after); err == nil {
		t.Fatal("noncanonical HMAC representation could look absent")
	}
}
