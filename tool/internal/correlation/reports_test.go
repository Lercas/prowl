package correlation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func report(fs []model.Finding, complete bool) model.ScanResult {
	return model.ScanResult{SchemaVersion: "1.4", IdentityScope: strings.Repeat("a", 16), Complete: complete, Count: len(fs), Findings: fs, Scope: []model.Scope{{Kind: "filesystem", Target: "/project", Policy: "same-policy"}}}
}

func TestIncompleteBeforeReportCannotConfirmAbsence(t *testing.T) {
	r, err := Compare(report([]model.Finding{finding()}, false), report([]model.Finding{}, true))
	if err != nil || r.Complete || r.Items[0].Presence != "inconclusive" || r.Items[0].Closed {
		t.Fatal("partial before report accepted as complete evidence")
	}
}

func TestNestedLiveOccurrenceOverridesRejectedProviderCheck(t *testing.T) {
	f := finding()
	f.Verification = &model.Verification{Status: "invalid"}
	f.Occurrences = []model.Occurrence{{Verification: &model.Verification{Status: "verified"}}}
	f.Occurrences[0].ID = strings.Repeat("d", 64)
	r, err := Compare(report([]model.Finding{finding()}, true), report([]model.Finding{f}, true))
	if err != nil || r.Items[0].Revocation != "live" || r.Items[0].Closed {
		t.Fatal("live occurrence incorrectly considered revoked")
	}
}

func TestReadRejectsPlaintextEnvelopeEvenWithoutFindings(t *testing.T) {
	r := report([]model.Finding{}, true)
	r.SecretsRevealed = true
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "unsafe.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path); err == nil {
		t.Fatal("plaintext envelope accepted")
	}
}
func finding() model.Finding {
	return model.Finding{Type: "vendor_token", SecretID: strings.Repeat("b", 64), IdentityScope: strings.Repeat("a", 16), OccurrenceID: strings.Repeat("c", 64), Redacted: "abcd********wxyz"}
}
func TestRemediationCannotCloseOnAbsenceOrPartialCoverage(t *testing.T) {
	before := report([]model.Finding{finding()}, true)
	for _, complete := range []bool{true, false} {
		after := report([]model.Finding{}, complete)
		r, err := Compare(before, after)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Items) != 1 || r.Items[0].Closed || r.Items[0].Revocation != "not_checked" {
			t.Fatal("absence inferred revocation")
		}
		want := "inconclusive"
		if complete {
			want = "absent_in_scope"
		}
		if r.Items[0].Presence != want {
			t.Fatal("partial scan confirmed absence")
		}
	}
}
func TestIncompatibleScopeAndIdentity(t *testing.T) {
	b := report([]model.Finding{finding()}, true)
	a := report([]model.Finding{}, true)
	a.Scope[0].Target = "/another-project"
	r, err := Compare(b, a)
	if err != nil || r.Comparable || r.Items[0].Presence != "inconclusive" {
		t.Fatal("compared different targets")
	}
	a = report([]model.Finding{}, true)
	a.IdentityScope = strings.Repeat("d", 16)
	if _, err := Compare(b, a); err == nil {
		t.Fatal("accepted another organization's empty report")
	}
}
func TestSameValueDoesNotProvePropagation(t *testing.T) {
	r, err := Join([]model.ScanResult{report([]model.Finding{finding()}, true), report([]model.Finding{finding()}, true)})
	if err != nil || len(r.Groups) != 1 || r.Groups[0].Relationship != "same_secret_observed" {
		t.Fatal("inferred unsupported provenance")
	}
}
