package correlation

import (
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestUnversionedPolicyCannotCertifyAbsence(t *testing.T) {
	before := report([]model.Finding{finding()}, true)
	before.Scope = append(before.Scope, model.Scope{Kind: "unversioned_policy", Target: "ml", Policy: strings.Repeat("a", 64)})
	after := report(nil, true)
	after.Scope = before.Scope
	result, err := Compare(before, after)
	if err != nil || result.Comparable || !result.Complete || result.Items[0].Presence != "inconclusive" || result.Items[0].Closed {
		t.Fatal("unknown model state certified absence", result, err)
	}
	after.Findings = []model.Finding{finding()}
	after.Count = 1
	result, err = Compare(before, after)
	if err != nil || result.Comparable || result.Items[0].Presence != "present" {
		t.Fatal("unknown policy erased an observed secret", result, err)
	}
}
func TestChangedLoadedPoliciesCannotCertifyAbsence(t *testing.T) {
	for _, kind := range []string{"ml_model", "verifiers"} {
		before := report([]model.Finding{finding()}, true)
		before.Scope = append(before.Scope, model.Scope{Kind: kind, Policy: strings.Repeat("a", 64)})
		after := report(nil, true)
		after.Scope = append(after.Scope, model.Scope{Kind: kind, Policy: strings.Repeat("b", 64)})
		result, err := Compare(before, after)
		if err != nil || result.Comparable || result.Items[0].Presence != "inconclusive" {
			t.Fatal("changed loaded policy certified absence", kind, result, err)
		}
		after.Scope = before.Scope
		result, err = Compare(before, after)
		if err != nil || !result.Comparable || result.Items[0].Presence != "absent_in_scope" || result.Items[0].Closed {
			t.Fatal("matching loaded policy did not preserve scoped absence", kind, result, err)
		}
	}
}
