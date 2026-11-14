package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyDistinguishesDefaultAndExplicitWholeMatchExtraction(t *testing.T) {
	var policies, values []string
	for _, group := range []string{"", "    group: 0\n"} {
		dir := t.TempDir()
		body := "id: owned-policy\ninfo:\n  name: Owned policy\n  severity: high\nmatchers:\n  - type: word\n    words: ['CUSTOM=']\nextractors:\n  - type: regex\n    regex: ['CUSTOM=([A-Z0-9]+)']\n" + group
		if err := os.WriteFile(filepath.Join(dir, "owned.yaml"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		e, err := Load(dir)
		if err != nil {
			t.Fatal(err)
		}
		hits := e.Match("CUSTOM=OWNEDVALUE42")
		if len(hits) != 1 {
			t.Fatalf("expected one extraction: %+v", hits)
		}
		values = append(values, hits[0].Value)
		policies = append(policies, e.PolicyDigest())
	}
	if values[0] != "OWNEDVALUE42" || values[1] != "CUSTOM=OWNEDVALUE42" || policies[0] == policies[1] {
		t.Fatal("different effective extraction semantics share a policy digest")
	}
}
