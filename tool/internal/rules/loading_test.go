package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateDirReportsReadFailures(t *testing.T) {
	paths := []string{filepath.Join(t.TempDir(), "missing.yaml")}
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.yaml")
	if err := os.WriteFile(outside, []byte(minimalRule("outside")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "escape.yaml")); err == nil {
		paths = append(paths, dir)
	}
	for _, p := range paths {
		issues := ValidateDir(p)
		hasError := false
		for _, issue := range issues {
			if issue.Level == "error" {
				hasError = true
			}
		}
		if !hasError {
			t.Errorf("validation silently accepted unreadable source %s: %+v", p, issues)
		}
	}
}

func TestRuntimeAndValidationRejectUnknownOrIneffectiveMatchers(t *testing.T) {
	for _, fragment := range []string{"unknown: true\n", "extractors:\n  - type: regex\n    regex: ['OWNED_[A-Z]{8}']\n    group: 0\n    unexpected: true\n", "matchers-condition: xor\n", "matchers:\n  - type: regex\n    condition: xor\n    regex: ['OWNED_[A-Z]{8}']\n", "matchers:\n  - type: regex\n", "extractors:\n  - type: words\n    regex: ['OWNED_[A-Z]{8}']\n"} {
		body := minimalRule("owned") + fragment
		// Replace rather than duplicate a matcher key, so failure proves schema/compile checks.
		if strings.HasPrefix(fragment, "matchers:\n") {
			body = "id: owned\ninfo: {name: Owned, severity: high}\n" + fragment
		}
		p := filepath.Join(t.TempDir(), "rule.yaml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Errorf("runtime accepted invalid template: %q", fragment)
		}
		bad := false
		for _, issue := range ValidateDir(p) {
			if issue.Level == "error" {
				bad = true
			}
		}
		if !bad {
			t.Errorf("validation accepted invalid template: %q", fragment)
		}
	}
}

func TestFilterAfterMatchingKeepsCorrectRuleSelection(t *testing.T) {
	dir := t.TempDir()
	for _, id := range []string{"owned_a", "owned_b"} {
		writeFile(t, filepath.Join(dir, id+".yaml"), minimalRule(id))
	}
	eng, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	const text = "XYZ0123456789ABCDEF"
	if hits := eng.Match(text); len(hits) != 2 {
		t.Fatalf("fixture expected 2 hits: %+v", hits)
	}
	eng.Filter(FilterOpts{IDs: []string{"owned_b"}})
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("filtering an already used engine panicked: %v", r)
		}
	}()
	hits := eng.Match(text)
	if len(hits) != 1 || hits[0].RuleID != "owned_b" {
		t.Fatalf("stale rule selection after Filter: %+v", hits)
	}
}

func TestDirectoryTemplateReadsStayWithinRoot(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.yaml")
	if err := os.WriteFile(outside, []byte(minimalRule("outside")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "escape.yaml")); err != nil {
		t.Skip(err)
	}
	eng, err := Load(dir)
	if err == nil || eng.Len() != 0 {
		t.Fatalf("directory loader followed an escaping rule: count=%d err=%v", eng.Len(), err)
	}
	// A directly selected path is operator-authorized and may follow a link.
	if eng, err := Load(filepath.Join(dir, "escape.yaml")); err != nil || eng.Len() != 1 {
		t.Fatalf("explicit rule path was rejected: count=%d err=%v", eng.Len(), err)
	}
	inside := t.TempDir()
	if err := os.WriteFile(filepath.Join(inside, "payload.data"), []byte(minimalRule("inside")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("payload.data", filepath.Join(inside, "rule.yaml")); err != nil {
		t.Fatal(err)
	}
	if eng, err := Load(inside); err != nil || eng.Len() != 1 {
		t.Fatalf("in-root rule link rejected: count=%d err=%v", eng.Len(), err)
	}
}

func TestParseTemplateDoesNotIgnoreFollowingDocuments(t *testing.T) {
	first := minimalRule("first")
	if _, err := ParseTemplate([]byte(first+"\n---\n"+minimalRule("second")), "two.yaml"); err == nil {
		t.Fatal("single-template parser ignored the second document")
	}
	path := filepath.Join(t.TempDir(), "stream.yaml")
	writeFile(t, path, first+"\n---\n"+minimalRule("second"))
	if eng, err := Load(path); err != nil || eng.Len() != 2 {
		t.Fatalf("stream loader lost a document: %v %v", eng, err)
	}
}

func TestTemplateByteLimitAppliesToLoadAndValidation(t *testing.T) {
	base := minimalRule("limit")
	body := base + "#" + strings.Repeat(" ", MaxTemplateSize-len(base)-1)
	for _, extra := range []string{"", " "} {
		p := filepath.Join(t.TempDir(), "size.yaml")
		writeFile(t, p, body+extra)
		_, err := Load(p)
		bad := false
		for _, issue := range ValidateDir(p) {
			if issue.Level == "error" {
				bad = true
			}
		}
		if (err != nil) != (extra != "") || bad != (extra != "") {
			t.Fatalf("wrong boundary for %d bytes: load=%v validationError=%v", len(body+extra), err, bad)
		}
	}
}
