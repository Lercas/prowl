package rules

import "testing"

func TestLintAllowsContextOnlyWordAnchor(t *testing.T) {
	tpl := &Template{
		ID:       "context-token",
		Category: "generic",
		Info: Info{
			Name:     "Context token",
			Severity: "medium",
			Tags:     "token",
		},
		MatchersCondition: "and",
		Matchers: []Matcher{
			{Type: "word", Words: []string{"auth_token"}},
			{Type: "regex", Regex: []string{`[A-Za-z0-9_-]{20,64}`}},
		},
	}

	issues := lintTemplate(tpl, "context-token.yaml", map[string]string{})
	if len(issues) != 0 {
		t.Fatalf("context-only word anchor should be valid, got issues: %+v", issues)
	}
}
