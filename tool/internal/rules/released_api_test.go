package rules_test

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/rules"
	"gopkg.in/yaml.v3"
)

// These public-API assertions also compile against the immutable released tag.
// The single feature probe names the declared 1.5 value/occurrence mode split.
type occurrenceEngine interface {
	MatchOccurrencesN(string, int) ([]rules.Hit, bool)
}

func releasedAPIEngine(t *testing.T, templates ...rules.Template) *rules.Engine {
	t.Helper()
	var data []byte
	for _, tpl := range templates {
		encoded, err := yaml.Marshal(tpl)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) > 0 {
			data = append(data, []byte("---\n")...)
		}
		data = append(data, encoded...)
	}
	file := filepath.Join(t.TempDir(), "owned.yaml")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	engine, err := rules.Load(file)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}
func releasedAPITemplate() rules.Template {
	return rules.Template{ID: "owned", Info: rules.Info{Name: "Owned", Severity: "high", Tags: "fixture, Contracts"}, Matchers: []rules.Matcher{{Type: "regex", Regex: []string{`OWNED_[A-Z0-9]+`}}}, Extractors: []rules.Extractor{{Type: "regex", Regex: []string{`OWNED_[A-Z0-9]+`}}}}
}
func releasedAPIHit(id, value string, start int) rules.Hit {
	return rules.Hit{RuleID: id, Severity: "high", Tags: []string{"fixture", "contracts"}, Value: value, Start: start, End: start + len(value)}
}
func releasedAPIAssertHits(t *testing.T, got, want []rules.Hit) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("public rule hits differ: got=%+v want=%+v", got, want)
	}
}
func TestReleasedAPIWordAndRegexMatrix(t *testing.T) {
	releasedAPIWordMatrix(t, false)
}

// Empty positive word activation is a known 1.4 bug fixed by the current index.
// Keep this extension separate from the unchanged cross-release matrix.
func TestReleasedAPIEmptyWordActivation(t *testing.T) {
	releasedAPIWordMatrix(t, true)
}

func releasedAPIWordMatrix(t *testing.T, emptyOnly bool) {
	groups := [][]string{{"context", "пароль"}, {"missing", "KEY"}, {"İ", "K", "Σ", "ſ"}, {"�"}, {""}}
	if emptyOnly {
		groups = groups[len(groups)-1:]
	} else {
		groups = groups[:len(groups)-1]
	}
	texts := []string{"", "CONTEXT ПАРОЛЬ OWNED_ABC", "KEY OWNED_123", "İKΣſ OWNED_ABC", "\xff OWNED_ABC", "OWNED_ABC", "ordinary source"}
	for _, outer := range []string{"and", "or"} {
		for _, inner := range []string{"and", "or"} {
			for _, negative := range []bool{false, true} {
				for group, words := range groups {
					tpl := releasedAPITemplate()
					tpl.MatchersCondition = outer
					tpl.Matchers = append([]rules.Matcher{{Type: "word", Words: words, Condition: inner, Negative: negative}}, tpl.Matchers...)
					engine := releasedAPIEngine(t, tpl)
					raw, err := yaml.Marshal(tpl)
					if err != nil {
						t.Fatal(err)
					}
					standalone, err := rules.ParseTemplate(raw, "owned.yaml")
					if err != nil {
						t.Fatal(err)
					}
					for textID, text := range texts {
						t.Run(fmt.Sprintf("%s-%s-negative-%v-group-%d-text-%d", outer, inner, negative, group, textID), func(t *testing.T) {
							lower := strings.ToLower(text)
							wordOK := inner == "and"
							for _, word := range words {
								present := strings.Contains(lower, strings.ToLower(word))
								if inner == "and" {
									wordOK = wordOK && present
								} else {
									wordOK = wordOK || present
								}
							}
							if negative {
								wordOK = !wordOK
							}
							loc := regexp.MustCompile(`OWNED_[A-Z0-9]+`).FindStringIndex(text)
							regexOK := loc != nil
							matched := wordOK && regexOK
							if outer == "or" {
								matched = wordOK || regexOK
							}
							var want []rules.Hit
							if matched && loc != nil {
								want = []rules.Hit{releasedAPIHit("owned", text[loc[0]:loc[1]], loc[0])}
							}
							hits, limited := engine.MatchN(text, 100)
							if limited {
								t.Fatal("unbounded small fixture marked incomplete")
							}
							releasedAPIAssertHits(t, hits, want)
							releasedAPIAssertHits(t, engine.Match(text), want)
							releasedAPIAssertHits(t, standalone.Match(text, lower), want)
						})
					}
				}
			}
		}
	}
}
func TestReleasedAPIRegexSpansAndLimits(t *testing.T) {
	patterns := []string{`OWNED_[A-Z0-9]+`, `(?m)^OWNED_[A-Z0-9]+$`, `(?s)BEGIN:(OWNED_[A-Z0-9]+).*?:END`, `(?:OWNED_ABC|OWNED_DEF)`, `\bOWNED_[A-Z0-9]+\b`}
	texts := []string{"OWNED_ABC", "é prefix OWNED_ABC tail", "OWNED_ABC\nOWNED_DEF", "\xff OWNED_ABC", "BEGIN:OWNED_ABC\nnoise:END", "no match", strings.Repeat("padding line\n", 64) + "OWNED_ABC\n"}
	for patternID, pattern := range patterns {
		tpl := releasedAPITemplate()
		tpl.Matchers[0].Regex = []string{pattern}
		tpl.Extractors[0].Regex = []string{pattern}
		if regexp.MustCompile(pattern).NumSubexp() > 0 {
			tpl.Extractors[0].Group = 1
		}
		engine := releasedAPIEngine(t, tpl)
		re := regexp.MustCompile(pattern)
		for textID, text := range texts {
			for _, limit := range []int{-1, 0, 1, 2, 10} {
				t.Run(fmt.Sprintf("pattern-%d-text-%d-limit-%d", patternID, textID, limit), func(t *testing.T) {
					var want []rules.Hit
					limited := false
					if limit > 0 {
						locations := re.FindAllStringSubmatchIndex(text, -1)
						for _, loc := range locations {
							start, end := loc[0], loc[1]
							if len(loc) > 2 {
								if loc[2] < 0 {
									continue
								}
								start, end = loc[2], loc[3]
							}
							want = append(want, releasedAPIHit("owned", text[start:end], start))
							if len(want) >= limit {
								limited = true
								break
							}
						}
					}
					got, truncated := engine.MatchN(text, limit)
					releasedAPIAssertHits(t, got, want)
					if truncated != limited {
						t.Fatalf("limit status=%v want=%v", truncated, limited)
					}
				})
			}
		}
	}
}
func TestReleasedAPISelectionAndOccurrenceModes(t *testing.T) {
	first, second := releasedAPITemplate(), releasedAPITemplate()
	second.ID = "second"
	second.Info.Severity = "critical"
	second.Info.Tags = "selected"
	engine := releasedAPIEngine(t, first, second)
	text := "OWNED_ABC OWNED_ABC"
	occurrence, hasModes := any(engine).(occurrenceEngine)
	want := []rules.Hit{releasedAPIHit("owned", "OWNED_ABC", 0)}
	if !hasModes {
		want = append(want, releasedAPIHit("owned", "OWNED_ABC", 10))
	}
	secondHit := func(start int) rules.Hit {
		h := releasedAPIHit("second", "OWNED_ABC", start)
		h.Severity = "critical"
		h.Tags = []string{"selected"}
		return h
	}
	want = append(want, secondHit(0))
	if !hasModes {
		want = append(want, secondHit(10))
	}
	hits, limited := engine.MatchN(text, 100)
	if limited {
		t.Fatal("small repeated fixture incomplete")
	}
	releasedAPIAssertHits(t, hits, want)
	if hasModes {
		raw, truncated := occurrence.MatchOccurrencesN(text, 100)
		releasedAPIAssertHits(t, raw, []rules.Hit{releasedAPIHit("owned", "OWNED_ABC", 0), releasedAPIHit("owned", "OWNED_ABC", 10), secondHit(0), secondHit(10)})
		if truncated {
			t.Fatal("occurrence mode lost completeness")
		}
	}
	// Filter after a populated lazy index must rebuild selection and matching state.
	if engine.Filter(rules.FilterOpts{IDs: []string{"second"}, Tags: []string{"selected"}, Severities: []string{"critical"}}) != engine || engine.Len() != 1 {
		t.Fatal("selection did not keep only the requested rule")
	}
	selected := []rules.Hit{secondHit(0)}
	if !hasModes {
		selected = append(selected, secondHit(10))
	}
	releasedAPIAssertHits(t, engine.Match(text), selected)
	engine.Filter(rules.FilterOpts{ExcludeIDs: []string{"second"}})
	if engine.Len() != 0 || len(engine.Match(text)) != 0 {
		t.Fatal("excluded rule survived filter after matching")
	}
}
