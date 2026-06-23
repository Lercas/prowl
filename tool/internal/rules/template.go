// Package rules implements nuclei-style secret-detection templates: one YAML file per rule with an
// info block, matchers (word / regex / entropy) combined with AND/OR, and extractors.
package rules

import (
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/Lercas/prowl/tool/internal/saferegex"
	"gopkg.in/yaml.v3"
)

// MaxTemplateSize caps a template's YAML bytes so an untrusted giant file can't burn CPU/RAM during
// decode. Per-regex regex-bomb guards live in internal/saferegex (used here via saferegex.Compile).
const MaxTemplateSize = 512 * 1024

// Info is the nuclei-style metadata block.
type Info struct {
	Name        string   `yaml:"name"`
	Author      string   `yaml:"author"`
	Severity    string   `yaml:"severity"` // info|low|medium|high|critical
	Description string   `yaml:"description"`
	Reference   []string `yaml:"reference"`
	Tags        string   `yaml:"tags"` // comma-separated (nuclei convention)
}

// Matcher matches part of the text by word presence, regex, or Shannon entropy.
type Matcher struct {
	Type      string   `yaml:"type"` // word|regex|entropy
	Words     []string `yaml:"words"`
	Regex     []string `yaml:"regex"`
	Condition string   `yaml:"condition"` // and|or within this matcher (default or)
	Min       float64  `yaml:"min"`       // entropy floor
	Negative  bool     `yaml:"negative"`

	res []*regexp.Regexp
}

// Extractor pulls the secret value out of a match.
type Extractor struct {
	Type  string   `yaml:"type"` // regex
	Regex []string `yaml:"regex"`
	Group int      `yaml:"group"` // capture group to extract; 0 (when explicitly set) == whole match

	res      []*regexp.Regexp
	groupSet bool // whether "group" appeared in the YAML (distinguishes unset from an explicit 0)
}

// UnmarshalYAML decodes an Extractor, recording whether "group" was present so an unset group can
// default to capture group 1 while an explicit "group: 0" means the whole match.
func (e *Extractor) UnmarshalYAML(node *yaml.Node) error {
	type rawExtractor Extractor // alias without this method, to avoid infinite recursion
	var r rawExtractor
	if err := node.Decode(&r); err != nil {
		return err
	}
	*e = Extractor(r)
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == "group" {
				e.groupSet = true
				break
			}
		}
	}
	return nil
}

// Template is one nuclei-style rule.
type Template struct {
	ID                string      `yaml:"id"`
	Info              Info        `yaml:"info"`
	Category          string      `yaml:"category"` // optional Prowl category override (severity mapping)
	MatchersCondition string      `yaml:"matchers-condition"`
	Matchers          []Matcher   `yaml:"matchers"`
	Extractors        []Extractor `yaml:"extractors"`

	path string
}

// isZero reports whether the template was decoded from an empty YAML document (a trailing "---", a
// comment-only doc) and should be skipped rather than treated as malformed. Any populated field makes
// it non-zero so it still reaches compile.
func (t *Template) isZero() bool {
	i := t.Info
	infoEmpty := i.Name == "" && i.Author == "" && i.Severity == "" &&
		i.Description == "" && i.Tags == "" && len(i.Reference) == 0
	return t.ID == "" && t.Category == "" && t.MatchersCondition == "" &&
		infoEmpty && len(t.Matchers) == 0 && len(t.Extractors) == 0
}

// Hit is one detection produced by a template.
type Hit struct {
	RuleID     string
	Severity   string
	Category   string
	Tags       []string
	Value      string
	Start, End int
}

// ParseTemplate decodes and compiles a single template's YAML.
func ParseTemplate(raw []byte, path string) (*Template, error) {
	if len(raw) > MaxTemplateSize {
		return nil, fmt.Errorf("%s: template too large (%d bytes > %d limit)", path, len(raw), MaxTemplateSize)
	}
	var t Template
	if err := yaml.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	t.path = path
	if err := t.compile(); err != nil {
		return nil, err
	}
	return &t, nil
}

func (t *Template) compile() error {
	if t.ID == "" {
		return fmt.Errorf("%s: template has no id", t.path)
	}
	if len(t.Matchers) == 0 {
		return fmt.Errorf("%s (%s): no matchers", t.path, t.ID)
	}
	for i := range t.Matchers {
		m := &t.Matchers[i]
		switch m.Type {
		case "word", "regex", "entropy":
		case "":
			m.Type = "regex"
		default:
			return fmt.Errorf("%s (%s): unknown matcher type %q", t.path, t.ID, m.Type)
		}
		for _, rx := range m.Regex {
			re, err := saferegex.Compile(rx)
			if err != nil {
				return fmt.Errorf("%s (%s): bad regex %q: %w", t.path, t.ID, rx, err)
			}
			m.res = append(m.res, re)
		}
	}
	for i := range t.Extractors {
		e := &t.Extractors[i]
		for _, rx := range e.Regex {
			re, err := saferegex.Compile(rx)
			if err != nil {
				return fmt.Errorf("%s (%s): bad extractor regex %q: %w", t.path, t.ID, rx, err)
			}
			e.res = append(e.res, re)
		}
		if e.Group < 0 {
			return fmt.Errorf("%s (%s): extractor group %d is negative", t.path, t.ID, e.Group)
		}
		// The group applies per-regex and falls back to the whole match for a regex with fewer
		// groups, so an extractor may legitimately mix a captured-group regex with a whole-match one.
		// Reject only a group that NO regex can satisfy (a real typo).
		maxGroups := 0
		for _, re := range e.res {
			if n := re.NumSubexp(); n > maxGroups {
				maxGroups = n
			}
		}
		if e.Group > maxGroups {
			return fmt.Errorf("%s (%s): extractor group %d exceeds the capture groups (%d) of every regex",
				t.path, t.ID, e.Group, maxGroups)
		}
	}
	return nil
}

// TagList returns the template's tags as a slice.
func (t *Template) TagList() []string {
	var out []string
	for _, s := range strings.Split(t.Info.Tags, ",") {
		if s = strings.TrimSpace(strings.ToLower(s)); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Keywords returns pre-filter anchor substrings that let the template be skipped when none are
// present. It returns anchors ONLY when a word match is provably required for any hit (else nil =
// "always run"), so the Aho-Corasick pre-filter never hides a match: under AND any non-negative word
// matcher's words are required; under OR anchoring is sound only if every matcher is a non-negative
// word matcher. A negative word matcher contributes no anchor.
func (t *Template) Keywords() []string {
	var words []string
	for _, m := range t.Matchers {
		if m.Type == "word" && !m.Negative {
			words = append(words, m.Words...)
		}
	}
	if len(words) == 0 {
		return nil // no positive word matcher: nothing safe to anchor on -> always run
	}
	if strings.EqualFold(t.MatchersCondition, "or") {
		// Under OR, anchoring is sound only if no matcher can fire without an anchor word.
		for _, m := range t.Matchers {
			if m.Type != "word" || m.Negative {
				return nil // a non-word/negative matcher could satisfy the OR alone -> always run
			}
		}
	}
	return words
}

// Match evaluates the template against text (lower is a lowercased copy for word matchers) and
// returns hits with extracted values, bounded by MaxEngineMatches.
func (t *Template) Match(text, lower string) []Hit {
	hits, _ := t.matchN(text, lower, MaxEngineMatches)
	return hits
}

// matchN is Match capped at limit hits, also reporting whether the cap truncated the template's
// output. A limit <= 0 yields nothing (the combined cap is already exhausted upstream).
func (t *Template) matchN(text, lower string, limit int) ([]Hit, bool) {
	if limit <= 0 {
		return nil, false
	}
	and := !strings.EqualFold(t.MatchersCondition, "or") // nuclei default is AND
	var minEntropy float64
	matchedAll, matchedAny := true, false
	for i := range t.Matchers {
		ok := t.Matchers[i].eval(text, lower, &minEntropy)
		if t.Matchers[i].Negative {
			ok = !ok
		}
		matchedAll = matchedAll && ok
		matchedAny = matchedAny || ok
	}
	if (and && !matchedAll) || (!and && !matchedAny) {
		return nil, false
	}
	return t.extract(text, minEntropy, limit)
}

func (m *Matcher) eval(text, lower string, minEntropy *float64) bool {
	switch m.Type {
	case "word":
		return listMatch(len(m.Words), m.Condition, func(i int) bool {
			return strings.Contains(lower, strings.ToLower(m.Words[i]))
		})
	case "regex":
		return listMatch(len(m.res), m.Condition, func(i int) bool {
			return m.res[i].MatchString(text)
		})
	case "entropy":
		if m.Min > *minEntropy {
			*minEntropy = m.Min
		}
		return true
	}
	return false
}

// listMatch applies the and/or condition over n items.
func listMatch(n int, cond string, ok func(int) bool) bool {
	if n == 0 {
		return false
	}
	all := strings.EqualFold(cond, "and")
	for i := 0; i < n; i++ {
		m := ok(i)
		if all && !m {
			return false
		}
		if !all && m {
			return true
		}
	}
	return all
}

// extractRe pairs a compiled regex with the capture group whose span is the extracted value.
type extractRe struct {
	re    *regexp.Regexp
	group int // capture group index; 0 == whole match
}

// extract pulls values via the extractors (or regex matchers) and applies the entropy floor, bounded
// at limit hits (the bool reports truncation). Each regex's FindAll is capped at the remaining budget
// so a dense file never materializes the full submatch slice up front.
func (t *Template) extract(text string, minEntropy float64, limit int) ([]Hit, bool) {
	if limit <= 0 {
		return nil, false
	}
	res := t.extractRes()
	if len(res) == 0 { // presence-only rule: report the whole text
		// Enforce the entropy floor here too: an entropy-only template (no regex/extractor) falls into
		// this branch, and without the check it would report the whole file regardless of its entropy.
		if minEntropy > 0 && shannon(text) < minEntropy {
			return nil, false
		}
		return []Hit{t.hit(text, 0, len(text))}, false
	}
	var hits []Hit
	seen := map[string]bool{}
	for _, x := range res {
		// Ask for at most (remaining budget + 1) so we stop early on a dense file yet can detect
		// truncation; dedupe via seen, so the +1 is a safe over-fetch.
		want := limit - len(hits) + 1
		for _, loc := range x.re.FindAllStringSubmatchIndex(text, want) {
			s, e := loc[0], loc[1] // group 0 == whole match
			if g := x.group; g > 0 && 2*g+1 < len(loc) {
				if loc[2*g] < 0 { // requested group did not participate in this match
					continue
				}
				s, e = loc[2*g], loc[2*g+1]
			}
			val := text[s:e]
			if minEntropy > 0 && shannon(val) < minEntropy {
				continue
			}
			if seen[val] {
				continue
			}
			seen[val] = true
			hits = append(hits, t.hit(val, s, e))
			if len(hits) >= limit {
				return hits, true // budget hit: stop before building more
			}
		}
	}
	return hits, false
}

// extractRes returns the regexes (with their target capture group) used to pull values: the
// extractors if any, else the regex matchers. An extractor's group defaults to 1 when unset; an
// explicit 0 means the whole match.
func (t *Template) extractRes() []extractRe {
	var res []extractRe
	for i := range t.Extractors {
		e := &t.Extractors[i]
		g := e.Group
		if g == 0 && !e.groupSet {
			g = 1
		}
		for _, re := range e.res {
			res = append(res, extractRe{re: re, group: g})
		}
	}
	if len(res) > 0 {
		return res
	}
	for i := range t.Matchers {
		if t.Matchers[i].Type == "regex" {
			for _, re := range t.Matchers[i].res {
				res = append(res, extractRe{re: re, group: 1}) // matcher fallback: prefer group 1
			}
		}
	}
	return res
}

func (t *Template) hit(val string, s, e int) Hit {
	return Hit{RuleID: t.ID, Severity: t.Info.Severity, Category: t.Category,
		Tags: t.TagList(), Value: val, Start: s, End: e}
}

func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]float64
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	h := 0.0
	for _, c := range counts {
		if c > 0 {
			p := c / n
			h -= p * math.Log2(p)
		}
	}
	return h
}
