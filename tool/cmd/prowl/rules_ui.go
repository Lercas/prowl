package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/saferegex"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

func rulesColor() bool { return os.Getenv("NO_COLOR") == "" && isTTY(os.Stdout) }

func sevAnsi(sev string) string {
	switch sev {
	case "critical":
		return "\x1b[1;31m"
	case "high":
		return "\x1b[31m"
	case "medium":
		return "\x1b[33m"
	default:
		return "\x1b[2m"
	}
}

func ansi(on bool, code, s string) string {
	s = logx.SanitizeTerminal(s) // s may be an untrusted rule field — strip terminal escapes
	if !on || code == "" {
		return s
	}
	return code + s + "\x1b[0m"
}

// builtinCategorySeverity mirrors scan.categorySeverity (unexported) so rules show/test can report a
// built-in detector's severity without importing the scan package.
var builtinCategorySeverity = map[string]string{
	"pki": "critical", "payment": "critical", "db": "critical",
	"cloud": "high", "vcs": "high", "ai": "high", "comms": "high", "messaging": "high",
	"ci": "high", "saas": "high", "observability": "high", "auth": "high",
	"generic": "medium",
}

// builtinSeverity maps a built-in type's category to its severity, applying the same confidence
// demotion scan.severityFor uses (a low-confidence critical drops to high).
func builtinSeverity(category string, conf float64) string {
	s, ok := builtinCategorySeverity[category]
	if !ok {
		s = "medium"
	}
	if conf < 0.7 && s == "critical" {
		s = "high"
	}
	return s
}

// builtinDetector loads the embedded taxonomy and builds the same cascade Detector the scanner uses,
// returning it alongside the taxonomy (for id/regex/gate lookups in show/search).
func builtinDetector() (*detect.Detector, *taxonomy.Taxonomy) {
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		fmt.Fprintf(os.Stderr, "built-in taxonomy: %v\n", err)
		return nil, nil
	}
	return detect.New(tax), tax
}

// loadRulesForQuery loads the rule library for show/test (working dir, else installed).
func loadRulesForQuery() *rules.Engine {
	dir := "rules"
	if !dirExists(dir) {
		dir = installedRulesDir()
	}
	eng, _ := rules.Load(dir)
	return eng
}

// renderRulesList prints templates grouped by category, severity-coloured, with tags.
func renderRulesList(eng *rules.Engine) {
	color := rulesColor()
	byCat := map[string][]*rules.Template{}
	maxID := 0
	for _, t := range eng.Templates() {
		c := t.Category
		if c == "" {
			c = "generic"
		}
		byCat[c] = append(byCat[c], t)
		if len(t.ID) > maxID {
			maxID = len(t.ID)
		}
	}
	if maxID > 40 {
		maxID = 40
	}
	cats := make([]string, 0, len(byCat))
	for c := range byCat {
		cats = append(cats, c)
	}
	sort.Slice(cats, func(i, j int) bool {
		if len(byCat[cats[i]]) != len(byCat[cats[j]]) {
			return len(byCat[cats[i]]) > len(byCat[cats[j]])
		}
		return cats[i] < cats[j]
	})
	for _, c := range cats {
		ts := byCat[c]
		sort.Slice(ts, func(i, j int) bool {
			return model.SeverityOrder[ts[i].Info.Severity] > model.SeverityOrder[ts[j].Info.Severity]
		})
		fmt.Printf("\n  %s %s\n", ansi(color, "\x1b[1m", c), ansi(color, "\x1b[2m", fmt.Sprintf("(%d)", len(ts))))
		for _, t := range ts {
			fmt.Printf("    %s  %-*s  %s\n",
				ansi(color, sevAnsi(t.Info.Severity), fmt.Sprintf("%-8s", t.Info.Severity)),
				maxID, logx.SanitizeTerminal(t.ID),
				ansi(color, "\x1b[2m", strings.Join(t.TagList(), ", ")))
		}
	}
	fmt.Fprintf(os.Stderr, "\n%d templates in %d categories\n", eng.Len(), len(cats))
}

// renderRulesStats prints category/severity breakdowns and the top tags (the rest summarised).
func renderRulesStats(eng *rules.Engine) {
	byCat, bySev, byTag := map[string]int{}, map[string]int{}, map[string]int{}
	for _, t := range eng.Templates() {
		byCat[orDash(t.Category)]++
		bySev[orDash(t.Info.Severity)]++
		for _, tag := range t.TagList() {
			byTag[tag]++
		}
	}
	fmt.Printf("%d templates\n", eng.Len())
	fmt.Println("  category  " + topCounts(byCat, 99))
	fmt.Println("  severity  " + topCounts(bySev, 99))
	fmt.Println("  top tags  " + topCounts(byTag, 12))
}

// topCounts renders "k n · k n ..." for the n highest-count entries, with a "(+N more)" tail.
func topCounts(m map[string]int, limit int) string {
	type kv struct {
		k string
		n int
	}
	var s []kv
	for k, n := range m {
		s = append(s, kv{k, n})
	}
	sort.Slice(s, func(i, j int) bool {
		if s[i].n != s[j].n {
			return s[i].n > s[j].n
		}
		return s[i].k < s[j].k
	})
	var parts []string
	for i, e := range s {
		if i >= limit {
			parts = append(parts, fmt.Sprintf("(+%d more)", len(s)-limit))
			break
		}
		parts = append(parts, fmt.Sprintf("%s %d", e.k, e.n))
	}
	return strings.Join(parts, " · ")
}

// renderRuleShow prints one rule's full detail: it looks the id up among templates, falling back to
// the built-in taxonomy so a cascade detector id (not a template) still shows its regex/severity/gates.
func renderRuleShow(eng *rules.Engine, id string) int {
	color := rulesColor()
	if eng != nil {
		for _, t := range eng.Templates() {
			if t.ID != id {
				continue
			}
			showTemplate(color, t)
			return 0
		}
	}
	if code, ok := showBuiltin(color, id); ok {
		return code
	}
	fmt.Fprintf(os.Stderr, "rule %q not found (try: prowl rules list, or prowl detectors)\n", id)
	return 2
}

// showTemplate renders a template rule's detail block.
func showTemplate(color bool, t *rules.Template) {
	fmt.Printf("\n  %s  %s  %s\n",
		ansi(color, sevAnsi(t.Info.Severity), t.Info.Severity),
		ansi(color, "\x1b[1m", t.ID),
		ansi(color, "\x1b[2m", t.Category))
	fmt.Printf("  %s\n", ansi(color, "\x1b[2m", "source: template"))
	if t.Info.Name != "" {
		fmt.Printf("  %s\n", logx.SanitizeTerminal(t.Info.Name))
	}
	if t.Info.Description != "" {
		fmt.Printf("  %s\n", ansi(color, "\x1b[2m", t.Info.Description))
	}
	fmt.Printf("  tags: %s\n", strings.Join(t.TagList(), ", "))
	for _, r := range t.Info.Reference {
		fmt.Printf("  ref:  %s\n", ansi(color, "\x1b[2m", r))
	}
	cond := t.MatchersCondition
	if cond == "" {
		cond = "or"
	}
	fmt.Printf("  match (%s):\n", cond)
	for _, m := range t.Matchers {
		neg := ""
		if m.Negative {
			neg = " (negative)"
		}
		switch m.Type {
		case "word":
			fmt.Printf("    word     %s%s\n", logx.SanitizeTerminal(strings.Join(m.Words, ", ")), neg)
		case "regex":
			for _, rx := range m.Regex {
				fmt.Printf("    regex    %s%s\n", logx.SanitizeTerminal(rx), neg)
			}
		case "entropy":
			fmt.Printf("    entropy  >= %.1f%s\n", m.Min, neg)
		}
	}
}

// showBuiltin renders a built-in taxonomy detector's detail (regex, category→severity, checksum /
// entropy gates) when id names one. ok is false when the id is not a built-in type.
func showBuiltin(color bool, id string) (int, bool) {
	_, tax := builtinDetector()
	if tax == nil {
		return 2, false
	}
	for _, st := range tax.Types {
		if st.ID != id {
			continue
		}
		sev := builtinSeverity(st.Category, 0.9)
		cat := st.Category
		if cat == "" {
			cat = "generic"
		}
		fmt.Printf("\n  %s  %s  %s\n",
			ansi(color, sevAnsi(sev), sev),
			ansi(color, "\x1b[1m", st.ID),
			ansi(color, "\x1b[2m", cat))
		fmt.Printf("  %s\n", ansi(color, "\x1b[2m", "source: built-in"))
		if st.Name != "" {
			fmt.Printf("  %s\n", st.Name)
		}
		fmt.Printf("  category %s → severity %s\n", cat, ansi(color, sevAnsi(sev), sev))
		fmt.Printf("  match:\n")
		if st.Detection.Regex != "" {
			fmt.Printf("    regex    %s\n", st.Detection.Regex)
		}
		if st.Detection.Charset != "" {
			fmt.Printf("    charset  %s\n", st.Detection.Charset)
		}
		if len(st.Keywords) > 0 {
			fmt.Printf("    keywords %s\n", strings.Join(st.Keywords, ", "))
		}
		if st.Checksum.Present {
			alg := st.Checksum.Algorithm
			if alg == "" {
				alg = "yes"
			}
			fmt.Printf("    checksum %s\n", alg)
		}
		if st.Entropy > 0 {
			fmt.Printf("    entropy  >= %.1f\n", st.Entropy)
		}
		return 0, true
	}
	return 2, false
}

// renderRulesTest reports which rules (built-in cascade + external templates) fire on a sample (literal
// text, @FILE contents, or stdin). When nothing matches it prints a near-miss diagnostic.
func renderRulesTest(eng *rules.Engine, arg string) int {
	color := rulesColor()
	text, label, err := resolveTestInput(arg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rules test: %v\n", err)
		return 2
	}

	n := 0
	seen := map[string]bool{} // dedupe "id" across built-in + templates and repeats

	// Built-in cascade detector — the same engine `scan` runs.
	det, _ := builtinDetector()
	if det != nil {
		for _, m := range det.Scan(text) {
			key := "builtin:" + m.Type
			if seen[key] {
				continue
			}
			seen[key] = true
			sev := builtinSeverity(m.Category, m.Confidence)
			fmt.Printf("  %s  %s  %-8s  %s  %s\n",
				ansi(color, "\x1b[32m", "✓"),
				ansi(color, "\x1b[36m", "built-in"),
				ansi(color, sevAnsi(sev), sev),
				m.Type,
				ansi(color, "\x1b[2m", "matched "+model.Redact(m.Value)))
			n++
		}
	}

	// External rule templates.
	if eng != nil {
		for _, h := range eng.Match(text) {
			key := "template:" + h.RuleID
			if seen[key] {
				continue
			}
			seen[key] = true
			fmt.Printf("  %s  %s  %-8s  %s  %s\n",
				ansi(color, "\x1b[32m", "✓"),
				ansi(color, "\x1b[35m", "template"),
				ansi(color, sevAnsi(h.Severity), h.Severity),
				h.RuleID,
				ansi(color, "\x1b[2m", "matched "+model.Redact(h.Value)))
			n++
		}
	}

	tplCount := 0
	if eng != nil {
		tplCount = eng.Len()
	}
	if n == 0 {
		fmt.Println(ansi(color, "\x1b[2m", "  no rule matched"))
		diagnoseNearMiss(color, eng, text)
		fmt.Fprintf(os.Stderr, "0 matches%s (%d built-in detectors, %d templates)\n", label, builtinTypeCount(), tplCount)
		return 1
	}
	fmt.Fprintf(os.Stderr, "\n%d match(es)%s (%d built-in detectors, %d templates)\n", n, label, builtinTypeCount(), tplCount)
	return 0
}

// resolveTestInput turns the test argument into the text to scan: a literal string, the contents of
// "@FILE", or stdin for "-". It returns a short label (" from <file>"/" from stdin") for the summary.
func resolveTestInput(arg string) (text, label string, err error) {
	switch {
	case arg == "-":
		b, e := io.ReadAll(os.Stdin)
		if e != nil {
			return "", "", fmt.Errorf("reading stdin: %w", e)
		}
		return string(b), " from stdin", nil
	case strings.HasPrefix(arg, "@"):
		path := arg[1:]
		b, e := os.ReadFile(path)
		if e != nil {
			return "", "", fmt.Errorf("reading %s: %w", path, e)
		}
		return string(b), " from " + path, nil
	default:
		return arg, "", nil
	}
}

// builtinTypeCount reports how many built-in detector types are loaded (for the summary line).
func builtinTypeCount() int {
	_, tax := builtinDetector()
	if tax == nil {
		return 0
	}
	return len(tax.Types)
}

// diagnoseNearMiss prints, for the template(s) closest to firing, why they did not. A template scores
// by how far it got (anchor present, regex matched, then a later gate); the top few are reported.
func diagnoseNearMiss(color bool, eng *rules.Engine, text string) {
	if eng == nil || eng.Len() == 0 {
		return
	}
	lower := strings.ToLower(text)
	type cand struct {
		id     string
		score  int
		reason string
	}
	var cands []cand
	for _, t := range eng.Templates() {
		score, reason := templateDiag(t, text, lower)
		if score <= 0 {
			continue // template never engaged the sample
		}
		cands = append(cands, cand{t.ID, score, reason})
	}
	if len(cands) == 0 {
		return
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].score != cands[j].score {
			return cands[i].score > cands[j].score
		}
		return cands[i].id < cands[j].id
	})
	max := 3
	if len(cands) < max {
		max = len(cands)
	}
	for _, c := range cands[:max] {
		fmt.Printf("  %s %s %s\n",
			ansi(color, "\x1b[2m", "closest:"),
			c.id,
			ansi(color, "\x1b[2m", "("+c.reason+")"))
	}
}

// templateDiag inspects how close one template came to firing on text, returning a score (higher =
// closer) and a human reason, or 0 if it never engaged. It tracks the three gates a hit must clear in
// order: a word anchor present, a regex match, then the entropy floor.
func templateDiag(t *rules.Template, text, lower string) (int, string) {
	var (
		anchorWords, anchorPresent bool
		hasRegex, regexMatched     bool
		minEntropy                 float64
		anchorLen                  int // longest matched anchor word — ties broken toward the most specific rule
	)
	for _, m := range t.Matchers {
		switch m.Type {
		case "word":
			if m.Negative {
				continue
			}
			for _, w := range m.Words {
				anchorWords = true
				if strings.Contains(lower, strings.ToLower(w)) {
					anchorPresent = true
					if len(w) > anchorLen {
						anchorLen = len(w)
					}
				}
			}
		case "regex":
			for _, rx := range m.Regex {
				hasRegex = true
				re, err := saferegex.Compile(rx) // loaded rule regex is untrusted — cap it
				if err != nil {
					continue
				}
				if re.MatchString(text) {
					regexMatched = true
				}
			}
		case "entropy":
			if m.Min > minEntropy {
				minEntropy = m.Min
			}
		}
	}

	// Score = stage*100 + anchor-specificity tiebreak, so the gate cleared dominates while a more-
	// specific anchor word (sk_live_ over a bare "live") wins ties between equally-staged rules.
	tie := anchorLen
	if tie > 99 {
		tie = 99
	}
	switch {
	case regexMatched:
		// Regex hit but the template didn't fire: a gate rejected the value — report the likely culprit.
		if minEntropy > 0 {
			anchor := "anchor present"
			if anchorWords && !anchorPresent {
				anchor = "anchor absent"
			}
			return 4*100 + tie, fmt.Sprintf("regex matched but entropy < %.1f rejected it (%s)", minEntropy, anchor)
		}
		if anchorWords && !anchorPresent {
			return 4*100 + tie, "regex matched but anchor word absent (AND-gated)"
		}
		return 3*100 + tie, "regex matched but a later gate rejected it"
	case anchorPresent && hasRegex:
		return 2*100 + tie, "anchor present, regex did not match"
	case anchorPresent:
		return 1*100 + tie, "anchor present, no regex on this rule"
	default:
		return 0, ""
	}
}

// renderRulesSearch searches the whole library (built-in types + templates) for term in the id, tags,
// name, or description (case-insensitive) and prints matches grouped by category. Returns 1 if none.
func renderRulesSearch(term string) int {
	color := rulesColor()
	q := strings.ToLower(strings.TrimSpace(term))
	if q == "" {
		fmt.Fprintln(os.Stderr, "usage: prowl rules search <term>")
		return 2
	}

	type row struct {
		id, severity, category, tags, source string
	}
	byCat := map[string][]row{}
	maxID := 0
	add := func(r row) {
		if r.category == "" {
			r.category = "generic"
		}
		byCat[r.category] = append(byCat[r.category], r)
		if len(r.id) > maxID {
			maxID = len(r.id)
		}
	}

	// Built-in detector types.
	if _, tax := builtinDetector(); tax != nil {
		for _, st := range tax.Types {
			hay := strings.ToLower(strings.Join([]string{st.ID, st.Name, st.Category, strings.Join(st.Keywords, " ")}, " "))
			if !strings.Contains(hay, q) {
				continue
			}
			add(row{
				id:       st.ID,
				severity: builtinSeverity(st.Category, 0.9),
				category: st.Category,
				tags:     strings.Join(st.Keywords, ", "),
				source:   "built-in",
			})
		}
	}

	// External templates.
	if eng := loadRulesForQuery(); eng != nil {
		for _, t := range eng.Templates() {
			tags := t.TagList()
			hay := strings.ToLower(strings.Join([]string{t.ID, t.Info.Name, t.Info.Description, t.Category, strings.Join(tags, " ")}, " "))
			if !strings.Contains(hay, q) {
				continue
			}
			add(row{
				id:       t.ID,
				severity: t.Info.Severity,
				category: t.Category,
				tags:     strings.Join(tags, ", "),
				source:   "template",
			})
		}
	}

	if len(byCat) == 0 {
		fmt.Println(ansi(color, "\x1b[2m", "  no rule matched"))
		fmt.Fprintf(os.Stderr, "0 rules match %q\n", term)
		return 1
	}
	if maxID > 40 {
		maxID = 40
	}
	cats := make([]string, 0, len(byCat))
	total := 0
	for c, rs := range byCat {
		cats = append(cats, c)
		total += len(rs)
	}
	sort.Slice(cats, func(i, j int) bool {
		if len(byCat[cats[i]]) != len(byCat[cats[j]]) {
			return len(byCat[cats[i]]) > len(byCat[cats[j]])
		}
		return cats[i] < cats[j]
	})
	for _, c := range cats {
		rs := byCat[c]
		sort.Slice(rs, func(i, j int) bool {
			if model.SeverityOrder[rs[i].severity] != model.SeverityOrder[rs[j].severity] {
				return model.SeverityOrder[rs[i].severity] > model.SeverityOrder[rs[j].severity]
			}
			return rs[i].id < rs[j].id
		})
		fmt.Printf("\n  %s %s\n", ansi(color, "\x1b[1m", c), ansi(color, "\x1b[2m", fmt.Sprintf("(%d)", len(rs))))
		for _, r := range rs {
			src := ansi(color, "\x1b[2m", fmt.Sprintf("[%s]", r.source))
			tags := ansi(color, "\x1b[2m", r.tags)
			fmt.Printf("    %s  %-*s  %s  %s\n",
				ansi(color, sevAnsi(r.severity), fmt.Sprintf("%-8s", orDash(r.severity))),
				maxID, r.id, src, tags)
		}
	}
	fmt.Fprintf(os.Stderr, "\n%d rule(s) match %q in %d categories\n", total, term, len(cats))
	return 0
}
