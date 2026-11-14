package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
	"github.com/Lercas/prowl/tool/internal/verify"
)

func cmdDetectors() int {
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	for _, t := range tax.Types {
		ck := ""
		if t.Checksum.Present {
			ck = " [checksum]"
		}
		fmt.Printf("%-26s %-14s%s\n", t.ID, t.Category, ck)
	}
	return 0
}

// cmdRules manages the rule set: export|list|validate|update|stats. DIR defaults to ./rules.
func cmdRules(args []string) int {
	c, dirs, err := parseCommand("rules", args)
	if err != nil {
		return commandParseError(err)
	}
	sub, out, source := c.cmd.sub, c.output, c.cmd.source
	tagFilter, sevFilter, ruleFiles := c.tags, c.ruleSeverity, c.rules
	check, allowUnsigned := c.cmd.check, c.cmd.allowUnsigned
	userPos := dirs // positionals as given (rule id / test text for show/test)
	if len(dirs) == 0 {
		dirs = []string{"rules"}
	}
	templatePaths := append(append([]string{}, userPos...), ruleFiles...)
	if len(templatePaths) == 0 && (sub == "list" || sub == "validate" || sub == "stats") {
		var err error
		templatePaths, err = defaultQueryRulePaths()
		if err != nil {
			fmt.Fprintln(os.Stderr, "rule discovery error:", err)
			if sub == "validate" {
				return 1
			}
			return 2
		}
	}

	switch sub {
	case "export":
		data := taxonomy.DefaultYAML()
		// Exported taxonomy contains public detector definitions, not credentials.
		if err := writeArtifactBytes(out, data, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 2
		}
		if out == "" {
			return 0
		}
		fmt.Fprintf(os.Stderr, "exported built-in taxonomy to %s — edit and use with --taxonomy %s\n", out, out)
		return 0

	case "list":
		eng, err := rules.Load(templatePaths...)
		if err != nil {
			fmt.Fprintln(os.Stderr, "rule load error:", err)
			return 2
		}
		if eng == nil || eng.Len() == 0 {
			fmt.Fprintln(os.Stderr, "no rule templates found; run 'prowl rules update'")
			return 0
		}
		eng.Filter(rules.FilterOpts{Tags: splitCSV(tagFilter), Severities: splitCSV(sevFilter)})
		renderRulesList(eng)
		return 0

	case "show":
		if len(userPos) == 0 {
			fmt.Fprintln(os.Stderr, "usage: prowl rules show <rule-id>   (see 'prowl rules list')")
			return 2
		}
		eng, err := loadRulesForQuery(ruleFiles...)
		if err != nil {
			fmt.Fprintln(os.Stderr, "rule load error:", err)
			return 2
		}
		return renderRuleShow(eng, userPos[0])

	case "test":
		if len(userPos) == 0 {
			fmt.Fprintln(os.Stderr, "usage: prowl rules test <text>   (which rules fire on this string)")
			return 2
		}
		eng, err := loadRulesForQuery(ruleFiles...)
		if err != nil {
			fmt.Fprintln(os.Stderr, "rule load error:", err)
			return 2
		}
		return renderRulesTest(eng, strings.Join(userPos, " "))

	case "search":
		if len(userPos) == 0 {
			fmt.Fprintln(os.Stderr, "usage: prowl rules search <term>   (id / tag / description, built-ins + templates)")
			return 2
		}
		eng, err := loadRulesForQuery(ruleFiles...)
		if err != nil {
			fmt.Fprintln(os.Stderr, "rule load error:", err)
			return 2
		}
		return renderRulesSearch(strings.Join(userPos, " "), eng)

	case "validate":
		issues := rules.ValidateDir(templatePaths...)
		nerr, nwarn := 0, 0
		for _, is := range issues {
			loc := is.Path
			if is.Rule != "" {
				loc += " (" + is.Rule + ")"
			}
			fmt.Printf("  %-5s %s: %s\n", strings.ToUpper(is.Level), loc, is.Msg)
			if is.Level == "error" {
				nerr++
			} else {
				nwarn++
			}
		}
		eng, loadErr := rules.Load(templatePaths...)
		if loadErr != nil && nerr == 0 {
			fmt.Fprintln(os.Stderr, "rule load error:", loadErr)
			nerr++
		}
		fmt.Fprintf(os.Stderr, "\n%d templates, %d error(s), %d warning(s)\n", eng.Len(), nerr, nwarn)
		if nerr > 0 {
			return 1
		}
		return 0

	case "update":
		return updateInto("rules", source, installedRulesDir(), time.Now().UTC().Format(time.RFC3339), check, allowUnsigned)

	case "manifest": // (re)generate MANIFEST.sha256 to bless the current contents of a rule dir
		return rulesManifestCmd(dirs[0], len(userPos) > 0)

	case "stats":
		eng, err := rules.Load(templatePaths...)
		if err != nil {
			fmt.Fprintln(os.Stderr, "rule load error:", err)
			return 2
		}
		renderRulesStats(eng)
		return 0

	default:
		fmt.Fprintln(os.Stderr, "usage: prowl rules list|show <id>|test <text>|search <term>|validate|stats|update|manifest|export")
		return 2
	}
}

// cmdVerifiers manages live-verifiers: list|validate|update. DIR defaults to the installed
// ~/.prowl/verifiers (then ./verifiers); `update` installs there from --source or the bundled set.
func cmdVerifiers(args []string) int {
	c, dirs, err := parseCommand("verifiers", args)
	if err != nil {
		return commandParseError(err)
	}
	sub, source, check, allowUnsigned := c.cmd.sub, c.cmd.source, c.cmd.check, c.cmd.allowUnsigned
	if sub == "update" {
		return updateInto("verifiers", source, installedVerifiersDir(), time.Now().UTC().Format(time.RFC3339), check, allowUnsigned)
	}
	if len(dirs) == 0 {
		var err error
		dirs, err = discoverVerifierDirs(nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, "verifier discovery error:", err)
			if sub == "validate" || sub == "manifest" {
				return 1
			}
			return 2
		}
		if len(dirs) == 0 {
			dirs = []string{"verifiers"}
		}
	}
	if sub == "manifest" { // (re)generate MANIFEST.sha256 to bless the current contents of a verifier dir
		n, err := verify.GenerateManifest(dirs[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, "manifest:", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "wrote %s (%d files) in %s\n", verify.ManifestName, n, dirs[0])
		return 0
	}
	// list/validate load with bundled trust, honouring --allow-unsigned so an operator can inspect an
	// unsigned set without it being silently trusted.
	set, err := verify.LoadWithPolicy(0, verify.LoadPolicy{AllowUnsigned: allowUnsigned}, dirs...)
	switch sub {
	case "validate":
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "%d verifiers, all valid\n", set.Count())
		return 0
	case "list":
		if err != nil {
			fmt.Fprintln(os.Stderr, "verifier load error:", err)
			return 2
		}
		fmt.Printf("%-16s %-28s %s\n", "VERIFIER", "MATCHES", "ENDPOINT")
		for _, v := range set.Verifiers() {
			ep := ""
			if len(v.Requests) > 0 {
				ep = v.Requests[0].URL
			}
			fmt.Printf("%-16s %-28s %s\n", v.ID, strings.Join(v.Match, ","), ep)
		}
		fmt.Fprintf(os.Stderr, "\n%d verifiers\n", set.Count())
		return 0
	default:
		fmt.Fprintln(os.Stderr, "usage: prowl verifiers list|validate|update|manifest [DIR] [--source SRC] [--check] [--allow-unsigned]")
		return 2
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
