package main

import (
	"fmt"
	"sort"
	"strings"
)

// flagGroups orders a command's flags by what the user is trying to do. A flag not named here is
// specific to its command and is listed first, untitled.
var flagGroups = []struct {
	title string
	names []string
}{
	{"Input", []string{"--staged", "--since", "--history", "--git-timeline", "--stdin-name", "--exclude", "--max-size", "--reconstruct"}},
	{"Output", []string{"--format", "--output", "--show-secrets", "--no-color", "--identity-key-file"}},
	{"Exit code", []string{"--fail-on", "--ci", "--fail-on-verified", "--strict"}},
	{"Noise control", []string{"--min-severity", "--min-confidence", "--disable", "--max-per-file", "--dedupe", "--no-dedupe", "--baseline", "--write-baseline"}},
	{"Live verification", []string{"--verify", "--verify-all", "--verified-only", "--verifiers"}},
	{"ML filter", []string{"--ml", "--ml-model", "--ml-url", "--ml-threshold"}},
	{"Semantic search", []string{"--semantic", "--semantic-url", "--semantic-model", "--semantic-allow-remote"}},
	{"OCR", []string{"--ocr", "--ocr-url", "--ocr-model", "--ocr-allow-remote", "--ocr-all-pages", "--ocr-max-pages", "--ocr-timeout"}},
	{"Rules and configuration", []string{"--config", "--rules-dir", "--tags", "--exclude-tags", "--rule-severity", "--rules", "--rules-only", "--taxonomy", "--bundled"}},
	{"Secret index", []string{"--index", "--scope"}},
	{"Performance", []string{"--workers", "--timeout"}},
	{"Logging", []string{"--quiet", "--silence", "--verbose", "--log-level", "--log-format"}},
	{"Help", []string{"--help"}},
}

// groupedHelpMin is the flag count from which headings help more than they cost.
const groupedHelpMin = 12

// maxFlagLabel caps the label column; a longer label puts its description on the next line.
const maxFlagLabel = 30

type flagHelpRow struct {
	label, description string
	rank               int
}

// commandFlagHelp renders the flags a command accepts, straight from the parser's schema.
func commandFlagHelp(command string) string {
	groupOf, rank := map[string]int{}, map[string]int{}
	for i, group := range flagGroups {
		for j, name := range group.names {
			groupOf[name], rank[name] = i+1, j
		}
	}
	rows := make([][]flagHelpRow, len(flagGroups)+1)
	total, width := 0, 0
	for _, flag := range cliFlags {
		flag = flag.forCommand(command)
		applies := flag.applies(command)
		var scopes []string
		for _, scope := range flag.commands {
			if strings.HasPrefix(scope, command+".") {
				applies = true
				scopes = append(scopes, strings.ReplaceAll(scope, ".", " "))
			}
		}
		if !applies {
			continue
		}
		label := strings.Join(flag.names, ", ")
		if flag.value != "" {
			label += " " + flag.value
		}
		description := flag.description
		if !flag.applies(command) && len(scopes) > 0 {
			description += " [" + strings.Join(scopes, ", ") + "]"
		}
		group := groupOf[flag.names[0]]
		rows[group] = append(rows[group], flagHelpRow{label, description, rank[flag.names[0]]})
		total++
		if n := len([]rune(label)); n > width && n <= maxFlagLabel {
			width = n
		}
	}
	var output strings.Builder
	for group, list := range rows {
		if len(list) == 0 {
			continue
		}
		if group > 0 {
			sort.SliceStable(list, func(i, j int) bool { return list[i].rank < list[j].rank })
		}
		if total >= groupedHelpMin {
			title := "This command"
			if group > 0 {
				title = flagGroups[group-1].title
			}
			if output.Len() > 0 {
				output.WriteByte('\n')
			}
			fmt.Fprintf(&output, "%s:\n", title)
		} else if output.Len() == 0 {
			output.WriteString("Flags:\n")
		}
		for _, row := range list {
			if len([]rune(row.label)) > width {
				fmt.Fprintf(&output, "  %s\n  %*s %s\n", row.label, width, "", row.description)
				continue
			}
			fmt.Fprintf(&output, "  %-*s %s\n", width, row.label, row.description)
		}
	}
	return output.String()
}

// commandGroups orders the top-level command list by purpose.
var commandGroups = []struct {
	title string
	names []string
}{
	{"Scan", []string{"scan", "repo", "org", "cicd", "image", "mobile", "bucket", "domain", "jira", "confluence", "agents", "hermes-audit"}},
	{"Track and compare", []string{"index", "diff", "compare", "correlate", "remediation-check"}},
	{"Integrate", []string{"guard", "serve", "lsp", "mcp", "completion"}},
	{"Set up", []string{"init", "identity", "doctor", "selftest", "detectors", "rules", "verifiers", "config", "version", "help"}},
}

func usageText() string {
	var output strings.Builder
	output.WriteString("prowl — configurable secret scanner\n\nUsage: prowl <command> [flags] [targets]\n\n" +
		"Quick start:\n" +
		"  prowl                           scan the current directory\n" +
		"  prowl scan src/ --verify        scan a path and check which secrets are live\n" +
		"  prowl scan --staged --ci        pre-commit / CI gate: exit 1 on high or critical\n")
	summary := map[string]string{}
	for _, command := range commands {
		summary[command.name] = command.summary
	}
	listed := map[string]bool{}
	for _, group := range commandGroups {
		fmt.Fprintf(&output, "\n%s:\n", group.title)
		for _, name := range group.names {
			if text, ok := summary[name]; ok {
				fmt.Fprintf(&output, "  %-15s %s\n", name, text)
				listed[name] = true
			}
		}
	}
	// A command added to the table but not yet to a group must still be discoverable.
	other := false
	for _, command := range commands {
		if listed[command.name] {
			continue
		}
		if !other {
			output.WriteString("\nOther:\n")
			other = true
		}
		fmt.Fprintf(&output, "  %-15s %s\n", command.name, command.summary)
	}
	output.WriteString("\nRun 'prowl <command> --help' for accepted flags and examples.\nFlags are command-scoped; -- ends flag parsing.\n")
	return output.String()
}
