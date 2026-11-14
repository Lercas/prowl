package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestForeignFlagsAreRejectedByEveryCommandSchema(t *testing.T) {
	for _, command := range []string{"scan", "compare", "repo", "org", "cicd", "image", "mobile", "bucket", "domain", "jira", "confluence", "serve", "doctor", "mcp", "lsp", "hermes-audit"} {
		for _, spec := range cliFlags {
			if spec.applies(command) {
				continue
			}
			args := []string{spec.names[0]}
			if spec.value != "" {
				args = append(args, "owned")
			}
			_, _, err := parseCommand(command, args)
			if err == nil || !strings.Contains(err.Error(), "does not apply") {
				t.Fatalf("%s accepted foreign flag %s: %v", command, spec.names[0], err)
			}
		}
	}
}

func TestCommandParserKeepsValueTokensAndEndOfFlags(t *testing.T) {
	c, rest, err := parseCommand("scan", []string{"a", "--exclude=--recon", "--format", "json", "b", "--output=--help", "--", "--ml", "-x"})
	if err != nil {
		t.Fatal(err)
	}
	if c.format != "json" || c.output != "--help" || !reflect.DeepEqual(c.exclude, []string{"--recon"}) || !reflect.DeepEqual(rest, []string{"a", "b", "--ml", "-x"}) {
		t.Fatalf("values or positional order changed: %+v %v", c, rest)
	}
	for _, args := range [][]string{{"--output"}, {"--output", "--help"}, {"--output", "-q"}, {"--output="}, {"--workers", "-1"}, {"--ml-threshold=NaN"}, {"--timeout=0s"}, {"--image-input=tar"}} {
		if _, _, err := parseCommand("scan", args); err == nil {
			t.Fatalf("accepted invalid flags: %v", args)
		}
	}
	if _, _, err := parseCommand("scan", []string{"--workrs", "2"}); err == nil || !strings.Contains(err.Error(), "--workers") {
		t.Fatal("missing command-local suggestion")
	}
	if _, _, err := parseCommand("scan", []string{"--workers=https://user:private-value@example.invalid"}); err == nil || strings.Contains(err.Error(), "private-value") {
		t.Fatal("parse diagnostics exposed a value")
	}
}

func TestRepeatedFlagsAndFalseAuthorization(t *testing.T) {
	c, rest, err := parseCommand("jira", []string{"--project=A,B", "host", "--project", "C", "--current-only=true", "--current-only=no"})
	if err != nil || !reflect.DeepEqual(c.cmd.projects, []string{"A", "B", "C"}) || c.cmd.currentOnly || !reflect.DeepEqual(rest, []string{"host"}) {
		t.Fatalf("repeated options: %+v %v %v", c.cmd, rest, err)
	}
	c, _, err = parseCommand("domain", []string{"--authorized=true", "--authorized=false"})
	if err != nil || c.cmd.authorized {
		t.Fatal("explicit false authorization was lost")
	}
	c, _, err = parseCommand("scan", []string{"--format=json", "--format=pretty", "--verified-only=false", "--ml=false"})
	if err != nil || c.format != "pretty" || c.verify || c.mlEmbed {
		t.Fatal("last scalar or explicit false was lost")
	}
}

func TestNestedCommandScopesAndEqualsValues(t *testing.T) {
	c, rest, err := parseCommand("rules", []string{"update", "--source=owned-rules", "--check=false"})
	if err != nil || c.cmd.sub != "update" || c.cmd.source != "owned-rules" || c.cmd.check || len(rest) != 0 {
		t.Fatalf("nested parser: %+v %v", c.cmd, err)
	}
	for _, args := range [][]string{{"list", "--source=owned"}, {"export", "--check"}, {"bogus", "--help"}} {
		if _, _, err := parseCommand("rules", args); err == nil {
			t.Fatalf("accepted invalid nested flags: %v", args)
		}
	}
	if _, _, err := parseCommand("verifiers", []string{"list", "--allow-unsigned"}); err != nil {
		t.Fatal(err)
	}
}

func TestHelpComesFromAcceptedFlagSchema(t *testing.T) {
	for _, command := range []string{"scan", "domain", "mobile", "rules.update", "hermes-audit"} {
		help := commandFlagHelp(command)
		for _, name := range commandFlagNames(command) {
			if !strings.Contains(help, name) {
				t.Fatalf("%s help omits %s", command, name)
			}
		}
	}
	if strings.Contains(commandFlagHelp("scan"), "--recon") || strings.Contains(commandFlagHelp("hermes-audit"), "--show-secrets") {
		t.Fatal("help advertises foreign flags")
	}
	_, _, err := parseCommand("rules", []string{"update", "--help"})
	var help *commandHelpRequest
	if !errors.As(err, &help) || help.command != "rules.update" {
		t.Fatal("nested help lost its scope")
	}
}

func TestCLIParseFailurePreservesExistingReport(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.WriteFile("report.json", []byte("existing report"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"scan", ".", "--output=report.json", "--recon"},
		{"repo", "--depth=1x"},
		{"domain", "--authorized=banana"},
		{"serve", "--recon"},
		{"rules", "list", "--source=owned"},
		{"mcp", "--show-secrets"},
		{"compare", ".", "--ocr"},
	} {
		if code := runCLI(args); code != 2 {
			t.Fatalf("%v returned %d", args, code)
		}
	}
	if raw, err := os.ReadFile("report.json"); err != nil || string(raw) != "existing report" {
		t.Fatal("parse failure replaced an artifact")
	}
}

func TestExplicitDefaultsOverrideOperatorConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operator.yaml")
	if err := os.WriteFile(path, []byte("output:\n  format: json\nperformance:\n  max_size: 2048\n  workers: 7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, explicit := range []bool{false, true} {
		args := []string{"--config", path}
		if explicit {
			args = append(args, "--format=pretty", "--max-size=10MB", "--workers=0")
		}
		c, _, err := parseCommand("scan", args)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfig(&c); err != nil {
			t.Fatal(err)
		}
		if explicit && (c.format != "pretty" || c.maxSize != 10<<20 || c.workers != 0) {
			t.Fatal("explicit defaults lost to configuration")
		}
		if !explicit && (c.format != "json" || c.maxSize != 2048 || c.workers != 7) {
			t.Fatal("configuration defaults were not applied")
		}
	}
}

func TestCLIHelpRoutesDoNotOpenSourcesOrProtocolStreams(t *testing.T) {
	output, err := os.CreateTemp(t.TempDir(), "help")
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = output
	t.Cleanup(func() { os.Stdout = previous; output.Close() })
	for _, command := range commands {
		if command.name == "help" {
			continue
		}
		if code := runCLI([]string{command.name, "--help"}); code != 0 {
			t.Fatalf("%s help returned %d", command.name, code)
		}
	}
	for _, args := range [][]string{{"version"}, {"--version"}, {"-V"}, {"help"}, {"help", "scan"}, {"rules", "update", "--help"}, {"verifiers", "validate", "--help"}} {
		if code := runCLI(args); code != 0 {
			t.Fatalf("%v returned %d", args, code)
		}
	}
	if code := runCLI([]string{"scna"}); code != 2 {
		t.Fatal("unknown command was accepted")
	}
	if code := runCLI(nil); code != 2 {
		t.Fatal("missing command was accepted")
	}
}
