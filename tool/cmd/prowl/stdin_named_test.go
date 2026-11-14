package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNamedStdinFlagScopeAndInputModes(t *testing.T) {
	for _, args := range [][]string{{"--stdin-name", "prod/config.json"}, {"--stdin-name=prod/config.json", "-"}} {
		c, rest, err := parseCommand("scan", args)
		if err != nil || c.stdinName != "prod/config.json" || checkSourceModes(c, rest) != 0 {
			t.Fatalf("valid stdin label rejected: %v", err)
		}
	}
	for _, args := range [][]string{{"--stdin-name="}, {"--stdin-name"}} {
		if _, _, err := parseCommand("scan", args); err == nil {
			t.Fatal("empty stdin label accepted")
		}
	}
	for _, command := range []string{"compare", "repo", "org", "domain", "serve", "mcp", "agents"} {
		if _, _, err := parseCommand(command, []string{"--stdin-name=owned.json"}); err == nil {
			t.Fatalf("%s accepted scan-only label", command)
		}
	}
	for _, args := range [][]string{{"--staged"}, {"--since=HEAD"}, {"--history"}, {"--git-timeline"}, {"path"}, {"-", "path"}} {
		c, rest, err := parseCommand("scan", append([]string{"--stdin-name=owned.json"}, args...))
		if err != nil {
			t.Fatal(err)
		}
		if checkSourceModes(c, rest) != 2 {
			t.Fatalf("conflicting inputs accepted: %v", args)
		}
		if items, err := scanInputAt(t.Context(), c, rest, ""); err == nil || items != nil {
			t.Fatal("input selector bypassed label validation")
		}
	}
	if !strings.Contains(commandFlagHelp("scan"), "--stdin-name") {
		t.Fatal("schema help lost stdin label")
	}
}

func TestInvalidNamedStdinDoesNotTouchReportOrConfiguration(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(root, "report.json")
	if err := os.WriteFile(out, []byte("keep original report"), 0600); err != nil {
		t.Fatal(err)
	}
	code := cmdScan([]string{"--stdin-name=owned.json", "path", "--config", filepath.Join(root, "missing-config.yml"), "--output", out})
	if code != 2 {
		t.Fatalf("conflicting input exit=%d", code)
	}
	raw, err := os.ReadFile(out)
	if err != nil || string(raw) != "keep original report" {
		t.Fatal("invalid source modes changed report")
	}
}
