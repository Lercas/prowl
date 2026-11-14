package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBundledSelectionAndIsolation(t *testing.T) {
	t.Chdir(t.TempDir())
	home := t.TempDir()
	t.Setenv("PROWL_HOME", home)
	eng, err := loadEngine(commonFlags{})
	if err != nil || eng == nil || eng.Len() != 175 || !eng.Bundled() {
		t.Fatalf("default rules omitted binary snapshot: %v", err)
	}
	if set, err := loadVerifySet(commonFlags{verify: true}); err != nil || set == nil || set.Count() == 0 {
		t.Fatalf("default verifiers omitted snapshot: %v", err)
	}
	if eng, err := loadRulesForQuery(); err != nil || eng.Len() != 175 {
		t.Fatalf("query omitted snapshot: %v", err)
	}
	for _, c := range []commonFlags{{rulesOnly: true}, {noAutoPolicy: true}, {rulesOnly: true, bundled: true}} {
		if eng, err := loadEngine(c); err != nil || eng != nil {
			t.Fatal("implicit rules broke explicit isolation")
		}
	}
	if eng, err := loadEngine(commonFlags{noAutoPolicy: true, bundled: true}); err != nil || eng == nil || eng.Len() != 175 {
		t.Fatal("explicit bundled choice lost under agent isolation")
	}
	for _, kind := range []string{"rules", "verifiers"} {
		if err := os.WriteFile(filepath.Join(home, kind), []byte("broken installed path"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if eng, err := loadEngine(commonFlags{bundled: true, rulesDir: []string{"missing-explicit"}}); err != nil || eng.Len() != 175 {
		t.Fatalf("bundled inspected unselected rules: %v", err)
	}
	if set, err := loadVerifySet(commonFlags{bundled: true, verify: true, verifiers: []string{"missing-explicit"}}); err != nil || set.Count() == 0 {
		t.Fatalf("bundled inspected unselected verifiers: %v", err)
	}
	if set, err := loadVerifySet(commonFlags{bundled: true}); err != nil || set != nil {
		t.Fatal("bundled activated verification without opt-in")
	}
}

func TestBundledFlagScopesAndMCPForwarding(t *testing.T) {
	for _, cmd := range []string{"scan", "compare", "repo", "org", "cicd", "image", "mobile", "bucket", "domain", "jira", "confluence", "agents", "serve", "doctor", "lsp", "version"} {
		c, _, err := parseCommand(cmd, []string{"--bundled"})
		if err != nil || !c.bundled {
			t.Fatalf("%s rejected bundled: %v", cmd, err)
		}
	}
	if _, _, err := parseCommand("mcp", []string{"--bundled"}); err == nil {
		t.Fatal("MCP startup accepted a per-call scan option")
	}
	for _, tool := range mcpTools() {
		argv, err := mcpArgv(tool.Name, map[string]any{"path": "owned", "bundled": true})
		switch tool.Name {
		case "prowl_domain":
			argv, err = mcpArgv(tool.Name, map[string]any{"target": "owned.invalid", "authorized": true, "bundled": true})
		case "prowl_repo":
			argv, err = mcpArgv(tool.Name, map[string]any{"url": "https://owned.invalid/repo", "bundled": true})
		case "prowl_cicd":
			argv, err = mcpArgv(tool.Name, map[string]any{"target": "github:owned/repo", "bundled": true})
		}
		if err != nil {
			t.Fatal(err)
		}
		c, _, err := parseCommand(argv[0], argv[1:])
		if err != nil || !c.bundled {
			t.Fatalf("MCP did not forward bundled: %v", err)
		}
	}
}
