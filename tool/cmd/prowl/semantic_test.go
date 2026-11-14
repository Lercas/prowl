package main

import (
	"strings"
	"testing"
)

func TestSemanticCLISelectionAndPrivacy(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("PROWL_HOME", t.TempDir())
	t.Setenv("PROWL_SEMANTIC_URL", "http://127.0.0.1:9/model")
	t.Setenv("PROWL_SEMANTIC_MODEL", "owned-model")
	t.Setenv("PROWL_SEMANTIC_API_KEY", "owned-private-key")
	for _, cmd := range strings.Fields(indexedCommands) {
		c, _, err := parseCommand(cmd, []string{"--semantic"})
		if err != nil || !c.semantic || c.semanticEngine == nil {
			t.Fatalf("%s semantic setup failed: %v", cmd, err)
		}
	}
	for _, args := range [][]string{{"--semantic-url=http://127.0.0.1:9/model"}, {"--semantic-model=owned"}} {
		c, _, err := parseCommand("scan", args)
		if err != nil || !c.semantic || c.semanticEngine == nil {
			t.Fatal("explicit model settings did not enable semantic")
		}
	}
	t.Setenv("PROWL_SEMANTIC_URL", "https://owned.invalid/model")
	if _, _, err := parseCommand("scan", []string{"--semantic"}); err == nil || strings.Contains(err.Error(), "owned-private-key") {
		t.Fatal("remote inference accepted without explicit opt-in or disclosed API key")
	}
	c, _, err := parseCommand("scan", []string{"--semantic=false"})
	if err != nil || c.semantic || c.semanticEngine != nil {
		t.Fatal("disabled model inspected unselected service")
	}
	if _, _, err := parseCommand("scan", []string{"--semantic", "--semantic-allow-remote"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseCommand("compare", []string{"--semantic"}); err == nil {
		t.Fatal("nondeterministic semantic comparison accepted without a frozen candidate set")
	}
	if _, _, err := parseCommand("serve", []string{"--semantic"}); err == nil {
		t.Fatal("unsupported worker stage silently accepted")
	}
	argv, err := mcpArgv("prowl_scan", map[string]any{"path": "owned", "semantic": true})
	if err != nil || !strings.Contains(strings.Join(argv, " "), "--semantic") {
		t.Fatal("MCP did not forward semantic")
	}
}
