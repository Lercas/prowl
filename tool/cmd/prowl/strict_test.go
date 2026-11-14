package main

import (
	"context"
	"github.com/Lercas/prowl/tool/internal/model"
	"strings"
	"testing"
	"time"
)

func TestStrictCompatibilityPreservesMandatoryCompleteness(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("PROWL_HOME", t.TempDir())
	for _, flag := range []string{"--strict", "--strict=true", "--strict=false"} {
		c, _, err := parseCommand("scan", []string{flag, "--format=json", "--min-severity=critical"})
		if err != nil {
			t.Fatal(err)
		}
		// Even an empty result must fail when acquisition reported an uninspected input.
		c.coverage.Note("owned_input_unread", "owned", true)
		if code := reportFindingsContext(context.Background(), c, nil, time.Millisecond); code != 2 {
			t.Fatalf("%s weakened completeness: %d", flag, code)
		}
	}
	for _, cmd := range strings.Fields(scanCommands) {
		if _, _, err := parseCommand(cmd, []string{"--strict"}); err != nil {
			t.Fatalf("%s: %v", cmd, err)
		}
	}
	if _, _, err := parseCommand("scan", []string{"--strict=invalid"}); err == nil {
		t.Fatal("invalid strict value accepted")
	}
	if _, _, err := parseCommand("mcp", []string{"--strict"}); err == nil {
		t.Fatal("startup scan flags accepted")
	}
	for _, tool := range mcpTools() {
		props := tool.InputSchema["properties"].(map[string]any)
		if _, ok := props["strict"]; !ok {
			t.Fatal("MCP strict schema missing")
		}
	}
	argv, err := mcpArgv("prowl_scan", map[string]any{"path": "owned", "strict": true})
	if err != nil || !strings.Contains(strings.Join(argv, " "), "--strict") {
		t.Fatal("MCP strict was not forwarded")
	}
	// A complete report still uses the ordinary findings gate.
	if code := gate([]model.Finding{{Type: "owned", Severity: "high"}}, "high", false); code != 1 {
		t.Fatal("strict changed severity gate")
	}
}
