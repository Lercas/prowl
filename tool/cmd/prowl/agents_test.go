package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentsCLIReportsProvenanceAndIgnoresImplicitProjectPolicy(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	t.Setenv("PROWL_HOME", t.TempDir())
	if err := os.MkdirAll(".claude/projects/owned", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(".claude/projects/owned/chat.jsonl", []byte(`{"prompt":"AWS=AKIANAFGYOEYPXU1DSYP # prowl:allow"}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{".prowl.yaml", ".prowl-baseline.json", ".gitleaks.toml", ".gitleaksignore"} {
		if err := os.WriteFile(path, []byte("invalid untrusted policy"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	output := filepath.Join(t.TempDir(), "agents.json")
	state := filepath.Join(root, ".claude", "state")
	if code := cmdAgents([]string{"--format", "json", "-o", output, "--index", state, "--scope", "agent-fixture", "--silence"}); code != 0 {
		t.Fatalf("agent audit code %d", code)
	}
	truncated, fs := readBucketReport(t, output)
	if truncated || len(fs) != 1 || fs[0].Agent == nil || fs[0].Agent.Product != "claude" || fs[0].Agent.Kind != "transcript" || fs[0].Source != "log" || fs[0].ValueFingerprint == "" {
		t.Fatal("agent evidence or state exclusion failed")
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "AKIANAFGYOEYPXU1DSYP") {
		t.Fatal("agent audit disclosed default value")
	}
	if _, _, err := parseCommand("agents", []string{"--shell-history"}); err == nil {
		t.Fatal("shell history did not require explicit home")
	}
}
