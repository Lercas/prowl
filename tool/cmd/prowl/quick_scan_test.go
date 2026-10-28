package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestQuickScanRouting(t *testing.T) {
	file := filepath.Join(t.TempDir(), "sample.txt")
	if err := os.WriteFile(file, []byte("clean"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args, want []string
	}{
		{nil, []string{"scan"}},
		{[]string{file}, []string{"scan", file}},
		{[]string{"./missing"}, []string{"scan", "./missing"}},
		{[]string{"-"}, []string{"scan", "-"}},
		{[]string{"--format", "json"}, []string{"scan", "--format", "json"}},
		{[]string{"--", "--help"}, []string{"scan", "--", "--help"}},
		{[]string{"--help"}, []string{"--help"}},
		{[]string{"--version"}, []string{"--version"}},
		{[]string{"scan"}, []string{"scan"}},
		{[]string{"compare"}, []string{"compare"}},
		{[]string{"mcp"}, []string{"mcp"}},
		{[]string{"scna"}, []string{"scna"}},
		{[]string{"https://example.invalid"}, []string{"https://example.invalid"}},
	} {
		if got := normalizeScanArgs(tc.args); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%v: got %v, want %v", tc.args, got, tc.want)
		}
	}
	for _, command := range commands {
		args := []string{command.name, "--help"}
		if got := normalizeScanArgs(args); !reflect.DeepEqual(got, args) {
			t.Errorf("command %s routed to scan", command.name)
		}
	}
}

func TestScanEndOfOptions(t *testing.T) {
	c, rest := parseCommon([]string{"--format", "json", "--", "--verify", "--help"})
	if c.verify || c.format != "json" || !reflect.DeepEqual(rest, []string{"--verify", "--help"}) {
		t.Fatalf("options after -- were interpreted: verify=%v rest=%v", c.verify, rest)
	}
	if hasHelpFlag([]string{"--", "--help"}) || !hasHelpFlag([]string{"--help", "--"}) {
		t.Fatal("help ignores the end-of-options boundary")
	}
}

func TestExplicitDefaultFlagsBeatConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("version: 1\noutput: {format: json}\nperformance: {max_size: 1, workers: 2}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c, _ := parseCommon([]string{"--config", path, "--format", "pretty", "--max-size", "10MB", "--workers", "0"})
	loadConfig(&c)
	if c.format != "pretty" || c.maxSize != 10<<20 || c.workers != 0 {
		t.Fatalf("explicit defaults overridden: format=%s maxSize=%d workers=%d", c.format, c.maxSize, c.workers)
	}
	c, _ = parseCommon([]string{"--config", path})
	loadConfig(&c)
	if c.format != "json" || c.maxSize != 1 || c.workers != 2 {
		t.Fatal("implicit defaults no longer inherit configuration")
	}
}

func TestCIGateDefaultsAndOverrides(t *testing.T) {
	for _, args := range [][]string{{"--ci"}, {"--ci", "--fail-on", "critical"}, {"--fail-on", "critical", "--ci"}} {
		c, _ := parseCommon(args)
		want := "critical"
		if len(args) == 1 {
			want = "high"
		}
		if !c.strict || c.failOn != want || c.verify || c.mlEmbed || c.ocrEnabled || c.semantic {
			t.Fatalf("CI changed detection or network stages: %v", args)
		}
	}
}

func TestNamedStdinRejectsOtherInputs(t *testing.T) {
	for _, args := range [][]string{
		{"--stdin-name", "config.json", "file.json"},
		{"--stdin-name", "config.json", "--history"},
		{"--stdin-name", "config.json", "--since", "HEAD"},
		{"--stdin-name", "config.json", "--staged"},
	} {
		c, rest := parseCommon(args)
		if code := checkSourceModes(c, rest); code != 2 {
			t.Fatalf("ambiguous named stdin accepted: %v", args)
		}
	}
	for _, args := range [][]string{{"--stdin-name", "config.json"}, {"--stdin-name", "config.yaml", "-"}} {
		c, rest := parseCommon(args)
		if code := checkSourceModes(c, rest); code != 0 {
			t.Fatalf("valid named stdin rejected: %v", args)
		}
	}
}
