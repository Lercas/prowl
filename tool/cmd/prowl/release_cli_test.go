package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestReleasedQuickScanRouting(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	for _, name := range []string{"sample.env", "scan", "guard", "index"} {
		if err := os.WriteFile(name, []byte("clean"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ args, want []string }{
		{nil, []string{"scan"}},
		{[]string{"sample.env"}, []string{"scan", "sample.env"}},
		{[]string{filepath.Join(root, "missing")}, []string{"scan", filepath.Join(root, "missing")}},
		{[]string{"./missing"}, []string{"scan", "./missing"}},
		{[]string{"../missing"}, []string{"scan", "../missing"}},
		{[]string{`..\missing`}, []string{"scan", `..\missing`}},
		{[]string{"-"}, []string{"scan", "-"}},
		{[]string{"--ci"}, []string{"scan", "--ci"}},
		{[]string{"--", "--help"}, []string{"scan", "--", "--help"}},
		{[]string{"--help"}, []string{"--help"}},
		{[]string{"--version"}, []string{"--version"}},
		{[]string{"scna"}, []string{"scna"}},
		{[]string{"https://example.invalid"}, []string{"https://example.invalid"}},
	} {
		if got := normalizeScanArgs(tc.args); !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%v routed to %v, want %v", tc.args, got, tc.want)
		}
	}
	for _, command := range commands {
		args := []string{command.name, "--help"}
		if got := normalizeScanArgs(args); !reflect.DeepEqual(got, args) {
			t.Fatalf("explicit command %s routed to scan", command.name)
		}
	}
}

func TestReleasedCIGateDefaultsAndOverrides(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--ci"}, "high"},
		{[]string{"--ci", "--fail-on=critical"}, "critical"},
		{[]string{"--fail-on=low", "--ci"}, "low"},
		{[]string{"--ci=false"}, ""},
		{[]string{"--ci", "--ci=false"}, ""},
		{[]string{"--ci=false", "--ci"}, "high"},
	} {
		c, _, err := parseCommand("scan", tc.args)
		if err != nil || c.failOn != tc.want || c.verify || c.mlEmbed || c.ocrEnabled {
			t.Fatalf("%v: CI policy changed: %+v err=%v", tc.args, c, err)
		}
		if code := gate([]model.Finding{{Type: "source_error"}}, c.failOn, false); code != 2 {
			t.Fatal("CI or its disablement weakened incompleteness policy")
		}
	}
	if !strings.Contains(commandFlagHelp("scan"), "--ci") {
		t.Fatal("CI flag missing from generated help")
	}
	for _, command := range []string{"serve", "guard", "mcp", "index", "doctor", "version"} {
		if _, _, err := parseCommand(command, []string{"--ci"}); err == nil {
			t.Fatalf("%s accepted scan CI policy", command)
		}
	}
}

func TestCIPolicyOverridesConfigWithoutChangingExplicitSeverity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operator.yaml")
	if err := os.WriteFile(path, []byte("output:\n  fail_on: low\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "low"},
		{[]string{"--ci"}, "high"},
		{[]string{"--ci=false"}, "low"},
		{[]string{"--ci", "--fail-on=critical"}, "critical"},
		{[]string{"--fail-on=medium", "--ci"}, "medium"},
	} {
		c, _, err := parseCommand("scan", append([]string{"--config", path}, tc.args...))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfig(&c); err != nil || c.failOn != tc.want {
			t.Fatalf("%v: fail_on=%q want %q err=%v", tc.args, c.failOn, tc.want, err)
		}
	}
}
