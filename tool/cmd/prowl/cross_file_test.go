package main

import (
	"strings"
	"testing"
)

func TestCrossFileFlagsRequireExplicitVerificationAndSupportedInput(t *testing.T) {
	for _, args := range [][]string{{"--cross-file"}, {"--cross-file", "--verify=false"}, {"--cross-file", "--verify", "--history"}, {"--cross-file", "--verify", "--staged"}, {"--cross-file", "--verify", "--since=HEAD"}, {"--cross-file", "--verify", "--stdin-name=prod.json"}} {
		if _, _, err := parseCommand("scan", args); err == nil || !strings.Contains(err.Error(), "--cross-file") {
			t.Fatal("unsafe cross-file flags accepted", args, err)
		}
	}
	for _, args := range [][]string{{"--cross-file", "--verify"}, {"--cross-file", "--verify-all"}, {"--cross-file", "--verified-only"}, {"--cross-file=false"}} {
		if _, _, err := parseCommand("scan", args); err != nil {
			t.Fatal("valid cross-file flags rejected", args, err)
		}
	}
	for _, command := range []string{"repo", "org", "image", "mobile", "bucket", "domain", "cicd", "agents", "serve", "mcp", "compare"} {
		if _, _, err := parseCommand(command, []string{"--cross-file", "--verify"}); err == nil {
			t.Fatal("unsupported command accepted cross-file acquisition", command)
		}
	}
	c, _, err := parseCommand("scan", []string{"--cross-file", "--verify"})
	if err != nil {
		t.Fatal(err)
	}
	if err := stdinModeError(c, []string{"-"}); err == nil {
		t.Fatal("stdin accepted as component acquisition")
	}
	if err := stdinModeError(c, []string{"configs"}); err != nil {
		t.Fatal(err)
	}
}
