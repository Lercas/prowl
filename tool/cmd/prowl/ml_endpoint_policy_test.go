package main

import (
	"os"
	"strings"
	"testing"
)

func TestMLRemoteEndpointRequiresExplicitHTTPSBeforeArtifacts(t *testing.T) {
	t.Setenv("PROWL_HOME", t.TempDir())
	t.Chdir(t.TempDir())
	for _, flags := range [][]string{
		{"--ml-url=https://owned.invalid"},
		{"--ml-url=http://owned.invalid", "--ml-allow-remote"},
		{"--ml-url=http://user:PRIVATE_ENDPOINT@127.0.0.1:8799"},
		{"--ml-url=https://owned.invalid", "--ml-allow-remote", "--ml-allow-remote=false"},
	} {
		_, _, err := parseCommand("scan", append(flags, "--index=unopened-owned-index", "--output=unopened-owned-report"))
		if err == nil || strings.Contains(err.Error(), "PRIVATE_ENDPOINT") {
			t.Fatal("unsafe endpoint accepted or disclosed", err)
		}
	}
	for _, path := range []string{"unopened-owned-index", "unopened-owned-report"} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("endpoint validation created an artifact", path, err)
		}
	}
	c, _, err := parseCommand("scan", []string{"--ml-url=https://owned.invalid", "--ml-allow-remote"})
	if err != nil || !c.mlAllowRemote {
		t.Fatal("explicit endpoint consent missing", err)
	}
	scorer, err := c.mlScorer()
	if err != nil || scorer == nil {
		t.Fatal("selected endpoint could not be constructed", err)
	}
	for _, command := range []string{"compare", "serve", "mcp", "doctor", "lsp", "version"} {
		if _, _, err := parseCommand(command, []string{"--ml-allow-remote"}); err == nil {
			t.Fatalf("%s accepted an unrelated ML transfer flag", command)
		}
	}
	if !strings.Contains(commandFlagHelp("scan"), "--ml-allow-remote") {
		t.Fatal("remote ML flag missing from generated help")
	}
}
