package main

import "testing"

func TestVerifyAllFlagImplicationAndScope(t *testing.T) {
	for _, c := range []struct {
		args        []string
		all, verify bool
	}{
		{[]string{"--verify-all"}, true, true},
		{[]string{"--verify-all=false"}, false, false},
		{[]string{"--verify-all", "--verify-all=false"}, false, false},
		{[]string{"--verify=false", "--verify-all"}, true, true},
	} {
		flags, _, err := parseCommand("scan", c.args)
		if err != nil || flags.verifyAll != c.all || flags.verify != c.verify {
			t.Fatal("verify-all implication or explicit false changed")
		}
	}
	for _, command := range []string{"serve", "mcp", "lsp", "guard", "identity"} {
		if _, _, err := parseCommand(command, []string{"--verify-all"}); err == nil {
			t.Fatal("foreign verification flag was accepted")
		}
	}
}
