package main

import (
	"os/exec"
	"strings"
	"testing"
)

func TestComparisonFormatCompletionInShells(t *testing.T) {
	for _, shell := range []string{"bash", "zsh"} {
		executable, err := exec.LookPath(shell)
		if err != nil {
			t.Skipf("%s unavailable", shell)
		}
		for _, command := range []string{"compare", "scan", "index", "diff"} {
			script := bashCompletion() + "\nCOMP_WORDS=(prowl " + command + " --format ''); COMP_CWORD=3; _prowl; printf '%s\\n' \"${COMPREPLY[@]}\"\n"
			if shell == "zsh" {
				script = "compdef() { :; }\ncompadd() { shift; print -l -- \"$@\"; }\n" + zshCompletion() + "\nwords=(prowl " + command + " --format ''); CURRENT=4; _prowl\n"
			}
			out, err := exec.Command(executable, "-c", script).CombinedOutput()
			if err != nil {
				t.Fatalf("%s/%s: %v: %s", shell, command, err, out)
			}
			want := "pretty\njson\n"
			if command == "scan" {
				want += "sarif\ndefectdojo\ndojo\n"
			}
			if strings.TrimSpace(string(out)) != strings.TrimSpace(want) {
				t.Fatalf("%s/%s choices: %q", shell, command, out)
			}
		}
	}
}
