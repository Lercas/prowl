package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleasedFullHelpIncludesCommandsAndNestedScopesWithoutSetup(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	t.Setenv("PROWL_HOME", filepath.Join(root, "home"))
	if err := os.WriteFile(".prowl.yaml", []byte("invalid: [configuration"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := os.CreateTemp(root, "full-help")
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = output
	t.Cleanup(func() { os.Stdout = previous; output.Close() })
	if code := runCLI([]string{"help", "all"}); code != 0 {
		t.Fatalf("full help returned %d", code)
	}
	data, err := os.ReadFile(output.Name())
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, command := range commands {
		if !strings.Contains(text, command.name+" flags:\n") {
			t.Fatalf("full help omitted command %s", command.name)
		}
		for _, child := range commandSubcommands[command.name] {
			if !strings.Contains(text, command.name+" "+child+" flags:\n") {
				t.Fatalf("full help omitted nested scope %s %s", command.name, child)
			}
		}
	}
	for _, flag := range []string{"--ci", "--stdin-name", "--verify-all", "--reconstruct", "--cross-file", "--audit-public", "--audit-firestore-collection"} {
		if !strings.Contains(text, flag) {
			t.Fatalf("full help omitted accepted flag %s", flag)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "home")); !os.IsNotExist(err) {
		t.Fatal("help initialized operator state")
	}
}
