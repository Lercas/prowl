package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const initHelp = `prowl init — set a project up for scanning: a starter .prowl.yaml and a git pre-commit hook

Run it in the project root. Existing files are never changed: a file that is already there is
reported and left alone. The hook is written to the repository's hooks directory (core.hooksPath
is respected) and runs 'prowl scan --staged --ci', which blocks a commit that adds a high or
critical secret.

Examples:
  prowl init
  prowl scan . --write-baseline .prowl-baseline.json   # then accept what is already in the tree`

const initConfig = `# Prowl configuration. Check it with: prowl config validate
version: 1

# Skip paths that contain any of these substrings.
exclude: []
#  - vendor/
#  - node_modules/

detectors:
  # Turn detector types off (see: prowl detectors).
  disable: []
#    - generic_high_entropy

allowlist:
  # Ignore findings whose path matches any of these regular expressions.
  paths: []
#    - 'testdata/'
#    - '_test\.go$'
  # Ignore values that contain any of these words.
  stopwords: []
#    - example
`

const initHook = `#!/bin/sh
# Installed by 'prowl init'. Blocks a commit that adds a high or critical secret.
# Accept one line with a '# prowl:allow' comment; skip the hook once with: git commit --no-verify
exec prowl scan --staged --ci
`

func cmdInit(args []string) int {
	_, rest, err := parseCommand("init", args)
	if err != nil {
		return commandParseError(err)
	}
	if len(rest) > 0 {
		fmt.Fprintln(os.Stderr, "init does not accept positional arguments; run it in the project root")
		return 2
	}
	code := 0
	report := func(path string, err error) {
		switch {
		case err == nil:
			fmt.Printf("  created  %s\n", path)
		case errors.Is(err, fs.ErrExist):
			fmt.Printf("  kept     %s (already exists)\n", path)
		default:
			fmt.Fprintf(os.Stderr, "  failed   %s: %v\n", path, err)
			code = 2
		}
	}
	report(".prowl.yaml", writeNew(".prowl.yaml", initConfig, 0o644))
	hooks, err := gitHooksDir()
	switch {
	case err != nil:
		fmt.Println("  skipped  pre-commit hook (not a git repository)")
	default:
		hook := filepath.Join(hooks, "pre-commit")
		err := os.MkdirAll(hooks, 0o755)
		if err == nil {
			err = writeNew(hook, initHook, 0o755)
		}
		report(hook, err)
		if errors.Is(err, fs.ErrExist) {
			fmt.Println("           to gate commits, add this line to it: prowl scan --staged --ci")
		}
	}
	if code == 0 {
		fmt.Print("\nNext:\n" +
			"  prowl scan .                                         see what is in the tree now\n" +
			"  prowl scan . --write-baseline .prowl-baseline.json   accept it; later scans report only new secrets\n")
	}
	return code
}

// writeNew creates path with the content and never replaces an existing file.
func writeNew(path, content string, mode fs.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		os.Remove(path) // our own partial file, created a moment ago
		return err
	}
	return f.Close()
}

// gitHooksDir asks git where this repository's hooks live, which honors core.hooksPath.
func gitHooksDir() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "git", "rev-parse", "--git-path", "hooks").Output()
	if err != nil {
		return "", err
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		return "", errors.New("git did not report a hooks directory")
	}
	return dir, nil
}
