package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/config"
	"github.com/Lercas/prowl/tool/internal/model"
)

func TestGroupedHelpCoversSchema(t *testing.T) {
	known := map[string]bool{}
	for _, flag := range cliFlags {
		known[flag.names[0]] = true
	}
	seen := map[string]bool{}
	for _, group := range flagGroups {
		for _, name := range group.names {
			if !known[name] || seen[name] {
				t.Fatalf("help group %q names a missing or repeated flag %s", group.title, name)
			}
			seen[name] = true
		}
	}
	help := commandFlagHelp("scan")
	for _, title := range []string{"Input:", "Output:", "Exit code:", "Noise control:", "Live verification:", "Help:"} {
		if !strings.Contains(help, "\n"+title+"\n") && !strings.HasPrefix(help, title+"\n") {
			t.Fatalf("scan help lost its %q section", title)
		}
	}
	if strings.Index(help, "--staged") > strings.Index(help, "--max-size") {
		t.Fatal("flags inside a section do not follow the section's order")
	}
	// A description never runs into a long label.
	if !strings.Contains(help, "  --format pretty|json|sarif|defectdojo|dojo\n") {
		t.Fatal("a label wider than the column must own its line")
	}
	// A short command keeps one flat list.
	if flat := commandFlagHelp("completion"); !strings.HasPrefix(flat, "Flags:\n") || strings.Contains(flat, "Help:") {
		t.Fatalf("short command help should stay flat:\n%s", flat)
	}
}

func TestUsageListsEveryCommandOnce(t *testing.T) {
	usage := usageText()
	for _, command := range commands {
		if n := strings.Count(usage, "\n  "+command.name+" "); n != 1 {
			t.Fatalf("command %s appears %d times in the usage text", command.name, n)
		}
	}
	if strings.Contains(usage, "\nOther:\n") {
		t.Fatal("a command is missing from commandGroups")
	}
}

func TestCompletionScripts(t *testing.T) {
	for _, command := range commands {
		if strings.ContainsAny(command.summary, "\\\n") {
			t.Fatalf("command %s summary cannot be quoted for every shell", command.name)
		}
	}
	for _, flag := range cliFlags {
		if strings.ContainsAny(flag.description, "\\\n") {
			t.Fatalf("flag %s description cannot be quoted for every shell", flag.names[0])
		}
	}
	for shell, interpreter := range map[string]string{"bash": "bash", "zsh": "zsh", "fish": "fish"} {
		var script bytes.Buffer
		if err := writeCompletion(&script, shell); err != nil {
			t.Fatal(err)
		}
		for _, command := range commands {
			if !strings.Contains(script.String(), command.name) {
				t.Fatalf("%s completion omits command %s", shell, command.name)
			}
		}
		for _, want := range []string{"recon", "fail-on", "sarif", "update"} {
			if !strings.Contains(script.String(), want) {
				t.Fatalf("%s completion omits %s", shell, want)
			}
		}
		path, err := exec.LookPath(interpreter)
		if err != nil {
			continue // syntax is checked wherever the shell is installed
		}
		check := exec.Command(path, "-n")
		check.Stdin = bytes.NewReader(script.Bytes())
		if out, err := check.CombinedOutput(); err != nil {
			t.Fatalf("%s rejects its completion script: %v\n%s", shell, err, out)
		}
	}
	if err := writeCompletion(&bytes.Buffer{}, "powershell"); err == nil {
		t.Fatal("an unsupported shell must be an error, not an empty script")
	}
	if code := runCLI([]string{"completion"}); code != 2 {
		t.Fatalf("completion without a shell returned %d", code)
	}
}

func TestBashCompletionIsCommandScoped(t *testing.T) {
	script := bashCompletion()
	var scan, domain string
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(line, "      scan) ") {
			scan = line
		}
		if strings.HasPrefix(line, "      domain) ") {
			domain = line
		}
	}
	hasFlag := func(line, name string) bool {
		for _, word := range strings.Fields(line) {
			if strings.Trim(word, "'") == name {
				return true
			}
		}
		return false
	}
	if !hasFlag(domain, "--recon") || hasFlag(scan, "--recon") || !hasFlag(scan, "--staged") || !hasFlag(scan, "--reconstruct") {
		t.Fatal("completion offers flags the command would reject")
	}
}

func TestMissingPathSuggestion(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.Mkdir("src", 0o755); err != nil {
		t.Fatal(err)
	}
	if nearestSibling("srcc") != "src" || nearestSibling("unrelated-name") != "" || nearestSibling("src/mian.go") != "" {
		t.Fatal("typo suggestion is wrong")
	}
	// The hint never decides the outcome: a missing root still reaches the scan and fails closed.
	if code := runCLI([]string{"scan", "srcc", "--silence"}); code != 2 {
		t.Fatalf("a scan of a missing path returned %d", code)
	}
}

func TestDisableFoldsTypeSpelling(t *testing.T) {
	findings := []model.Finding{{Type: "aws-access-key-id"}, {Type: "generic_password"}, {Type: "jwt"}}
	kept := applyReportFilters(commonFlags{disable: "aws_access_key_id, Generic-Password"}, findings)
	if len(kept) != 1 || kept[0].Type != "jwt" {
		t.Fatalf("--disable missed a type spelled the other way: %+v", kept)
	}
}

func TestSourceLinesMaskEverySecretOnTheLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.py")
	const text = "x = 1\n\tcfg = {\"password\": \"Tr0ub4dor&3xKq9\", \"key\": \"AKIANAFGYOEYPXU1DSYP\"}\nlast\n"
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	at := func(value string) (int, int) { i := strings.Index(text, value); return i, i + len(value) }
	ps, pe := at("Tr0ub4dor&3xKq9")
	ks, ke := at("AKIANAFGYOEYPXU1DSYP")
	password := model.Finding{Source: "code", Path: path, Line: 2, ByteStart: ps, ByteEnd: pe, Redacted: "Tr0u*******xKq9"}
	key := model.Finding{Source: "code", Path: path, Line: 2, ByteStart: ks, ByteEnd: ke, Redacted: "AKIA********DSYP"}
	line := sourceLines([]model.Finding{key, password})(key)
	if line != `cfg = {"password": "Tr0u*******xKq9", "key": "AKIA********DSYP"}` {
		t.Fatalf("unexpected source line: %q", line)
	}
	for name, f := range map[string]model.Finding{
		"wrong line":     {Source: "code", Path: path, Line: 3, ByteStart: ks, ByteEnd: ke, Redacted: "AKIA********DSYP"},
		"other content":  {Source: "code", Path: path, Line: 2, ByteStart: ks, ByteEnd: ke, Redacted: "ghp_********abcd"},
		"past the end":   {Source: "code", Path: path, Line: 2, ByteStart: ks, ByteEnd: len(text) + 9, Redacted: "AKIA********DSYP"},
		"missing file":   {Source: "code", Path: filepath.Join(dir, "gone.py"), Line: 2, ByteStart: ks, ByteEnd: ke, Redacted: "AKIA********DSYP"},
		"not local code": {Source: "jira", Path: path, Line: 2, ByteStart: ks, ByteEnd: ke, Redacted: "AKIA********DSYP"},
	} {
		if got := sourceLines([]model.Finding{f})(f); got != "" {
			t.Errorf("%s: a line that cannot be verified was shown: %q", name, got)
		}
	}
	// A second secret whose range cannot be verified must hide the whole line, not leak itself.
	stale := password
	stale.Redacted = "Zz9y*******0000"
	if got := sourceLines([]model.Finding{key, stale})(key); got != "" {
		t.Fatalf("line shown with an unmasked neighbour: %q", got)
	}
	long := strings.Repeat("a", 300) + " AKIA********DSYP " + strings.Repeat("b", 300)
	if cut := cutSnippet(long, 301); len([]rune(cut)) > snippetMaxRunes+2 || !strings.Contains(cut, "AKIA********DSYP") || !strings.HasPrefix(cut, "…") {
		t.Fatalf("long line was not cut around the secret: %q", cut)
	}
}

func TestProgressIsOffOutsideATerminal(t *testing.T) {
	items := make(chan model.Item)
	var in <-chan model.Item = items
	if withProgress(t.Context(), commonFlags{format: "pretty"}, in) != in {
		t.Fatal("progress wrapped a scan whose output is not a terminal")
	}
	if humanBytes(1536) != "2 KB" || humanBytes(5<<20) != "5.0 MB" || humanBytes(12) != "12 B" {
		t.Fatal("byte formatting changed")
	}
}

func TestInitNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if code := runCLI([]string{"init"}); code != 0 {
		t.Fatalf("init failed: %d", code)
	}
	if problems, err := config.ValidateFile(".prowl.yaml"); err != nil || len(problems) != 0 {
		t.Fatalf("starter config does not validate: %v %v", problems, err)
	}
	if err := os.WriteFile(".prowl.yaml", []byte("version: 1\n# mine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := runCLI([]string{"init"}); code != 0 {
		t.Fatalf("second init failed: %d", code)
	}
	if data, _ := os.ReadFile(".prowl.yaml"); string(data) != "version: 1\n# mine\n" {
		t.Fatal("init replaced an existing config")
	}
	if err := writeNew(".prowl.yaml", "x", 0o644); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("writeNew must refuse an existing file, got %v", err)
	}
	if code := runCLI([]string{"init", "extra"}); code != 2 {
		t.Fatal("init accepted a positional argument")
	}
}
