package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/logx"
)

func TestBrokenInstalledRulesDoNotLookAbsent(t *testing.T) {
	for _, mode := range []string{"file", "broken-link", "broken-home"} {
		t.Run(mode, func(t *testing.T) {
			t.Chdir(t.TempDir())
			home := t.TempDir()
			t.Setenv("PROWL_HOME", home)
			var err error
			switch mode {
			case "file":
				err = os.WriteFile(filepath.Join(home, "rules"), []byte("not a library"), 0o600)
			case "broken-link":
				err = os.Symlink(filepath.Join(home, "missing"), filepath.Join(home, "rules"))
			case "broken-home":
				path := filepath.Join(home, "broken-home")
				err = os.Symlink(filepath.Join(home, "missing"), path)
				t.Setenv("PROWL_HOME", path)
			}
			if err != nil {
				t.Fatal(err)
			}
			if eng, err := loadEngine(commonFlags{}); err == nil || eng != nil {
				t.Errorf("broken installed %s rules silently ignored: engine=%v err=%v", mode, eng, err)
			}
			if eng, err := loadRulesForQuery(); err == nil || eng != nil {
				t.Errorf("query ignored broken library: engine=%v err=%v", eng, err)
			}
			// Explicit isolation must avoid even inspecting the unselected installed library.
			if eng, err := loadEngine(commonFlags{rulesOnly: true}); err != nil || eng != nil {
				t.Errorf("rules-only inspected unselected library: engine=%v err=%v", eng, err)
			}
			explicit := t.TempDir()
			writeTemplate(t, explicit, "owned-explicit")
			if eng, err := loadEngine(commonFlags{rulesDir: []string{explicit}}); err != nil || eng == nil || eng.Len() != 1 {
				t.Errorf("explicit library did not bypass installed discovery: engine=%v err=%v", eng, err)
			}
			for _, args := range [][]string{{"list"}, {"stats"}, {"show", "aws_access_key_id"}, {"test", "owned"}, {"search", "aws"}} {
				if code := cmdRules(args); code != 2 {
					t.Errorf("query %v ignored discovery failure: exit=%d", args, code)
				}
			}
			if code := cmdRules([]string{"validate"}); code != 1 {
				t.Errorf("validator ignored discovery failure: exit=%d", code)
			}
		})
	}
}

func TestInstalledVerifierFailureCannotFallBackToLocalSet(t *testing.T) {
	t.Chdir(t.TempDir())
	home := t.TempDir()
	t.Setenv("PROWL_HOME", home)
	if err := os.Symlink(filepath.Join(home, "missing"), filepath.Join(home, "verifiers")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir("verifiers", 0o700); err != nil {
		t.Fatal(err)
	}
	body := "id: owned\nmatch: [aws_access_key_id]\nrequests:\n  - url: https://owned.invalid/identity\n    matchers:\n      - type: status\n        status: [200]\n"
	if err := os.WriteFile(filepath.Join("verifiers", "owned.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if set, err := loadVerifySet(commonFlags{verify: true}); err == nil || set != nil {
		t.Errorf("broken installed verifier set fell back: set=%v err=%v", set, err)
	}
	if set, err := loadVerifySet(commonFlags{}); err != nil || set != nil {
		t.Errorf("disabled verification inspected unselected library: set=%v err=%v", set, err)
	}
	for _, sub := range []string{"list", "validate"} {
		want := 2
		if sub == "validate" {
			want = 1
		}
		if code := cmdVerifiers([]string{sub}); code != want {
			t.Errorf("verifiers %s fell back: exit=%d", sub, code)
		}
	}
	if set, err := loadVerifySet(commonFlags{verify: true, verifiers: []string{"verifiers"}}); err != nil || set == nil || set.Count() != 1 {
		t.Errorf("explicit verifier library lost priority: set=%v err=%v", set, err)
	}
}

func TestRuleQueriesCannotFallbackPastBrokenLocalDirectory(t *testing.T) {
	t.Chdir(t.TempDir())
	home := t.TempDir()
	t.Setenv("PROWL_HOME", home)
	writeTemplate(t, filepath.Join(home, "rules"), "owned-installed")
	if err := os.WriteFile("rules", []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if eng, err := loadRulesForQuery(); err == nil || eng != nil {
		t.Errorf("query silently chose installed library instead: engine=%v err=%v", eng, err)
	}
	if eng, err := loadEngine(commonFlags{}); err != nil || eng == nil || eng.Len() != 1 {
		t.Errorf("scanner inspected local query-only candidate: engine=%v err=%v", eng, err)
	}
}

func TestVerifierListCannotReportPartialLibrarySuccess(t *testing.T) {
	if code := cmdVerifiers([]string{"list", partialVerifierSet(t)}); code != 2 {
		t.Errorf("partial verifier list returned success: exit=%d", code)
	}
}

func TestInstalledVerifierDirectoryLinkIsUsable(t *testing.T) {
	t.Chdir(t.TempDir())
	home, target := t.TempDir(), t.TempDir()
	t.Setenv("PROWL_HOME", home)
	body := "id: owned\nmatch: [aws_access_key_id]\nrequests:\n  - url: https://owned.invalid/identity\n    matchers:\n      - type: status\n        status: [200]\n"
	if err := os.WriteFile(filepath.Join(target, "owned.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(home, "verifiers")); err != nil {
		t.Fatal(err)
	}
	if set, err := loadVerifySet(commonFlags{verify: true}); err != nil || set == nil || set.Count() != 1 {
		t.Fatalf("valid linked library failed to load: set=%v err=%v", set, err)
	}
}

func TestServeRejectsVerificationBeforeListen(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("PROWL_HOME", t.TempDir())
	for _, flag := range []string{"--verify", "--verified-only", "--fail-on-verified"} {
		t.Run(flag, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "stderr")
			if err != nil {
				t.Fatal(err)
			}
			original := os.Stderr
			os.Stderr = f
			defer func() { os.Stderr = original; logx.Setup(logx.Options{}); f.Close() }()
			// A bad address guarantees a regressed implementation cannot hang listening. The log
			// assertion distinguishes preflight rejection from trying to bind that address.
			if code := cmdServe([]string{"--addr", "invalid-listen-address", flag, "--no-color"}); code != 2 {
				t.Errorf("unsupported verification returned %d", code)
			}
			b, err := os.ReadFile(f.Name())
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(b), "serve does not support live verification") || strings.Contains(string(b), "listening") {
				t.Errorf("verification was not rejected before listening: %s", b)
			}
		})
	}
}
