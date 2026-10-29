package lsp

import (
	"os"
	"testing"
)

func TestWorkspaceGitleaksPolicy(t *testing.T) {
	for _, name := range []string{".gitleaks.toml", "gitleaks.toml"} {
		t.Run(name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			t.Setenv("PROWL_HOME", t.TempDir())
			body := "[[rules]]\nid = 'owned-editor-rule'\nregex = 'EDITOR_[A-Z0-9]{8}'\n[allowlist]\nstopwords = ['AABBCCDD']\n"
			if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(".prowl.yaml", []byte("detectors:\n  enable: [owned_editor_rule]\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			e, err := build()
			if err != nil {
				t.Fatal(err)
			}
			if got := scanDiagnostics(e, "file:///owned/prod.env", "EDITOR_Q7K8M9N0"); len(got) != 1 {
				t.Errorf("workspace gitleaks detector ignored: %+v", got)
			}
			if got := scanDiagnostics(e, "file:///owned/prod.env", "EDITOR_AABBCCDD"); len(got) != 0 {
				t.Errorf("imported allowlist ignored: %+v", got)
			}
		})
	}
}

func TestWorkspaceInvalidPolicyDoesNotFallBack(t *testing.T) {
	for _, mode := range []string{"config", "gitleaks", "gitleaks-regex", "gitleaks-precedence"} {
		t.Run(mode, func(t *testing.T) {
			t.Chdir(t.TempDir())
			t.Setenv("PROWL_HOME", t.TempDir())
			name, body := ".prowl.yaml", "detectors: [\n"
			switch mode {
			case "gitleaks":
				name, body = ".gitleaks.toml", "[[rules]\n"
			case "gitleaks-regex":
				name, body = ".gitleaks.toml", "[[rules]]\nid='bad'\nregex='['\n"
			case "gitleaks-precedence":
				name, body = ".gitleaks.toml", "[[rules]\n"
				if err := os.WriteFile("gitleaks.toml", []byte("[[rules]]\nid='good'\nregex='EDITOR_[A-Z]{8}'\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if e, err := build(); err == nil || e != nil {
				t.Errorf("invalid %s policy accepted: engine=%v err=%v", mode, e, err)
			}
		})
	}
}
