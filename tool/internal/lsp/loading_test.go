package lsp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Lercas/prowl/tool/internal/rules"
)

func TestBuildRejectsIncompleteRulePolicy(t *testing.T) {
	for _, mode := range []string{"templates", "tampered", "custom"} {
		t.Run(mode, func(t *testing.T) {
			t.Chdir(t.TempDir())
			home := t.TempDir()
			t.Setenv("PROWL_HOME", home)
			if mode == "templates" || mode == "tampered" {
				dir := filepath.Join(home, "rules")
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				for name, body := range map[string]string{"good.yaml": "id: good\nmatchers:\n  - type: regex\n    regex: ['OWNED_[A-Z]{8}']\n", "bad.yaml": "id: bad\nmatchers:\n  - type: regex\n    regex: ['[']\n"} {
					if mode == "tampered" && name == "bad.yaml" {
						continue
					}
					if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "tampered" {
					if _, err := rules.GenerateManifest(dir); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(dir, "good.yaml"), []byte("id: good\nmatchers:\n  - type: regex\n    regex: ['NEVER_MATCH_ZZZ']\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				if err := os.WriteFile(".prowl.yaml", []byte("version: 1\ndetectors:\n  custom:\n    - id: bad\n      regex: '['\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if engine, err := build(); err == nil || engine != nil {
				t.Errorf("LSP accepted incomplete %s policy: engine=%v err=%v", mode, engine, err)
			}
		})
	}
}
