package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOfflineSelftestProfilesAndML(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("PROWL_HOME", t.TempDir())
	for _, profile := range []string{"all", "web", "mobile", "enterprise"} {
		for _, ml := range []bool{false, true} {
			result, err := runSelftest(profile, ml)
			if err != nil || !result.Passed || result.Network || len(result.Cases) < 2 {
				t.Fatalf("profile=%s ml=%v result=%+v err=%v", profile, ml, result, err)
			}
			for _, c := range result.Cases {
				if !c.Passed || !c.Complete {
					t.Fatal("partial fixture passed selftest")
				}
			}
		}
	}
	for _, args := range [][]string{{"--verify"}, {"--ocr"}, {"--semantic"}, {"--profile=unknown"}, {"--ml-model=owned"}} {
		if _, _, err := parseCommand("selftest", args); err == nil {
			t.Fatalf("unsupported selftest flags accepted: %v", args)
		}
	}
}

func TestOfflineSelftestDoesNotHideBrokenSelectedMLModel(t *testing.T) {
	t.Chdir(t.TempDir())
	home := t.TempDir()
	t.Setenv("PROWL_HOME", home)
	if err := os.WriteFile(filepath.Join(home, "model_binary.json"), []byte("not a model"), 0600); err != nil {
		t.Fatal(err)
	}
	if result, err := runSelftest("web", false); err != nil || !result.Passed {
		t.Fatal("disabled ML inspected an unselected model")
	}
	if _, err := runSelftest("web", true); err == nil {
		t.Fatal("ML selftest hid a broken installed model")
	}
}

func TestBundledConflictsAreRejectedByCLI(t *testing.T) {
	for _, args := range [][]string{{"--bundled", "--rules-only"}, {"--bundled", "--rules-dir=owned"}, {"--bundled", "--verifiers=owned"}} {
		if _, _, err := parseCommand("scan", args); err == nil {
			t.Fatalf("conflicting selection accepted: %v", args)
		}
	}
}
