//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInaccessibleHomeCannotLookAbsent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	t.Chdir(t.TempDir())
	home := t.TempDir()
	t.Setenv("PROWL_HOME", home)
	if err := os.Chmod(home, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(home, 0o700) })
	if eng, err := loadEngine(commonFlags{}); err == nil || eng != nil {
		t.Errorf("inaccessible home accepted: engine=%v err=%v", eng, err)
	}
	if set, err := loadVerifySet(commonFlags{verify: true}); err == nil || set != nil {
		t.Errorf("inaccessible verifier home accepted: set=%v err=%v", set, err)
	}
	// Explicit paths have precedence and must not inspect an unrelated inaccessible home.
	explicit := filepath.Join(t.TempDir(), "rules")
	writeTemplate(t, explicit, "owned")
	if eng, err := loadEngine(commonFlags{rulesDir: []string{explicit}}); err != nil || eng == nil || eng.Len() != 1 {
		t.Errorf("explicit rules blocked by inaccessible home: engine=%v err=%v", eng, err)
	}
}
