package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/verify"
)

func TestInvocationOperationalSettingsDoNotChangeLegacyDefaults(t *testing.T) {
	t.Setenv("PROWL_HOME", t.TempDir())
	defer verify.SetConcurrency(verify.DefaultConcurrency)
	verify.SetConcurrency(7)
	dir := t.TempDir()
	selectedPath := filepath.Join(dir, "selected.yaml")
	defaultPath := filepath.Join(dir, "default.yaml")
	if err := os.WriteFile(selectedPath, []byte("limits:\n  org_max_pages: 2\n  clone_timeout: 125ms\nperformance:\n  verify_concurrency: 3\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(defaultPath, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	selected := commonFlags{config: selectedPath, verify: true, bundled: true}
	defaults := commonFlags{config: defaultPath, verify: true, bundled: true}
	if _, err := loadConfig(&selected); err != nil {
		t.Fatal(err)
	}
	first, err := loadVerifySet(selected)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(&defaults); err != nil {
		t.Fatal(err)
	}
	second, err := loadVerifySet(defaults)
	if err != nil {
		t.Fatal(err)
	}
	if first.Concurrency() != 3 || second.Concurrency() != 8 || verify.New(time.Second).Concurrency() != 7 {
		t.Fatal("invocations inherited or changed process defaults")
	}
	if selected.cloneTimeout != 125*time.Millisecond || selected.orgMaxPages != 2 || defaults.cloneTimeout != 0 || defaults.orgMaxPages != 0 {
		t.Fatal("source/forge settings inherited a previous configuration")
	}
	selected.config = defaultPath
	if _, err := loadConfig(&selected); err != nil {
		t.Fatal(err)
	}
	third, err := loadVerifySet(selected)
	if err != nil || third.Concurrency() != 8 || selected.cloneTimeout != 0 || selected.orgMaxPages != 0 {
		t.Fatal("reloading empty config retained operational overrides", err)
	}
	if first.Concurrency() != 3 {
		t.Fatal("later configuration changed an existing verifier Set")
	}
}
