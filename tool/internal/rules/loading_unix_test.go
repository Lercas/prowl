//go:build !windows

package rules

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestTemplateFIFOIsRejectedWithoutWaitingForWriter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pipe.yaml")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTemplateFile(path); err == nil {
		t.Fatal("FIFO template accepted")
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("FIFO in rule directory accepted")
	}
	if issues := ValidateDir(dir); len(issues) == 0 || issues[0].Level != "error" {
		t.Fatalf("validator omitted FIFO: %+v", issues)
	}
}

func TestRuleManifestFIFOIsRejectedWithoutWriter(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "owned.yaml", awsTemplate)
	path := filepath.Join(dir, IntegrityManifestName)
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- CheckIntegrity(dir, IntegrityPolicy{}) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO checksum manifest accepted")
		}
	case <-time.After(3 * time.Second):
		// Release a regressed blocking reader without leaving a goroutine stuck in the test process.
		if f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
		t.Fatal("manifest read waited for a FIFO writer")
	}
	requireRuleLoadRefusal(t, dir)
}

func TestUnreadableNestedRuleDirectoryIsReported(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses permissions")
	}
	dir := t.TempDir()
	blocked := filepath.Join(dir, "blocked")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(blocked, "rule.yaml"), minimalRule("blocked"))
	if err := os.Chmod(blocked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(blocked, 0o700); err != nil {
			t.Error(err)
		}
	})
	if _, err := Load(dir); err == nil {
		t.Fatal("unreadable rule subtree omitted at runtime")
	}
	if issues := ValidateDir(dir); len(issues) == 0 || issues[0].Level != "error" {
		t.Fatalf("validator omitted unreadable subtree: %+v", issues)
	}
}
