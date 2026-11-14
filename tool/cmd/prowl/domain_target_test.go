package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDomainValidatesAllTargetsBeforeScanningPrefix(t *testing.T) {
	dir := t.TempDir()
	path, out := filepath.Join(dir, "targets"), filepath.Join(dir, "report.json")
	if err := os.WriteFile(path, []byte("owned.example\nhttps://user:owned-password@owned.example/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, []byte("previous owned report"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := cmdDomain([]string{"--targets", path, "--authorized", "--output", out}); code != 2 {
		t.Fatalf("invalid suffix returned %d", code)
	}
	raw, err := os.ReadFile(out)
	if err != nil || string(raw) != "previous owned report" {
		t.Fatal("invalid inventory replaced report")
	}
}
