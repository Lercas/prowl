package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/targetlist"
)

func TestInvalidInventoryRefusedBeforeAudit(t *testing.T) {
	dir := t.TempDir()
	path, out := filepath.Join(dir, "targets.txt"), filepath.Join(dir, "report.json")
	if err := os.WriteFile(path, []byte("127.0.0.1\n"+strings.Repeat("x", targetlist.MaxLine+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, []byte("previous owned report"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"--authorized", "--targets", path, "--output", out}); code != 2 {
		t.Fatalf("invalid inventory returned %d", code)
	}
	raw, err := os.ReadFile(out)
	if err != nil || string(raw) != "previous owned report" {
		t.Fatal("failed inventory changed report")
	}
}

func TestOutputRefusesLeafLink(t *testing.T) {
	dir := t.TempDir()
	outside, out := filepath.Join(dir, "outside"), filepath.Join(dir, "output")
	if err := os.WriteFile(outside, []byte("owned sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, out); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := writeReportOutput(out, []byte("report")); err == nil {
		t.Fatal("output link accepted")
	}
	raw, err := os.ReadFile(outside)
	if err != nil || string(raw) != "owned sentinel" {
		t.Fatal("linked file was overwritten")
	}
}

func TestOutputPreservesHardlinkAndRestrictsMode(t *testing.T) {
	dir := t.TempDir()
	outside, out := filepath.Join(dir, "outside"), filepath.Join(dir, "output")
	if err := os.WriteFile(outside, []byte("owned sentinel"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, out); err != nil {
		t.Skipf("hardlinks unavailable: %v", err)
	}
	if err := writeReportOutput(out, []byte("report")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(outside)
	if err != nil || string(raw) != "owned sentinel" {
		t.Fatal("hardlink was overwritten")
	}
	info, err := os.Stat(out)
	if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Fatalf("report mode: %v %v", info, err)
	}
}

func TestOfflineAuditReportsClosedStdoutError(t *testing.T) {
	closed, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = closed
	defer func() { os.Stdout = previous }()
	// Unknown explicit providers select none; active probing is disabled. No network is used.
	if code := run([]string{"--authorized", "--target", "127.0.0.1", "--active=false", "--passive=true", "--provider=owned-offline"}); code != 2 {
		t.Fatalf("closed stdout returned %d", code)
	}
}
