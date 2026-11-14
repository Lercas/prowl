package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestReportWriteFailurePreservesPreviousArtifact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte("previous owned report"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeReportFile(path, []model.Finding{{Type: "owned"}}, "unsupported"); err == nil {
		t.Fatal("unknown report format reported success")
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "previous owned report" {
		t.Fatalf("failed report destroyed its previous artifact: %v", err)
	}
}

func TestReportFailureReturnsThroughCallerCleanup(t *testing.T) {
	closed, err := os.CreateTemp(t.TempDir(), "closed-stdout")
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = closed
	defer func() { os.Stdout = previous }()
	cleaned := false
	code := func() int {
		defer func() { cleaned = true }()
		return reportFindings(commonFlags{format: "json"}, nil, time.Second)
	}()
	if code != 2 || !cleaned {
		t.Fatal("report error bypassed cleanup or returned success")
	}
}

func TestReportReplacementPreservesHardlinksAndPrivatePermissions(t *testing.T) {
	dir := t.TempDir()
	outside, path := filepath.Join(dir, "outside"), filepath.Join(dir, "report.json")
	if err := os.WriteFile(outside, []byte("owned sentinel"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(outside, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, path); err != nil {
		t.Skipf("hardlinks unavailable: %v", err)
	}
	if err := writeReportFile(path, nil, "json"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(outside)
	if err != nil || string(raw) != "owned sentinel" {
		t.Fatal("report replacement modified another hardlink")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("report may contain raw secrets but has mode %o", info.Mode().Perm())
	}
}

func offlineArtifactCommands() map[string]func(string) int {
	return map[string]func(string) int{
		"taxonomy": func(path string) int {
			args := []string{"export"}
			if path != "" {
				args = append(args, "--output", path)
			}
			return cmdRules(args)
		},
		"hermes": func(path string) int {
			// No active probe and no recognized provider: this fixture cannot make HTTP requests.
			args := []string{"--authorized", "--active=false", "--passive=true", "--provider=owned-offline", "127.0.0.1"}
			if path != "" {
				args = append(args, "--output", path)
			}
			return cmdHermesAudit(args)
		},
	}
}

func TestArtifactCommandsRefuseDestinationLinks(t *testing.T) {
	for name, command := range offlineArtifactCommands() {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			outside, path := filepath.Join(dir, "outside"), filepath.Join(dir, "output")
			if err := os.WriteFile(outside, []byte("owned sentinel"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, path); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			if code := command(path); code != 2 {
				t.Fatalf("linked output reported success: %d", code)
			}
			raw, err := os.ReadFile(outside)
			if err != nil || string(raw) != "owned sentinel" {
				t.Fatal("artifact command wrote through its destination link")
			}
		})
	}
}

func TestArtifactCommandsSurfaceStdoutWriteFailures(t *testing.T) {
	for name, command := range offlineArtifactCommands() {
		t.Run(name, func(t *testing.T) {
			closed, err := os.CreateTemp(t.TempDir(), "closed-stdout")
			if err != nil {
				t.Fatal(err)
			}
			if err := closed.Close(); err != nil {
				t.Fatal(err)
			}
			previous := os.Stdout
			os.Stdout = closed
			defer func() { os.Stdout = previous }()
			if code := command(""); code != 2 {
				t.Fatalf("failed stdout write reported success: %d", code)
			}
		})
	}
}
