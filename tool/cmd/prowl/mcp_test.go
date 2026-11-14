package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMCPRunResultPreservesIncompleteReports(t *testing.T) {
	// Obtain a real ExitError without relying on shell-specific exit syntax.
	exitCmd := exec.Command("git", "--prowl-invalid-option")
	exitErr := exitCmd.Run()
	var processErr *exec.ExitError
	if !errors.As(exitErr, &processErr) || processErr.ExitCode() <= 1 {
		t.Fatalf("expected a failed process, got %v", exitErr)
	}
	dir := t.TempDir()
	left, right := filepath.Join(dir, "left"), filepath.Join(dir, "right")
	if err := os.WriteFile(left, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(right, []byte("different"), 0o600); err != nil {
		t.Fatal(err)
	}
	findingErr := exec.Command("git", "diff", "--no-index", "--", left, right).Run()
	if !errors.As(findingErr, &processErr) || processErr.ExitCode() != 1 {
		t.Fatalf("expected findings exit status, got %v", findingErr)
	}
	for _, tc := range []struct {
		name      string
		out       string
		err       error
		wantError bool
	}{
		{"clean", `{"findings":[],"truncated":false}`, nil, false},
		{"findings", `{"findings":[{"type":"aws-access-key-id"}]}`, nil, false},
		{"findings exit status", `{"findings":[{"type":"aws-access-key-id"}]}`, findingErr, false},
		{"empty findings with exit status", `{"findings":[]}`, findingErr, true},
		{"partial", `{"findings":[{"type":"source_error"}],"truncated":true}`, nil, true},
		{"process failure with partial JSON", `{"findings":[{"type":"source_error"}]}`, exitErr, true},
		{"transport failure with JSON", `{"findings":[]}`, errors.New("interrupted"), true},
		{"malformed JSON", `{"findings":`, nil, true},
		{"missing findings", `{"truncated":false}`, nil, true},
		{"null findings", `{"findings":null}`, nil, true},
		{"empty output", "", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text, isError := mcpRunResult(tc.out, tc.err)
			if isError != tc.wantError || text == "" {
				t.Fatalf("result=(%q, %v), want isError=%v", text, isError, tc.wantError)
			}
			if json.Valid([]byte(tc.out)) && strings.Contains(tc.out, `"findings":[`) && text != tc.out {
				t.Fatalf("partial report changed: %q", text)
			}
		})
	}
}

func TestMCPArgv(t *testing.T) {
	argv, err := mcpArgv("prowl_scan", map[string]any{
		"path": "/x", "verify": true, "ml": true, "ocr": true,
	})
	if err != nil || strings.Join(argv, " ") != "scan /x --verify --ml --ocr --format json" {
		t.Errorf("scan argv = %v, err=%v", argv, err)
	}
	// domain MUST refuse without an authorized attestation
	if _, err := mcpArgv("prowl_domain", map[string]any{"target": "x", "authorized": false}); err == nil {
		t.Error("domain without authorized must error")
	}
	argv, err = mcpArgv("prowl_domain", map[string]any{"target": "x", "authorized": true, "recon": true})
	if err != nil || strings.Join(argv, " ") != "domain x --authorized --recon --format json" {
		t.Errorf("domain argv = %v, err=%v", argv, err)
	}
	if _, err := mcpArgv("prowl_scan", map[string]any{}); err == nil {
		t.Error("missing path must error")
	}
	// a dash-led positional would be reparsed as a prowl flag (e.g. --show-secrets) — must be rejected
	if _, err := mcpArgv("prowl_scan", map[string]any{"path": "--show-secrets"}); err == nil {
		t.Error("dash-led path must error")
	}
	if _, err := mcpArgv("prowl_domain", map[string]any{"target": "-rf", "authorized": true}); err == nil {
		t.Error("dash-led target must error")
	}
	if _, err := mcpArgv("nope", map[string]any{}); err == nil {
		t.Error("unknown tool must error")
	}
}

func TestMCPArgvRepoOCR(t *testing.T) {
	argv, err := mcpArgv("prowl_repo", map[string]any{"url": "https://example.com/acme/repo.git", "ocr": true})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(argv, " "); got != "repo https://example.com/acme/repo.git --ocr --format json" {
		t.Fatalf("argv = %q", got)
	}
}

func TestMCPArgvCICD(t *testing.T) {
	argv, err := mcpArgv("prowl_cicd", map[string]any{
		"target": "github:acme/app", "verify": true, "ml": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(argv, " ")
	if got != "cicd github:acme/app --verify --ml --format json" {
		t.Fatalf("argv = %q", got)
	}
	if _, err := mcpArgv("prowl_cicd", map[string]any{}); err == nil {
		t.Fatal("missing CI target accepted")
	}
}
