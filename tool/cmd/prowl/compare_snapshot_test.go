package main

import (
	"os"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestCompareCountsSuppressedOccurrencesOfRepeatedValue(t *testing.T) {
	first := model.Finding{Type: "owned_token", Path: "production.env", Fingerprint: "same-value", Line: 1, Col: 1, ByteStart: 0, ByteEnd: 8, Redacted: "redacted"}
	second := first
	second.Line, second.ByteStart, second.ByteEnd = 2, 10, 18
	file, err := os.CreateTemp(t.TempDir(), "summary")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	previous := os.Stdout
	os.Stdout = file
	defer func() { os.Stdout = previous }()
	printCompare([]model.Finding{first, second}, []model.Finding{second})
	raw, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "(50%)") || !strings.Contains(text, "production.env:1") || strings.Contains(text, "production.env:2") {
		t.Fatalf("a surviving duplicate hid the suppressed occurrence: %s", text)
	}
}

func TestCompareHelpRejectsUnsupportedSideEffects(t *testing.T) {
	for _, flag := range []string{"--verify", "--verify-all", "--verified-only", "--fail-on-verified", "--verifiers=owned", "--ml-url=http://127.0.0.1:9/score"} {
		if _, _, err := parseCommand("compare", []string{flag}); err == nil {
			t.Fatalf("unsupported comparison option accepted: %s", flag)
		}
	}
}
