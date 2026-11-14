package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type guardShortWriter struct{}

func (guardShortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestGuardUsesHostBlockingExitAndNeverEchoesValues(t *testing.T) {
	for _, protocol := range []string{"raw", "claude", "cursor-prompt", "cursor-tool"} {
		input := "AWS=AKIANAFGYOEYPXU1DSYP"
		switch protocol {
		case "claude":
			input = `{"hook_event_name":"UserPromptSubmit","prompt":"` + input + `"}`
		case "cursor-prompt":
			input = `{"hook_event_name":"beforeSubmitPrompt","prompt":"` + input + `"}`
		case "cursor-tool":
			input = `{"hook_event_name":"beforeShellExecution","command":"` + input + `"}`
		}
		var out, diag bytes.Buffer
		code := runGuard(t.Context(), protocol, 1024, strings.NewReader(input), &out, &diag)
		expected := 2
		if protocol == "raw" {
			expected = 1
		}
		if code != expected || strings.Contains(out.String()+diag.String(), "AKIA") {
			t.Fatal("wrong host exit or value disclosure")
		}
		if protocol == "claude" && out.Len() != 0 {
			t.Fatal("Claude stdout injected unexpected context")
		}
		if protocol != "claude" {
			var response map[string]any
			if err := json.Unmarshal(out.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if protocol == "cursor-prompt" && response["continue"] != false {
				t.Fatal("Cursor prompt not blocked")
			}
			if protocol == "cursor-tool" && response["permission"] != "deny" {
				t.Fatal("Cursor tool not denied")
			}
		}
	}
}

func TestGuardFailsClosedOnLimitsTimeoutAndShortOutput(t *testing.T) {
	var out bytes.Buffer
	if code := runGuard(t.Context(), "raw", 2, strings.NewReader("too long"), &out, &out); code != 2 {
		t.Fatal("oversized stdin allowed")
	}
	if code := runGuard(t.Context(), "raw", 1024, strings.NewReader("hello"), guardShortWriter{}, &out); code != 2 {
		t.Fatal("short response writer allowed")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	if code := runGuard(ctx, "claude", 1024, strings.NewReader("{}"), &out, &out); code != 2 {
		t.Fatal("expired check allowed")
	}
	for _, args := range [][]string{{"--verify"}, {"--ml"}, {"--show-secrets"}, {"--config", "untrusted"}, {"--max-size", "9MB"}, {"--timeout", "0s"}, {"--timeout", "31s"}, {"file"}} {
		if _, _, err := parseCommand("guard", args); err == nil {
			t.Fatal("unsafe or unsupported guard option accepted")
		}
	}
}

func TestAgentHookTemplatesBlockHostFailures(t *testing.T) {
	path := filepath.Join("..", "..", "..", "integrations", "agent-hooks")
	raw, err := os.ReadFile(filepath.Join(path, "claude.settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var claude struct {
		Hooks map[string][]struct {
			Hooks []struct {
				Command   string
				Args      []string
				OnFailure string `json:"onFailure"`
				Timeout   int
			}
		}
	}
	if err := json.Unmarshal(raw, &claude); err != nil {
		t.Fatal(err)
	}
	for _, event := range []string{"UserPromptSubmit", "PreToolUse"} {
		entries := claude.Hooks[event]
		if len(entries) != 1 || len(entries[0].Hooks) != 1 {
			t.Fatal("missing Claude enforcement hook")
		}
		hook := entries[0].Hooks[0]
		if hook.OnFailure != "block" || hook.Timeout <= 3 || strings.Join(hook.Args, " ") != "guard --protocol claude" {
			t.Fatal("Claude host failure can bypass guard")
		}
	}
	raw, err = os.ReadFile(filepath.Join(path, "cursor.hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cursor struct {
		Version int
		Hooks   map[string][]struct {
			Command    string
			FailClosed bool `json:"failClosed"`
			Timeout    int
		}
	}
	if err := json.Unmarshal(raw, &cursor); err != nil {
		t.Fatal(err)
	}
	for _, event := range []string{"beforeSubmitPrompt", "preToolUse", "beforeReadFile"} {
		hooks := cursor.Hooks[event]
		if cursor.Version != 1 || len(hooks) != 1 || !hooks[0].FailClosed || hooks[0].Timeout <= 3 {
			t.Fatal("Cursor host failure can bypass guard")
		}
	}
}
