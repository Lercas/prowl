package agentguard

import (
	"encoding/json"
	"strings"
	"testing"
)

const ownedKey = "AKIANAFGYOEYPXU1DSYP"

func TestGuardBlocksSecretsAcrossHostProtocolsAndPragmas(t *testing.T) {
	for _, c := range []struct{ protocol, input string }{
		{"raw", "AWS=" + ownedKey + " # prowl:allow"},
		{"claude", `{"hook_event_name":"UserPromptSubmit","prompt":"AWS=` + ownedKey + ` # prowl:allow"}`},
		{"claude", `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"AWS=` + ownedKey + ` # prowl:allow"}}`},
		{"cursor-prompt", `{"hook_event_name":"beforeSubmitPrompt","prompt":"AWS=\u0041KIANAFGYOEYPXU1DSYP","attachments":[]}`},
		{"cursor-tool", `{"hook_event_name":"preToolUse","tool_name":"MCP:owned","tool_input":{"nested":{"token":"` + ownedKey + `"}}}`},
		{"cursor-tool", `{"hook_event_name":"beforeMCPExecution","tool_name":"owned","tool_input":"{\"AWS\":\"` + ownedKey + `\"}"}`},
		{"cursor-tool", `{"hook_event_name":"beforeReadFile","file_path":"/not/read","content":"AWS=` + ownedKey + `"}`},
		{"cursor-tool", `{"hook_event_name":"beforeShellExecution","command":"AWS=` + ownedKey + `"}`},
	} {
		r := Check(t.Context(), c.protocol, []byte(c.input))
		if r.Allowed || r.Incomplete || r.Findings < 1 {
			t.Errorf("%s failed to block a complete detected payload: %+v", c.protocol, r)
		}
	}
}

func TestGuardRejectsAmbiguousUnknownOrUninspectablePayloads(t *testing.T) {
	for _, raw := range []string{
		`{"hook_event_name":"PreToolUse","tool_name":"x","tool_input":null}`,
		`{"hook_event_name":"PreToolUse","tool_name":"x","tool_input":[]}`,
		`{"hook_event_name":"UserPromptSubmit","prompt":"clean","prompt":"secret"}`,
		`{"hook_event_name":"UserPromptSubmit","prompt":"clean","Prompt":"secret"}`,
		`{"hook_event_name":"PreToolUse","tool_name":"x","tool_input":{"a":"safe","a":"secret"}}`,
		`{"hook_event_name":"UserPromptSubmit","prompt":"\ud800"}`,
		`{"hook_event_name":"UserPromptSubmit","prompt":"safe"} {}`,
		`{"hook_event_name":"PostToolUse","prompt":"safe"}`,
		`{"hook_event_name":"UserPromptSubmit"}`,
		`{"hook_event_name":"UserPromptSubmit","prompt":"safe","attachments":[{"file_path":"/unread/owned"}]}`,
	} {
		if r := Check(t.Context(), "claude", []byte(raw)); r.Allowed || !r.Incomplete {
			t.Error("ambiguous payload allowed")
		}
	}
	for _, raw := range [][]byte{nil, []byte{0xff}, []byte{'a', 0}, []byte(strings.Repeat("x", MaxBytes+1))} {
		if r := Check(t.Context(), "raw", raw); r.Allowed || !r.Incomplete {
			t.Error("invalid text accepted")
		}
	}
	var nested any = "safe"
	for i := 0; i < maxDepth+2; i++ {
		nested = []any{nested}
	}
	raw, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "owned", "tool_input": map[string]any{"nested": nested}})
	if r := Check(t.Context(), "claude", raw); r.Allowed || !r.Incomplete {
		t.Fatal("nesting exhaustion allowed")
	}
}

func TestGuardDoesNotReadPayloadPathsOrExecuteCommands(t *testing.T) {
	for _, c := range []struct{ protocol, input string }{
		{"raw", "Summarize the architecture"},
		{"claude", `{"hook_event_name":"UserPromptSubmit","prompt":"hello","transcript_path":"/not/read","cwd":"/not/read"}`},
		{"cursor-tool", `{"hook_event_name":"beforeShellExecution","command":"a-command-that-must-never-execute"}`},
		{"cursor-prompt", `{"hook_event_name":"beforeSubmitPrompt","prompt":"hello","attachments":[]}`},
	} {
		if r := Check(t.Context(), c.protocol, []byte(c.input)); !r.Allowed || r.Incomplete || r.Findings != 0 {
			t.Errorf("safe %s payload denied", c.protocol)
		}
	}
}

func FuzzGuardParts(f *testing.F) {
	for _, seed := range []string{`{"hook_event_name":"UserPromptSubmit","prompt":"hello"}`, `{"hook_event_name":"PreToolUse","tool_name":"owned","tool_input":{"token":"uYPIcjDG4DmisHIv80lPq7Zx"}}`, `{"hook_event_name":"UserPromptSubmit","prompt":"\ud800"}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 32<<10 {
			return
		}
		parts, err := Parts(t.Context(), "claude", []byte(raw))
		if err != nil {
			return
		}
		bytes := 0
		for _, part := range parts {
			bytes += len(part)
		}
		if len(parts) > maxParts || bytes > MaxBytes {
			t.Fatal("accepted payload exceeded expansion budget")
		}
	})
}
