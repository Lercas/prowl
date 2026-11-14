// Package agentguard checks only the payload supplied by a caller. It never
// executes tools, follows paths/URLs, loads project policy, or calls a provider.
package agentguard

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/jsonstrict"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/scan"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

const MaxBytes = 8 << 20
const maxParts = 8192
const maxDepth = 32

const BlockReason = "Possible secret detected. Transfer blocked."
const ErrorReason = "Secret check did not complete. Transfer blocked."

type Result struct {
	Allowed    bool
	Incomplete bool
	Findings   int
}

type envelope struct {
	Event       string  `json:"hook_event_name"`
	Prompt      *string `json:"prompt"`
	ToolName    *string `json:"tool_name"`
	ToolInput   any     `json:"tool_input"`
	Content     *string `json:"content"`
	FilePath    *string `json:"file_path"`
	Command     *string `json:"command"`
	Attachments []any   `json:"attachments"`
}

// Parts validates the host event and extracts decoded strings, including nested
// tool arguments. Metadata such as cwd/transcript_path is never dereferenced.
func Parts(ctx context.Context, protocol string, raw []byte) ([]string, error) {
	if len(raw) == 0 || len(raw) > MaxBytes || !utf8.Valid(raw) || strings.ContainsRune(string(raw), 0) {
		return nil, errors.New("invalid guard input")
	}
	if protocol == "raw" {
		return []string{string(raw)}, nil
	}
	var e envelope
	if err := jsonstrict.UnmarshalContext(ctx, raw, &e); err != nil {
		return nil, errors.New("invalid hook envelope")
	}
	var value any
	switch protocol {
	case "claude":
		switch e.Event {
		case "UserPromptSubmit":
			if len(e.Attachments) > 0 {
				return nil, errors.New("attachment content not supplied")
			}
			if e.Prompt == nil {
				return nil, errors.New("missing prompt")
			}
			value = *e.Prompt
		case "PreToolUse":
			if e.ToolName == nil || *e.ToolName == "" {
				return nil, errors.New("missing tool name")
			}
			if _, ok := e.ToolInput.(map[string]any); !ok {
				return nil, errors.New("invalid tool input")
			}
			value = map[string]any{"tool_name": *e.ToolName, "tool_input": e.ToolInput}
		default:
			return nil, errors.New("unsupported Claude event")
		}
	case "cursor-prompt":
		if e.Event != "beforeSubmitPrompt" || e.Prompt == nil {
			return nil, errors.New("invalid Cursor prompt event")
		}
		if len(e.Attachments) > 0 {
			return nil, errors.New("attachment content not supplied")
		}
		value = *e.Prompt
	case "cursor-tool":
		switch e.Event {
		case "beforeReadFile":
			if e.Content == nil || e.FilePath == nil || *e.FilePath == "" {
				return nil, errors.New("missing file content")
			}
			value = map[string]any{"file_path": *e.FilePath, "content": *e.Content}
		case "beforeShellExecution":
			if e.Command == nil {
				return nil, errors.New("missing command")
			}
			value = *e.Command
		case "preToolUse", "beforeMCPExecution":
			if e.ToolName == nil || *e.ToolName == "" || e.ToolInput == nil {
				return nil, errors.New("missing tool input")
			}
			switch e.ToolInput.(type) {
			case map[string]any, string:
				value = map[string]any{"tool_name": *e.ToolName, "tool_input": e.ToolInput}
			default:
				return nil, errors.New("invalid tool input")
			}
		default:
			return nil, errors.New("unsupported Cursor tool event")
		}
	default:
		return nil, errors.New("unsupported guard protocol")
	}
	var parts []string
	size := 0
	add := func(text string) error {
		size += len(text)
		if len(parts) >= maxParts || size > MaxBytes {
			return errors.New("guard expansion limit")
		}
		parts = append(parts, text)
		return nil
	}
	var walk func(any, int) error
	walk = func(v any, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if depth > maxDepth {
			return errors.New("guard nesting limit")
		}
		switch x := v.(type) {
		case string:
			return add(x)
		case map[string]any:
			if len(x) > maxParts-len(parts) {
				return errors.New("guard expansion limit")
			}
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if err := add(k); err != nil {
					return err
				}
				if text, ok := x[k].(string); ok {
					if err := add(k + " = " + text); err != nil {
						return err
					}
				}
				if err := walk(x[k], depth+1); err != nil {
					return err
				}
			}
		case []any:
			for _, entry := range x {
				if err := walk(entry, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	// Keep the serialized structure too: assignment context is useful for generic
	// candidates while decoded strings expose escaped/split JSON values.
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, errors.New("invalid hook content")
	}
	if err = add(string(encoded)); err != nil {
		return nil, err
	}
	if err = walk(value, 0); err != nil {
		return nil, err
	}
	return parts, nil
}

// Check uses embedded L1 rules without ML suppression or network verification.
// The caller must treat Incomplete as a blocking result, never as clean.
func Check(ctx context.Context, protocol string, raw []byte) Result {
	parts, err := Parts(ctx, protocol, raw)
	if err != nil {
		return Result{Incomplete: true}
	}
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		return Result{Incomplete: true}
	}
	if taxonomy.RequireComplete(tax) != nil {
		return Result{Incomplete: true}
	}
	pipeline := scan.New(scan.Options{Detector: detect.New(tax), Workers: 1, IgnorePragmas: true})
	items := make(chan model.Item, len(parts))
	for _, text := range parts {
		items <- model.Item{Text: text, Source: "code", Path: "hook-input"}
	}
	close(items)
	result := Result{}
	for _, f := range pipeline.Run(ctx, items) {
		if model.IsIncompleteFinding(f) {
			result.Incomplete = true
		} else {
			result.Findings++
		}
	}
	result.Incomplete = result.Incomplete || ctx.Err() != nil
	result.Allowed = !result.Incomplete && result.Findings == 0
	return result
}
