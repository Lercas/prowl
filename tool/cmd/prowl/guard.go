package main

import (
	"context"
	"encoding/json"
	"io"
	"os"

	"github.com/Lercas/prowl/tool/internal/agentguard"
)

func cmdGuard(args []string) int {
	c, _, err := parseCommand("guard", args)
	if err != nil {
		return commandParseError(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	return runGuard(ctx, c.cmd.guardProtocol, c.maxSize, os.Stdin, os.Stdout, os.Stderr)
}

func runGuard(ctx context.Context, protocol string, limit int64, input io.Reader, output, diagnostic io.Writer) int {
	// Stdin belongs to this short-lived hook process. A host that holds it open
	// cannot keep the guard alive past its deadline; the process exits on return.
	type readResult struct {
		data []byte
		err  error
	}
	reads := make(chan readResult, 1)
	go func() { data, err := io.ReadAll(io.LimitReader(input, limit+1)); reads <- readResult{data, err} }()
	result := agentguard.Result{Incomplete: true}
	select {
	case <-ctx.Done():
	case read := <-reads:
		if read.err == nil && int64(len(read.data)) <= limit {
			result = agentguard.Check(ctx, protocol, read.data)
		}
	}
	reason := agentguard.BlockReason
	if result.Incomplete {
		reason = agentguard.ErrorReason
	}
	if protocol == "claude" {
		if result.Allowed {
			return 0
		}
		_, _ = io.WriteString(diagnostic, reason+"\n")
		return 2 // Claude blocks only exit 2, not the ordinary scanner's exit 1.
	}
	var response any
	switch protocol {
	case "cursor-prompt":
		response = struct {
			Continue bool   `json:"continue"`
			Message  string `json:"user_message,omitempty"`
		}{Continue: result.Allowed}
		if !result.Allowed {
			response = struct {
				Continue bool   `json:"continue"`
				Message  string `json:"user_message"`
			}{false, reason}
		}
	case "cursor-tool":
		permission := "allow"
		message := ""
		if !result.Allowed {
			permission = "deny"
			message = reason
		}
		response = struct {
			Permission  string `json:"permission"`
			UserMessage string `json:"user_message,omitempty"`
		}{permission, message}
	default:
		decision := "allow"
		message := ""
		if !result.Allowed {
			decision = "block"
			message = reason
		}
		if result.Incomplete {
			decision = "error"
		}
		response = struct {
			Decision string `json:"decision"`
			Message  string `json:"reason,omitempty"`
		}{decision, message}
	}
	data, err := json.Marshal(response)
	if err != nil {
		return 2
	}
	data = append(data, '\n')
	if n, err := output.Write(data); err != nil || n != len(data) {
		return 2
	}
	if protocol == "cursor-prompt" || protocol == "cursor-tool" {
		if result.Allowed {
			return 0
		}
		return 2
	}
	if result.Incomplete {
		return 2
	}
	if !result.Allowed {
		return 1
	}
	return 0
}
