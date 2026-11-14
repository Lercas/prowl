package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Lercas/prowl/tool/internal/jsonstrict"
)

type scanRunner func(context.Context, []string) (string, error)

func serveMCP(input io.Reader, output io.Writer, stderr ...io.Writer) int {
	target := io.Writer(os.Stderr)
	if len(stderr) > 0 {
		target = stderr[0]
	}
	return serveMCPWithRunnerAndErrors(input, output, target, runSelfContext)
}
func serveMCPWithRunner(input io.Reader, output io.Writer, runner scanRunner) int {
	return serveMCPWithRunnerAndErrors(input, output, os.Stderr, runner)
}
func serveMCPWithRunnerAndErrors(input io.Reader, output, stderr io.Writer, runner scanRunner) int {
	sc := bufio.NewScanner(input)
	sc.Buffer(make([]byte, 0, 64*1024), maxMCPMessageBytes+1)
	w := newMCPWriter(output)
	var writes sync.Mutex
	var active sync.Mutex
	var closeInput sync.Once
	calls := map[string]context.CancelFunc{}
	slots := make(chan struct{}, 2)
	var wg sync.WaitGroup
	reply := func(fn func()) {
		writes.Lock()
		if w.err == nil {
			fn()
			_ = w.flush()
		}
		failed := w.err != nil
		writes.Unlock()
		if failed {
			closeInput.Do(func() {
				if closer, ok := input.(io.Closer); ok {
					_ = closer.Close()
				}
			})
		}
	}
	outputFailed := func() bool { writes.Lock(); defer writes.Unlock(); return w.err != nil }
	inputTooLarge := false
	for !outputFailed() && sc.Scan() {
		if len(sc.Bytes()) > maxMCPMessageBytes {
			inputTooLarge = true
			break
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req mcpRequest
		if jsonstrict.UnmarshalContext(context.Background(), []byte(line), &req) != nil {
			reply(func() { mcpError(w, nil, -32700, "parse error") })
			continue
		}
		if req.JSONRPC != "2.0" {
			reply(func() { mcpError(w, req.ID, -32600, "invalid request") })
			continue
		}
		if len(req.ID) > 0 && string(req.ID) != "null" {
			if _, valid := mcpIDKey(req.ID); !valid {
				reply(func() { mcpError(w, nil, -32600, "invalid request id") })
				continue
			}
		}
		if req.Method == "notifications/cancelled" {
			if len(req.ID) != 0 {
				reply(func() { mcpError(w, req.ID, -32600, "cancellation must be a notification") })
				continue
			}
			var p struct {
				ID json.RawMessage `json:"requestId"`
			}
			if jsonstrict.UnmarshalContext(context.Background(), req.Params, &p) == nil {
				active.Lock()
				key, _ := mcpIDKey(p.ID)
				cancel := calls[key]
				if cancel != nil {
					cancel()
				}
				active.Unlock()
			}
			continue
		}
		if len(req.ID) == 0 || string(req.ID) == "null" {
			continue
		}
		modern, protocolErr := mcpModernRequest(req)
		if protocolErr != nil {
			reply(func() { writeMCP(w, map[string]any{"jsonrpc": "2.0", "id": rawID(req.ID), "error": protocolErr}) })
			continue
		}
		if req.Method != "tools/call" {
			reply(func() { w.modern = modern; handleMCP(line, w); w.modern = false })
			continue
		}
		key, _ := mcpIDKey(req.ID)
		active.Lock()
		_, duplicate := calls[key]
		if duplicate {
			active.Unlock()
			reply(func() { mcpError(w, req.ID, -32600, "duplicate active request id") })
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			active.Unlock()
			reply(func() {
				w.modern = modern
				mcpToolResult(w, req.ID, "Достигнут лимит одновременных сканов", true)
				w.modern = false
			})
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		calls[key] = cancel
		active.Unlock()
		wg.Add(1)
		go func(req mcpRequest, key string) {
			defer wg.Done()
			defer cancel()
			defer func() { <-slots; active.Lock(); delete(calls, key); active.Unlock() }()
			var buffer bytes.Buffer
			bw := newMCPWriter(&buffer)
			bw.modern = modern
			mcpCallContext(ctx, bw, req, runner)
			_ = bw.flush()
			active.Lock()
			if !modern || ctx.Err() != context.Canceled {
				reply(func() { _, _ = w.Write(buffer.Bytes()) })
			}
			active.Unlock()
		}(req, key)
	}
	// EOF ends the session, so outstanding work cannot outlive its client.
	active.Lock()
	for _, cancel := range calls {
		cancel()
	}
	active.Unlock()
	wg.Wait()
	if outputFailed() {
		fmt.Fprintln(stderr, errMCPOutput)
		return 2
	}
	if inputTooLarge {
		fmt.Fprintln(stderr, "mcp: превышен лимит входного сообщения")
		return 2
	}
	if sc.Err() != nil {
		fmt.Fprintln(stderr, "mcp: не удалось прочитать входной поток")
		return 2
	}
	return 0
}

// Modern requests carry their own version and capabilities; requests without
// the modern envelope retain the existing initialization-based behavior.
func mcpModernRequest(req mcpRequest) (bool, map[string]any) {
	var p struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	_ = jsonstrict.UnmarshalContext(context.Background(), req.Params, &p)
	versionRaw, hasVersion := p.Meta["io.modelcontextprotocol/protocolVersion"]
	modern := hasVersion || req.Method == "server/discover"
	if !modern {
		return false, nil
	}
	var requested string
	if !hasVersion || json.Unmarshal(versionRaw, &requested) != nil || requested == "" {
		return true, map[string]any{"code": -32602, "message": "missing or invalid protocol version"}
	}
	if requested != mcpModernVersion {
		return true, map[string]any{"code": -32022, "message": "Unsupported protocol version", "data": map[string]any{"requested": requested, "supported": []string{mcpModernVersion, mcpProtocolVersion, "2025-03-26", "2024-11-05"}}}
	}
	var capabilities map[string]json.RawMessage
	if json.Unmarshal(p.Meta["io.modelcontextprotocol/clientCapabilities"], &capabilities) != nil || capabilities == nil {
		return true, map[string]any{"code": -32602, "message": "missing or invalid client capabilities"}
	}
	return true, nil
}

func mcpIDKey(raw json.RawMessage) (string, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return "s:" + s, true
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil && n.String() != "" && !strings.ContainsAny(n.String(), ".eE") {
		return "n:" + n.String(), true
	}
	return "", false
}
