package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestMCPModernAndLegacyTransport(t *testing.T) {
	in, writer := io.Pipe()
	out, output := io.Pipe()
	done := make(chan int, 1)
	go func() {
		done <- serveMCPWithRunner(in, output, func(context.Context, []string) (string, error) {
			return `{"schema_version":"1.4","complete":true,"count":0,"findings":[]}`, nil
		})
		_ = output.Close()
	}()
	reader := bufio.NewReader(out)
	exchange := func(request string) map[string]any {
		t.Helper()
		if _, err := fmt.Fprintln(writer, request); err != nil {
			t.Fatal(err)
		}
		line, err := reader.ReadBytes('\n')
		if err != nil {
			t.Fatal(err)
		}
		var response map[string]any
		if err := json.Unmarshal(line, &response); err != nil {
			t.Fatal(err)
		}
		return response
	}
	meta := `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}`
	for _, req := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{` + meta + `}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{` + meta + `}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"prowl_scan","arguments":{"path":"."},` + meta + `}}`,
	} {
		response := exchange(req)
		result, ok := response["result"].(map[string]any)
		if !ok || result["resultType"] != "complete" {
			t.Fatalf("modern response: %v", response)
		}
		if result["_meta"] == nil {
			t.Fatalf("missing server identity: %v", response)
		}
		if strings.Contains(req, "server/discover") && result["supportedVersions"] == nil {
			t.Fatalf("missing versions: %v", response)
		}
		if strings.Contains(req, "tools/call") && result["structuredContent"] == nil {
			t.Fatalf("missing scan: %v", response)
		}
	}
	unsupported := exchange(`{"jsonrpc":"2.0","id":4,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2099-01-01","io.modelcontextprotocol/clientCapabilities":{}}}}`)
	if e, ok := unsupported["error"].(map[string]any); !ok || e["code"] != float64(-32022) || e["data"] == nil {
		t.Fatalf("unsupported version: %v", unsupported)
	}
	missing := exchange(`{"jsonrpc":"2.0","id":5,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`)
	if e, ok := missing["error"].(map[string]any); !ok || e["code"] != float64(-32602) {
		t.Fatalf("missing metadata: %v", missing)
	}
	legacy := exchange(`{"jsonrpc":"2.0","id":6,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)
	if result, ok := legacy["result"].(map[string]any); !ok || result["protocolVersion"] != "2025-06-18" || result["resultType"] != nil {
		t.Fatalf("legacy response: %v", legacy)
	}
	_ = writer.Close()
	if status := <-done; status != 0 {
		t.Fatal(status)
	}
	_ = out.Close()
}
