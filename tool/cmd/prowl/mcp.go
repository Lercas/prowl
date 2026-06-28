package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const mcpProtocolVersion = "2024-11-05"

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type mcpTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

func strProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}
func boolProp(desc string) map[string]any {
	return map[string]any{"type": "boolean", "description": desc}
}

func mcpTools() []mcpTool {
	return []mcpTool{
		{Name: "prowl_scan", Description: "Scan a local file or directory for secrets. Returns the JSON findings envelope.",
			InputSchema: map[string]any{"type": "object", "required": []string{"path"}, "properties": map[string]any{
				"path": strProp("file or directory to scan"), "verify": boolProp("live-validate found secrets (L3)"),
				"ml": boolProp("apply the ML false-positive filter (L2)"), "show_secrets": boolProp("return full unredacted values (authorized triage)")}}},
		{Name: "prowl_domain", Description: "Scan a domain's public web surface (HTML, JS bundles, source maps) for secrets. Network access.",
			InputSchema: map[string]any{"type": "object", "required": []string{"target", "authorized"}, "properties": map[string]any{
				"target": strProp("domain, e.g. example.com"), "authorized": boolProp("attest the target is in your authorized scope (required)"),
				"recon": boolProp("also enumerate subdomains (crt.sh) + wayback history"), "verify": boolProp("live-validate found secrets")}}},
		{Name: "prowl_mobile", Description: "Unpack and scan an Android APK or iOS IPA (resources, dex/arsc/.so strings) for embedded secrets.",
			InputSchema: map[string]any{"type": "object", "required": []string{"path"}, "properties": map[string]any{
				"path": strProp("path to a .apk or .ipa file"), "ml": boolProp("apply the ML false-positive filter (recommended for binary dumps)")}}},
		{Name: "prowl_repo", Description: "Clone a git repository and scan its working tree and history for secrets.",
			InputSchema: map[string]any{"type": "object", "required": []string{"url"}, "properties": map[string]any{
				"url": strProp("git clone URL"), "verify": boolProp("live-validate found secrets")}}},
	}
}

func cmdMCP(args []string) int {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024) // cap one JSON-RPC line at 16 MiB
	w := bufio.NewWriter(os.Stdout)
	for sc.Scan() {
		if s := strings.TrimSpace(sc.Text()); s != "" {
			handleMCP(s, w)
			w.Flush()
		}
	}
	return 0 // stdin closed by the client
}

func handleMCP(line string, w *bufio.Writer) {
	var req mcpRequest
	if json.Unmarshal([]byte(line), &req) != nil {
		return
	}
	if len(req.ID) == 0 || string(req.ID) == "null" {
		return // JSON-RPC 2.0: a server MUST NOT reply to (or act on) a notification
	}
	switch req.Method {
	case "initialize":
		mcpReply(w, req.ID, map[string]any{"protocolVersion": mcpProtocolVersion,
			"capabilities": map[string]any{"tools": map[string]any{}},
			"serverInfo":   map[string]any{"name": "prowl", "version": version}})
	case "tools/list":
		mcpReply(w, req.ID, map[string]any{"tools": mcpTools()})
	case "tools/call":
		mcpCall(w, req)
	case "ping":
		mcpReply(w, req.ID, map[string]any{})
	default:
		mcpError(w, req.ID, -32601, "method not found: "+req.Method)
	}
}

func mcpCall(w *bufio.Writer, req mcpRequest) {
	var p struct {
		Name string         `json:"name"`
		Args map[string]any `json:"arguments"`
	}
	json.Unmarshal(req.Params, &p)
	argv, err := mcpArgv(p.Name, p.Args)
	if err != nil {
		mcpToolResult(w, req.ID, err.Error(), true)
		return
	}
	out, runErr := runSelf(argv)
	if strings.TrimSpace(out) == "" && runErr != nil {
		mcpToolResult(w, req.ID, "scan failed: "+runErr.Error(), true)
		return
	}
	mcpToolResult(w, req.ID, out, false)
}

// notDashLed rejects a positional value that starts with '-', which the prowl parser would otherwise
// read as a flag (e.g. a target literally named "--show-secrets" or "--rules-dir").
func notDashLed(kind, v string) error {
	if strings.HasPrefix(v, "-") {
		return fmt.Errorf("%s %q must not start with '-'", kind, v)
	}
	return nil
}

// mcpArgv maps a tool call to the prowl CLI argv it shells out to (reusing the tested CLI behavior).
func mcpArgv(name string, a map[string]any) ([]string, error) {
	s := func(k string) string { v, _ := a[k].(string); return strings.TrimSpace(v) }
	b := func(k string) bool { v, _ := a[k].(bool); return v }
	switch name {
	case "prowl_scan":
		if s("path") == "" {
			return nil, fmt.Errorf("path is required")
		}
		if err := notDashLed("path", s("path")); err != nil {
			return nil, err
		}
		argv := []string{"scan", s("path")}
		if b("verify") {
			argv = append(argv, "--verify")
		}
		if b("ml") {
			argv = append(argv, "--ml")
		}
		if b("show_secrets") {
			argv = append(argv, "--show-secrets")
		}
		return append(argv, "--format", "json"), nil
	case "prowl_domain":
		if s("target") == "" {
			return nil, fmt.Errorf("target is required")
		}
		if !b("authorized") {
			return nil, fmt.Errorf("refusing to scan %q: set authorized=true to attest it is in your scope", s("target"))
		}
		if err := notDashLed("target", s("target")); err != nil {
			return nil, err
		}
		argv := []string{"domain", s("target"), "--authorized"}
		if b("recon") {
			argv = append(argv, "--recon")
		}
		if b("verify") {
			argv = append(argv, "--verify")
		}
		return append(argv, "--format", "json"), nil
	case "prowl_mobile":
		if s("path") == "" {
			return nil, fmt.Errorf("path is required")
		}
		if err := notDashLed("path", s("path")); err != nil {
			return nil, err
		}
		argv := []string{"mobile", s("path")}
		if b("ml") {
			argv = append(argv, "--ml")
		}
		return append(argv, "--format", "json"), nil
	case "prowl_repo":
		if s("url") == "" {
			return nil, fmt.Errorf("url is required")
		}
		if err := notDashLed("url", s("url")); err != nil {
			return nil, err
		}
		argv := []string{"repo", s("url")}
		if b("verify") {
			argv = append(argv, "--verify")
		}
		return append(argv, "--format", "json"), nil
	}
	return nil, fmt.Errorf("unknown tool: %s", name)
}

// runSelf invokes this same binary with argv, returning its stdout (the JSON findings). A non-zero exit
// from a findings-found run is normal, so the output is returned regardless; err carries a real failure.
func runSelf(argv []string) (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, self, argv...)
	out, err := cmd.Output()
	return string(out), err
}

func mcpReply(w *bufio.Writer, id json.RawMessage, result any) {
	writeMCP(w, map[string]any{"jsonrpc": "2.0", "id": rawID(id), "result": result})
}

func mcpError(w *bufio.Writer, id json.RawMessage, code int, msg string) {
	writeMCP(w, map[string]any{"jsonrpc": "2.0", "id": rawID(id), "error": map[string]any{"code": code, "message": msg}})
}

func mcpToolResult(w *bufio.Writer, id json.RawMessage, text string, isError bool) {
	mcpReply(w, id, map[string]any{"content": []any{map[string]any{"type": "text", "text": text}}, "isError": isError})
}

func rawID(id json.RawMessage) any {
	if len(id) == 0 {
		return nil
	}
	return id
}

func writeMCP(w *bufio.Writer, msg map[string]any) {
	b, err := json.Marshal(msg)
	if err != nil {
		return
	}
	w.Write(b)
	w.WriteByte('\n')
}
