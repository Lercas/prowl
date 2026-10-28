package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/Lercas/prowl/tool/internal/checkedio"
	"github.com/Lercas/prowl/tool/internal/model"
)

const mcpProtocolVersion = "2025-06-18"
const mcpModernVersion = "2026-07-28"
const maxMCPMessageBytes = 16 << 20

var errMCPOutput = errors.New("mcp: не удалось записать сообщение")

type mcpWriter struct {
	*bufio.Writer
	err    error
	modern bool
}

func newMCPWriter(output io.Writer) *mcpWriter {
	return &mcpWriter{Writer: bufio.NewWriter(checkedio.NewWriter(output))}
}

func (w *mcpWriter) flush() error {
	if w.err == nil && w.Flush() != nil {
		w.err = errMCPOutput
	}
	return w.err
}

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type mcpTool struct {
	Name         string         `json:"name"`
	Description  string         `json:"description"`
	InputSchema  map[string]any `json:"inputSchema"`
	OutputSchema map[string]any `json:"outputSchema,omitempty"`
}

func strProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}
func boolProp(desc string) map[string]any {
	return map[string]any{"type": "boolean", "description": desc}
}

func mcpTools() []mcpTool {
	result := []mcpTool{
		{Name: "prowl_scan", Description: "Scan a local file or directory for secrets. Returns the JSON findings envelope.",
			InputSchema: map[string]any{"type": "object", "required": []string{"path"}, "properties": map[string]any{
				"path": strProp("file or directory to scan"), "verify": boolProp("live-validate found secrets after detection"),
				"ml":           boolProp("apply the ML false-positive filter (L2)"),
				"ocr":          boolProp("OCR images and image-only PDF pages using the configured local endpoint"),
				"show_secrets": boolProp("return full unredacted values (authorized triage)")}}},
		{Name: "prowl_domain", Description: "Scan a domain's public web surface (HTML, JS bundles, source maps) for secrets. Network access.",
			InputSchema: map[string]any{"type": "object", "required": []string{"target", "authorized"}, "properties": map[string]any{
				"target": strProp("domain, e.g. example.com"), "authorized": boolProp("attest the target is in your authorized scope (required)"),
				"recon": boolProp("also enumerate subdomains (crt.sh) + wayback history"), "verify": boolProp("live-validate found secrets")}}},
		{Name: "prowl_mobile", Description: "Unpack and scan an Android APK or iOS IPA (resources, dex/arsc/.so strings) for embedded secrets.",
			InputSchema: map[string]any{"type": "object", "required": []string{"path"}, "properties": map[string]any{
				"path": strProp("path to a .apk or .ipa file"), "ml": boolProp("apply the ML false-positive filter (recommended for binary dumps)")}}},
		{Name: "prowl_repo", Description: "Clone a git repository and scan its working tree and history for secrets.",
			InputSchema: map[string]any{"type": "object", "required": []string{"url"}, "properties": map[string]any{
				"url": strProp("git clone URL"), "verify": boolProp("live-validate found secrets"),
				"ocr": boolProp("OCR images and image-only PDF pages using the configured local endpoint")}}},
		{Name: "prowl_cicd", Description: "Scan recent GitHub Actions or GitLab CI logs and artifacts. Uses GITHUB_TOKEN/GITLAB_TOKEN from the server environment.",
			InputSchema: map[string]any{"type": "object", "required": []string{"target"}, "properties": map[string]any{
				"target": strProp("github:owner/repo or gitlab:group/project"),
				"verify": boolProp("live-validate found secrets"), "ml": boolProp("apply the ML false-positive filter (L2)")}}},
	}
	for i := range result {
		result[i].InputSchema["additionalProperties"] = false
		props := result[i].InputSchema["properties"].(map[string]any)
		props["strict"] = boolProp("ошибка при неполном скане")
		props["bundled"] = boolProp("использовать встроенные rules/verifiers релиза, сохранив текущий identity key")
		props["reconstruct"] = boolProp("статическое восстановление JS/TS")
		props["semantic"] = boolProp("обнаружение кандидатов локальной моделью")
		if _, supportsVerify := props["verify"]; supportsVerify {
			props["verified_only"] = boolProp("проверить секреты у провайдеров и оставить только подтверждённые находки")
		}
		result[i].OutputSchema = map[string]any{"type": "object", "required": []string{"findings", "complete", "schema_version"}, "properties": map[string]any{"findings": map[string]any{"type": "array", "items": map[string]any{"type": "object"}}, "complete": map[string]any{"type": "boolean"}, "schema_version": map[string]any{"type": "string"}}}
	}
	return result

}

func cmdMCP(args []string) int {
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "MCP не принимает scan flags при startup; передайте bundled/strict/ml/verify в аргументах tool call")
		return 2
	}
	return serveMCP(os.Stdin, os.Stdout)
}

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
		if json.Unmarshal([]byte(line), &req) != nil {
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
			if json.Unmarshal(req.Params, &p) == nil {
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
	_ = json.Unmarshal(req.Params, &p)
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

func handleMCP(line string, w *mcpWriter) {
	var req mcpRequest
	if json.Unmarshal([]byte(line), &req) != nil {
		return
	}
	if len(req.ID) == 0 || string(req.ID) == "null" {
		return // JSON-RPC 2.0: a server MUST NOT reply to (or act on) a notification
	}
	switch req.Method {
	case "server/discover":
		mcpReply(w, req.ID, map[string]any{"supportedVersions": []string{mcpModernVersion, mcpProtocolVersion, "2025-03-26", "2024-11-05"}, "capabilities": map[string]any{"tools": map[string]any{}}})
	case "initialize":
		protocol := mcpProtocolVersion
		var p struct {
			Protocol string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		if p.Protocol == "2024-11-05" || p.Protocol == "2025-03-26" {
			protocol = p.Protocol
		}
		mcpReply(w, req.ID, map[string]any{"protocolVersion": protocol,
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

func mcpCall(w *mcpWriter, req mcpRequest) { mcpCallContext(context.Background(), w, req) }
func mcpCallContext(ctx context.Context, w *mcpWriter, req mcpRequest, runners ...scanRunner) {
	var p struct {
		Name string         `json:"name"`
		Args map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
		mcpError(w, req.ID, -32602, "invalid tool call parameters")
		return
	}
	known := false
	for _, tool := range mcpTools() {
		if tool.Name == p.Name {
			known = true
			break
		}
	}
	if !known {
		mcpError(w, req.ID, -32602, "unknown tool")
		return
	}
	argv, err := mcpArgv(p.Name, p.Args)
	if err != nil {
		mcpToolResult(w, req.ID, err.Error(), true)
		return
	}
	runner := scanRunner(runSelfContext)
	if len(runners) > 0 {
		runner = runners[0]
	}
	out, runErr := runner(ctx, argv)
	if errors.Is(runErr, errMCPOutputLimit) {
		mcpToolResult(w, req.ID, "Отчёт превышает лимит MCP (32 МиБ)", true)
		return
	}
	if strings.TrimSpace(out) == "" && runErr != nil {
		message := "Скан не запустился или завершился без отчёта; проверьте путь, настройки и доступ к источнику"
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			message = "Превышен лимит времени сканирования (5 минут)"
		} else if errors.Is(ctx.Err(), context.Canceled) {
			message = "Сканирование отменено"
		}
		mcpToolResult(w, req.ID, message, true)
		return
	}
	var result model.ScanResult
	if json.Unmarshal([]byte(out), &result) != nil || result.SchemaVersion != "1.4" || result.Findings == nil || result.Count != len(result.Findings) {
		mcpToolResult(w, req.ID, "Недопустимый ответ сканера", true)
		return
	}
	failed := !result.Complete
	if runErr != nil {
		var exit *exec.ExitError
		if !errors.As(runErr, &exit) || exit.ExitCode() != 1 || len(result.Findings) == 0 {
			failed = true
		}
	}
	mcpReply(w, req.ID, map[string]any{"content": []any{map[string]any{"type": "text", "text": out}}, "structuredContent": result, "isError": failed})
}

// mcpRunResult preserves partial JSON while distinguishing findings (exit 1) from scan failures.
func mcpRunResult(out string, runErr error) (string, bool) {
	if strings.TrimSpace(out) == "" {
		if runErr != nil {
			return "scan failed: " + runErr.Error(), true
		}
		return "scan produced no result", true
	}
	var envelope struct {
		Findings  []json.RawMessage `json:"findings"`
		Truncated bool              `json:"truncated"`
	}
	if err := json.Unmarshal([]byte(out), &envelope); err != nil || envelope.Findings == nil {
		return "scan returned an invalid JSON findings envelope", true
	}
	if runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) || exitErr.ExitCode() != 1 || len(envelope.Findings) == 0 {
			return out, true
		}
	}
	return out, envelope.Truncated
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
	var schema map[string]any
	for _, tool := range mcpTools() {
		if tool.Name == name {
			schema = tool.InputSchema
			break
		}
	}
	if schema == nil {
		return nil, fmt.Errorf("unknown tool")
	}
	props := schema["properties"].(map[string]any)
	for k, v := range a {
		prop, ok := props[k]
		if !ok {
			return nil, fmt.Errorf("unknown argument: %s", k)
		}
		typ := prop.(map[string]any)["type"]
		if typ == "boolean" {
			if _, ok := v.(bool); !ok {
				return nil, fmt.Errorf("%s must be boolean", k)
			}
		} else if _, ok := v.(string); !ok {
			return nil, fmt.Errorf("%s must be string", k)
		}
	}
	appendFlags := func(argv []string) []string {
		for _, k := range []string{"strict", "reconstruct", "semantic", "bundled"} {
			if v, _ := a[k].(bool); v {
				argv = append(argv, "--"+k)
			}
		}
		if v, _ := a["verified_only"].(bool); v {
			argv = append(argv, "--verified-only")
		}
		return append(argv, "--format", "json")
	}
	s := func(k string) string { v, _ := a[k].(string); return strings.TrimSpace(v) }
	path := func() string { v, _ := a["path"].(string); return v }
	b := func(k string) bool { v, _ := a[k].(bool); return v }
	switch name {
	case "prowl_scan":
		if path() == "" {
			return nil, fmt.Errorf("path is required")
		}
		if err := notDashLed("path", path()); err != nil {
			return nil, err
		}
		argv := []string{"scan", path()}
		if b("verify") {
			argv = append(argv, "--verify")
		}
		if b("ml") {
			argv = append(argv, "--ml")
		}
		if b("ocr") {
			argv = append(argv, "--ocr")
		}
		if b("show_secrets") {
			argv = append(argv, "--show-secrets")
		}
		return appendFlags(argv), nil
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
		return appendFlags(argv), nil
	case "prowl_mobile":
		if path() == "" {
			return nil, fmt.Errorf("path is required")
		}
		if err := notDashLed("path", path()); err != nil {
			return nil, err
		}
		argv := []string{"mobile", path()}
		if b("ml") {
			argv = append(argv, "--ml")
		}
		return appendFlags(argv), nil
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
		if b("ocr") {
			argv = append(argv, "--ocr")
		}
		return appendFlags(argv), nil
	case "prowl_cicd":
		if s("target") == "" {
			return nil, fmt.Errorf("target is required")
		}
		if err := notDashLed("target", s("target")); err != nil {
			return nil, err
		}
		argv := []string{"cicd", s("target")}
		if b("verify") {
			argv = append(argv, "--verify")
		}
		if b("ml") {
			argv = append(argv, "--ml")
		}
		return appendFlags(argv), nil
	}
	return nil, fmt.Errorf("unknown tool: %s", name)
}

// runSelf invokes this same binary with argv, returning its stdout (the JSON findings). A non-zero exit
// from a findings-found run is normal, so the output is returned regardless; err carries a real failure.
func runSelfContext(parent context.Context, argv []string) (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, self, argv...)
	cmd.WaitDelay = 2 * time.Second
	output := &boundedMCPOutput{cancel: cancel}
	cmd.Stdout = output
	err = cmd.Run()
	if output.exceeded {
		return "", errMCPOutputLimit
	}
	return output.String(), err
}

type boundedMCPOutput struct {
	bytes.Buffer
	cancel   context.CancelFunc
	exceeded bool
}

var errMCPOutputLimit = errors.New("MCP output budget exceeded")

func (w *boundedMCPOutput) Write(p []byte) (int, error) {
	if len(p)+w.Len() > 32<<20 {
		w.exceeded = true
		w.cancel()
		return 0, errMCPOutputLimit
	}
	return w.Buffer.Write(p)
}

func mcpReply(w *mcpWriter, id json.RawMessage, result any) {
	if w.modern {
		if fields, ok := result.(map[string]any); ok {
			fields["resultType"] = "complete"
			fields["_meta"] = map[string]any{"io.modelcontextprotocol/serverInfo": map[string]any{"name": "prowl", "version": version}}
		}
	}
	writeMCP(w, map[string]any{"jsonrpc": "2.0", "id": rawID(id), "result": result})
}

func mcpError(w *mcpWriter, id json.RawMessage, code int, msg string) {
	writeMCP(w, map[string]any{"jsonrpc": "2.0", "id": rawID(id), "error": map[string]any{"code": code, "message": msg}})
}

func mcpToolResult(w *mcpWriter, id json.RawMessage, text string, isError bool) {
	mcpReply(w, id, map[string]any{"content": []any{map[string]any{"type": "text", "text": text}}, "isError": isError})
}

func rawID(id json.RawMessage) any {
	if len(id) == 0 {
		return nil
	}
	return id
}

func writeMCP(w *mcpWriter, msg map[string]any) {
	if w.err != nil {
		return
	}
	b, err := json.Marshal(msg)
	if err != nil {
		w.err = errMCPOutput
		return
	}
	if _, err := w.Write(b); err != nil {
		w.err = errMCPOutput
		return
	}
	if w.WriteByte('\n') != nil {
		w.err = errMCPOutput
	}
}
