package lsp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

const validInitialize = `{"processId":null,"rootUri":null,"capabilities":{}}`

func protocolJSON(method string, id any, params json.RawMessage) []byte {
	msg := map[string]any{"jsonrpc": "2.0", "method": method}
	if id != nil {
		msg["id"] = id
	}
	if params != nil {
		msg["params"] = params
	}
	b, _ := json.Marshal(msg)
	return b
}

func protocolFrames(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var frames []map[string]any
	r := bufio.NewReader(bytes.NewReader(buf.Bytes()))
	for {
		body, err := readMessage(r)
		if err != nil {
			break
		}
		var msg map[string]any
		if json.Unmarshal(body, &msg) != nil {
			t.Fatal("invalid response encoding")
		}
		frames = append(frames, msg)
	}
	buf.Reset()
	return frames
}

func expectProtocolError(t *testing.T, buf *bytes.Buffer, id any, code int) {
	t.Helper()
	frames := protocolFrames(t, buf)
	if len(frames) != 1 || frames[0]["id"] != id || frames[0]["jsonrpc"] != "2.0" {
		t.Fatal("missing error response or incorrect correlation ID")
	}
	err, ok := frames[0]["error"].(map[string]any)
	_, hasResult := frames[0]["result"]
	if !ok || err["code"] != float64(code) || hasResult {
		t.Fatal("incorrect protocol error")
	}
}

func protocolSession(t *testing.T) (*session, *bytes.Buffer) {
	t.Helper()
	buf := new(bytes.Buffer)
	e := newTestEngine(t)
	w := newSafeWriter(bufio.NewWriter(buf))
	d := newDebouncer(e, w, time.Hour)
	t.Cleanup(d.stop)
	return &session{w: w, e: e, d: d}, buf
}

func initializeSession(t *testing.T, s *session, buf *bytes.Buffer) {
	t.Helper()
	s.handle(protocolJSON("initialize", "startup", json.RawMessage(validInitialize)))
	frames := protocolFrames(t, buf)
	if len(frames) != 1 || frames[0]["id"] != "startup" || frames[0]["result"] == nil || s.state != awaitInitialized {
		t.Fatal("initialize did not return capabilities")
	}
	s.handle(protocolJSON("initialized", nil, json.RawMessage(`{}`)))
	if s.state != ready || len(protocolFrames(t, buf)) != 0 {
		t.Fatal("initialized did not enter the ready state silently")
	}
}

func TestProtocolEnvelopeValidation(t *testing.T) {
	cases := []struct {
		name, raw string
		code      int
	}{
		{"syntax", `{"method":`, parseError},
		{"surrogate", `{"jsonrpc":"2.0","method":"\ud800"}`, parseError},
		{"utf8", "{\"jsonrpc\":\"2.0\",\"method\":\"\xff\"}", parseError},
		{"null", `null`, invalidRequest},
		{"array", `[]`, invalidRequest},
		{"scalar", `42`, invalidRequest},
		{"missing-version", `{"method":"exit"}`, invalidRequest},
		{"wrong-version", `{"jsonrpc":"1.0","method":"exit"}`, invalidRequest},
		{"version-number", `{"jsonrpc":2,"method":"exit"}`, invalidRequest},
		{"version-case", `{"JSONRPC":"2.0","method":"exit"}`, invalidRequest},
		{"method-case", `{"jsonrpc":"2.0","Method":"exit"}`, invalidRequest},
		{"missing-method", `{"jsonrpc":"2.0"}`, invalidRequest},
		{"null-method", `{"jsonrpc":"2.0","method":null}`, invalidRequest},
		{"numeric-method", `{"jsonrpc":"2.0","method":7}`, invalidRequest},
		{"duplicate-method", `{"jsonrpc":"2.0","method":"other","method":"exit"}`, invalidRequest},
		{"duplicate-id", `{"jsonrpc":"2.0","method":"shutdown","id":1,"id":2}`, invalidRequest},
		{"escaped-duplicate", `{"jsonrpc":"2.0","method":"other","m\u0065thod":"exit"}`, invalidRequest},
		{"null-id", `{"jsonrpc":"2.0","method":"shutdown","id":null}`, invalidRequest},
		{"bool-id", `{"jsonrpc":"2.0","method":"shutdown","id":false}`, invalidRequest},
		{"object-id", `{"jsonrpc":"2.0","method":"shutdown","id":{}}`, invalidRequest},
		{"fraction-id", `{"jsonrpc":"2.0","method":"shutdown","id":1.5}`, invalidRequest},
		{"overflow-id", `{"jsonrpc":"2.0","method":"shutdown","id":2147483648}`, invalidRequest},
		{"underflow-id", `{"jsonrpc":"2.0","method":"shutdown","id":-2147483649}`, invalidRequest},
		{"result-with-method", `{"jsonrpc":"2.0","method":"exit","result":null}`, invalidRequest},
		{"error-with-method", `{"jsonrpc":"2.0","method":"exit","error":{}}`, invalidRequest},
		{"scalar-params", `{"jsonrpc":"2.0","method":"shutdown","id":7,"params":true}`, invalidParams},
		{"null-params", `{"jsonrpc":"2.0","method":"shutdown","params":null}`, invalidParams},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, code := decodeMessage([]byte(tc.raw))
			if code != tc.code {
				t.Fatalf("code=%d, want %d", code, tc.code)
			}
		})
	}
	for _, id := range []any{"", "Ключ 😀", -2147483648, 0, 2147483647} {
		msg, code := decodeMessage(protocolJSON("owned/method", id, json.RawMessage(`[]`)))
		if code != 0 || msg.method != "owned/method" || msg.id == nil {
			t.Fatal("valid request or opaque ID rejected")
		}
	}
	msg, code := decodeMessage([]byte(`{"jsonrpc":"2.0","method":"owned/event","Method":"exit","extension":true}`))
	if code != 0 || msg.method != "owned/event" || msg.id != nil {
		t.Fatal("case-sensitive method or notification identity was lost")
	}
}

func TestInitializeParameters(t *testing.T) {
	for _, raw := range []string{
		validInitialize,
		`{"processId":0,"rootUri":"file:///Ключ%20😀","capabilities":{"experimental":{"owned":true}},"extension":1}`,
		`{"processId":2147483647,"rootUri":"untitled:owned","capabilities":{}}`,
	} {
		if !initializeParams(json.RawMessage(raw)) {
			t.Fatal("valid initialize parameters rejected")
		}
	}
	for _, raw := range []string{
		`{}`, `null`, `[]`, `{"processId":null,"rootUri":null}`,
		`{"processId":null,"capabilities":{}}`, `{"rootUri":null,"capabilities":{}}`,
		`{"processId":null,"rootUri":null,"capabilities":null}`,
		`{"processId":null,"rootUri":null,"capabilities":[]}`,
		`{"processId":true,"rootUri":null,"capabilities":{}}`,
		`{"processId":2147483648,"rootUri":null,"capabilities":{}}`,
		`{"processId":null,"rootUri":"relative/path","capabilities":{}}`,
		`{"processId":null,"rootUri":"file:///bad%zz","capabilities":{}}`,
		`{"processId":null,"rootUri":42,"capabilities":{}}`,
		`{"processId":null,"rootUri":null,"capabilities":{},"capabilities":{}}`,
	} {
		if initializeParams(json.RawMessage(raw)) {
			t.Fatal("invalid initialize parameters admitted")
		}
	}
}

func TestSessionRequiresInitialization(t *testing.T) {
	s, buf := protocolSession(t)
	const uri = "file:///startup.py"
	s.handle(protocolJSON("textDocument/didOpen", nil, documentParams(uri, genericSecretLine, 1)))
	s.handle(protocolJSON("initialize", nil, json.RawMessage(validInitialize)))
	if len(protocolFrames(t, buf)) != 0 || len(s.d.opened) != 0 || s.state != beforeInitialize {
		t.Fatal("notification initialized the server or scanned before initialization")
	}
	s.handle(protocolJSON("shutdown", 7, nil))
	expectProtocolError(t, buf, float64(7), serverNotInitialized)
	s.handle(protocolJSON("initialize", 8, json.RawMessage(`{}`)))
	expectProtocolError(t, buf, float64(8), invalidParams)
	if s.state != beforeInitialize {
		t.Fatal("invalid initialize consumed the initialization slot")
	}
	s.handle(protocolJSON("initialize", "startup", json.RawMessage(validInitialize)))
	_ = protocolFrames(t, buf)
	s.handle(protocolJSON("textDocument/didOpen", nil, documentParams(uri, genericSecretLine, 1)))
	s.handle(protocolJSON("initialized", nil, json.RawMessage(`[]`)))
	if len(s.d.opened) != 0 || s.state != awaitInitialized || len(protocolFrames(t, buf)) != 0 {
		t.Fatal("document work began before initialized")
	}
	s.handle(protocolJSON("owned/request", 9, nil))
	expectProtocolError(t, buf, float64(9), serverNotInitialized)
	s.handle(protocolJSON("initialized", nil, json.RawMessage(`{}`)))
	s.handle(protocolJSON("textDocument/didOpen", nil, documentParams(uri, genericSecretLine, 1)))
	if count, last := drainPublishes(t, buf); count != 1 || !hasDiag(last) {
		t.Fatal("valid initialization did not permit diagnostics")
	}
}

func TestSessionRequestsCannotInvokeNotificationHandlers(t *testing.T) {
	for _, method := range []string{"textDocument/didOpen", "textDocument/didChange", "textDocument/didSave", "textDocument/didClose", "initialized", "exit", "owned/unknown", "$/owned", ""} {
		t.Run(method, func(t *testing.T) {
			s, buf := protocolSession(t)
			initializeSession(t, s, buf)
			s.handle(protocolJSON("textDocument/didOpen", nil, documentParams("file:///owned.py", genericSecretLine, 1)))
			_ = protocolFrames(t, buf)
			previous := s.d.documents["file:///owned.py"]
			exit, err := s.handle(protocolJSON(method, "correlation", documentParams("file:///owned.py", "", 2)))
			expectProtocolError(t, buf, "correlation", methodNotFound)
			if exit || err != nil || s.state != ready || s.d.documents["file:///owned.py"] != previous {
				t.Fatal("request invoked a notification handler")
			}
		})
	}
}

func TestShutdownSuppressesInFlightPublication(t *testing.T) {
	s, buf := protocolSession(t)
	initializeSession(t, s, buf)
	const uri = "file:///shutdown.py"
	s.handle(protocolJSON("textDocument/didOpen", nil, documentParams(uri, "", 1)))
	_ = protocolFrames(t, buf)
	entered, release := make(chan struct{}), make(chan struct{})
	var once, blockOnce sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	s.e.allow = func(_, _ string) bool {
		blockOnce.Do(func() { close(entered); <-release })
		return false
	}
	s.handle(protocolJSON("textDocument/didChange", nil, documentParams(uri, genericSecretLine, 2)))
	done := firePending(s.d, uri)
	awaitScan(t, entered)
	s.handle(protocolJSON("shutdown", "stop", nil))
	frames := protocolFrames(t, buf)
	if len(frames) != 1 || frames[0]["id"] != "stop" || frames[0]["error"] != nil || !s.d.stopped {
		t.Fatal("shutdown did not acknowledge and halt without waiting for the scan")
	}
	s.handle(protocolJSON("textDocument/didSave", nil, documentParams(uri, genericSecretLine, 2)))
	for _, method := range []string{"initialize", "shutdown", "owned/request", "exit"} {
		s.handle(protocolJSON(method, "late", nil))
		expectProtocolError(t, buf, "late", invalidRequest)
	}
	once.Do(func() { close(release) })
	awaitScan(t, done)
	if len(protocolFrames(t, buf)) != 0 || len(s.d.opened) != 0 || len(s.d.documents) != 0 {
		t.Fatal("in-flight scan published after shutdown")
	}
	if exit, err := s.handle(protocolJSON("exit", nil, nil)); !exit || err != nil {
		t.Fatal("balanced shutdown/exit did not exit cleanly")
	}
}

func TestControlNotificationsAndInvalidParametersDoNotChangeSession(t *testing.T) {
	s, buf := protocolSession(t)
	initializeSession(t, s, buf)
	for _, method := range []string{"initialize", "shutdown", "initialized", "owned/event", "$/owned"} {
		s.handle(protocolJSON(method, nil, json.RawMessage(`{}`)))
	}
	if s.state != ready || len(protocolFrames(t, buf)) != 0 || s.d.stopped {
		t.Fatal("control notification changed session state or emitted a response")
	}
	s.handle(protocolJSON("initialize", "again", json.RawMessage(validInitialize)))
	expectProtocolError(t, buf, "again", invalidRequest)
	s.handle(protocolJSON("shutdown", 7, json.RawMessage(`{}`)))
	expectProtocolError(t, buf, float64(7), invalidParams)
	if exit, err := s.handle(protocolJSON("exit", nil, json.RawMessage(`{}`))); exit || err != nil || s.state != ready {
		t.Fatal("invalid exit parameters terminated the session")
	}
	if exit, err := s.handle(protocolJSON("exit", nil, nil)); !exit || !errors.Is(err, ErrExitWithoutShutdown) {
		t.Fatal("exit without shutdown did not return the LSP failure status")
	}
	s, _ = protocolSession(t)
	if exit, err := s.handle(protocolJSON("exit", nil, nil)); !exit || !errors.Is(err, ErrExitWithoutShutdown) {
		t.Fatal("exit before initialize did not return failure")
	}
}

func TestServeFramedSessionRecovery(t *testing.T) {
	var input, output bytes.Buffer
	for _, body := range [][]byte{
		[]byte(`{"method":"exit"}`),
		protocolJSON("initialize", 0, json.RawMessage(validInitialize)),
		protocolJSON("initialized", nil, json.RawMessage(`{}`)),
		protocolJSON("textDocument/didOpen", nil, documentParams("file:///owned.py", "", 1)),
		protocolJSON("textDocument/didChange", nil, documentParams("file:///owned.py", genericSecretLine, 2)),
		protocolJSON("shutdown", 1, nil),
		protocolJSON("textDocument/didSave", nil, documentParams("file:///owned.py", genericSecretLine, 2)),
		protocolJSON("owned/request", 2, nil),
		protocolJSON("exit", nil, nil),
	} {
		fmt.Fprintf(&input, "Content-Length: %d\r\n\r\n", len(body))
		input.Write(body)
	}
	if err := serve(&input, &output, newTestEngine(t)); err != nil {
		t.Fatal(err)
	}
	frames := protocolFrames(t, &output)
	if len(frames) != 5 || frames[0]["error"] == nil || frames[1]["id"] != float64(0) || frames[2]["method"] != "textDocument/publishDiagnostics" || frames[3]["id"] != float64(1) || frames[4]["error"] == nil {
		t.Fatal("malformed frame or shutdown did not preserve the session response sequence")
	}
	encoded, _ := json.Marshal(frames)
	if strings.Contains(string(encoded), genericSecretLine) {
		t.Fatal("response reflected a candidate value")
	}
}
