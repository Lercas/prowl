package lsp

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/Lercas/prowl/tool/internal/jsonstrict"
	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/resilience"
)

// ErrExitWithoutShutdown lets the CLI report the LSP exit status without calling os.Exit in a library.
var ErrExitWithoutShutdown = errors.New("lsp: exit without shutdown")

const (
	parseError           = -32700
	invalidRequest       = -32600
	methodNotFound       = -32601
	invalidParams        = -32602
	internalError        = -32603
	serverNotInitialized = -32002
)

type protocolMessage struct {
	method     string
	id, params json.RawMessage
	response   bool
}

func decodeMessage(raw []byte) (protocolMessage, int) {
	if jsonstrict.ValidateEncoding(raw) != nil {
		return protocolMessage{}, parseError
	}
	fields, err := jsonstrict.Object(raw, false)
	if err != nil {
		return protocolMessage{}, invalidRequest
	}
	version, ok := stringField(fields["jsonrpc"])
	if !ok || version != "2.0" {
		return protocolMessage{}, invalidRequest
	}
	// This server never issues client requests. Unsolicited responses cannot invoke a handler.
	if fields["method"] == nil && (fields["result"] != nil || fields["error"] != nil) {
		return protocolMessage{response: true}, 0
	}
	method, ok := stringField(fields["method"])
	if !ok || fields["result"] != nil || fields["error"] != nil {
		return protocolMessage{}, invalidRequest
	}
	msg := protocolMessage{method: method, params: fields["params"]}
	if id, exists := fields["id"]; exists {
		if _, ok := stringField(id); !ok {
			if _, ok := integerField(id); !ok {
				return protocolMessage{}, invalidRequest
			}
		}
		msg.id = id
	}
	if p := bytes.TrimSpace(msg.params); len(p) > 0 && p[0] != '{' && p[0] != '[' {
		return msg, invalidParams
	}
	return msg, 0
}

type sessionState uint8

const (
	beforeInitialize sessionState = iota
	awaitInitialized
	ready
	shuttingDown
)

type session struct {
	w     *safeWriter
	e     *engine
	d     *debouncer
	state sessionState
}

func (s *session) handle(raw []byte) (exit bool, err error) {
	msg, code := decodeMessage(raw)
	if code != 0 {
		// Invalid parameter notifications have no response. An invalid envelope has no reliable ID.
		if code != invalidParams || msg.id != nil {
			respondError(s.w, msg.id, code)
		}
		return false, nil
	}
	if msg.response {
		return false, nil
	}
	resilience.Guard(
		func() { exit, err = s.dispatch(msg) },
		func(any) {
			logx.Warn("lsp: recovered handler panic")
			if msg.id != nil {
				respondError(s.w, msg.id, internalError)
			}
		},
	)
	return exit, err
}

func (s *session) dispatch(msg protocolMessage) (bool, error) {
	if msg.id == nil && msg.method == "exit" {
		if len(msg.params) != 0 {
			return false, nil
		}
		if s.state != shuttingDown {
			return true, ErrExitWithoutShutdown
		}
		return true, nil
	}
	if s.state == shuttingDown {
		if msg.id != nil {
			respondError(s.w, msg.id, invalidRequest)
		}
		return false, nil
	}
	if msg.method == "initialize" {
		if msg.id == nil {
			return false, nil
		}
		if s.state != beforeInitialize {
			respondError(s.w, msg.id, invalidRequest)
		} else if !initializeParams(msg.params) {
			respondError(s.w, msg.id, invalidParams)
		} else {
			s.state = awaitInitialized
			dispatch(s.w, s.e, s.d, msg.method, msg.id, msg.params)
		}
		return false, nil
	}
	if s.state == beforeInitialize {
		if msg.id != nil {
			respondError(s.w, msg.id, serverNotInitialized)
		}
		return false, nil
	}
	if msg.method == "shutdown" && msg.id != nil {
		if len(msg.params) != 0 {
			respondError(s.w, msg.id, invalidParams)
		} else {
			s.state = shuttingDown
			s.d.halt()
			respond(s.w, msg.id, nil)
		}
		return false, nil
	}
	if s.state == awaitInitialized {
		if msg.method == "initialized" && msg.id == nil {
			if _, err := jsonstrict.Object(msg.params, false); err == nil {
				s.state = ready
			}
		} else if msg.id != nil {
			respondError(s.w, msg.id, serverNotInitialized)
		}
		return false, nil
	}
	if msg.id != nil {
		// Supported document methods are notifications; a request must not mutate their state.
		respondError(s.w, msg.id, methodNotFound)
	} else {
		switch msg.method {
		case "textDocument/didOpen", "textDocument/didChange", "textDocument/didSave", "textDocument/didClose":
			dispatch(s.w, s.e, s.d, msg.method, nil, msg.params)
		}
	}
	return false, nil
}

func initializeParams(raw json.RawMessage) bool {
	fields, err := jsonstrict.Object(raw, false)
	if err != nil {
		return false
	}
	pid, exists := fields["processId"]
	if !exists {
		return false
	}
	if !bytes.Equal(bytes.TrimSpace(pid), []byte("null")) {
		if _, ok := integerField(pid); !ok {
			return false
		}
	}
	root, exists := fields["rootUri"]
	if !exists {
		return false
	}
	if !bytes.Equal(bytes.TrimSpace(root), []byte("null")) {
		// Reuse the same URI contract as document notifications; never read this URI from disk.
		if _, ok := uriField(root); !ok {
			return false
		}
	}
	_, err = jsonstrict.Object(fields["capabilities"], false)
	return err == nil
}

func respondError(w *safeWriter, id json.RawMessage, code int) {
	messages := map[int]string{
		parseError: "Некорректный JSON.", invalidRequest: "Некорректный запрос.",
		methodNotFound: "Метод не поддерживается.", invalidParams: "Некорректные параметры.",
		internalError: "Внутренняя ошибка сервера.", serverNotInitialized: "Сервер ещё не инициализирован.",
	}
	w.send(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": messages[code]}})
}
