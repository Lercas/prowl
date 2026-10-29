package lsp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/checkedio"
)

const outputFailureSecret = "\x4fWNED_G7hJ9kL2mN5p"

type outputFault struct {
	mu     sync.Mutex
	mode   string
	failAt int
	calls  int
	buf    bytes.Buffer
}

func (w *outputFault) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls++
	if w.calls != w.failAt {
		return w.buf.Write(p)
	}
	switch w.mode {
	case "zero":
		return 0, nil
	case "short":
		return len(p) / 2, nil
	case "negative":
		return -1, nil
	case "oversized":
		return len(p) + 1, nil
	case "panic":
		panic(outputFailureSecret)
	default:
		return 0, errors.New(outputFailureSecret)
	}
}

func (w *outputFault) callCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.calls
}

func outputFrame(method string, id any, params json.RawMessage) []byte {
	b := protocolJSON(method, id, params)
	return append([]byte(fmt.Sprintf("Content-Length: %d\r\n\r\n", len(b))), b...)
}

func TestServeRejectsFailedResponseOutput(t *testing.T) {
	for _, mode := range []string{"zero", "short", "negative", "oversized", "error", "panic"} {
		writer := &outputFault{mode: mode, failAt: 1}
		input := bytes.NewReader(outputFrame("initialize", 1, json.RawMessage(validInitialize)))
		err := serve(input, writer, newTestEngine(t))
		if !errors.Is(err, errOutput) || writer.callCount() != 1 || strings.Contains(err.Error(), outputFailureSecret) {
			t.Fatalf("%s failure was ignored, retried or exposed", mode)
		}
	}
}

func TestFailedWriterIsStickyAcrossSizesAndConcurrentSenders(t *testing.T) {
	for _, size := range []int{16, 32 * 1024} {
		for _, mode := range []string{"zero", "short", "negative", "oversized", "error", "panic"} {
			raw := &outputFault{mode: mode, failAt: 1}
			w := newSafeWriter(bufio.NewWriter(checkedio.NewWriter(raw)))
			var callbacks atomic.Int32
			w.onFailure = func() { callbacks.Add(1) }
			var senders sync.WaitGroup
			for i := 0; i < 8; i++ {
				senders.Add(1)
				go func() {
					defer senders.Done()
					w.send(map[string]any{"body": strings.Repeat("x", size)})
				}()
			}
			senders.Wait()
			if !errors.Is(w.Err(), errOutput) || callbacks.Load() != 1 || raw.callCount() != 1 {
				t.Fatal("failed frame was retried or failure callback ran more than once")
			}
		}
	}
}

func TestFrameEncodingFailureIsFatalBeforeAnyOutput(t *testing.T) {
	raw := &outputFault{}
	w := newSafeWriter(bufio.NewWriter(checkedio.NewWriter(raw)))
	w.send(map[string]any{"unsupported": func() {}})
	w.send(map[string]any{"jsonrpc": "2.0", "id": 1, "result": nil})
	if !errors.Is(w.Err(), errOutput) || raw.callCount() != 0 {
		t.Fatal("unserializable reply became silent success or was followed by another frame")
	}
}

type outputWakeReader struct {
	*io.PipeReader
	reads    int
	waiting  chan struct{}
	closed   atomic.Int32
	waitOnce sync.Once
}

func (r *outputWakeReader) Read(p []byte) (int, error) {
	r.reads++
	if r.reads >= 3 {
		r.waitOnce.Do(func() { close(r.waiting) })
	}
	return r.PipeReader.Read(p)
}

func (r *outputWakeReader) Close() error {
	r.closed.Add(1)
	return r.PipeReader.Close()
}

func TestBackgroundOutputFailureWakesIdleReadLoop(t *testing.T) {
	r, input := io.Pipe()
	reader := &outputWakeReader{PipeReader: r, waiting: make(chan struct{})}
	defer r.Close()
	defer input.Close()
	writer := &outputFault{mode: "error", failAt: 3}
	e := newTestEngine(t)
	e.allow = func(string, string) bool { <-reader.waiting; return false }
	done := make(chan error, 1)
	go func() { done <- serve(reader, writer, e) }()
	startup := outputFrame("initialize", 1, json.RawMessage(validInitialize))
	startup = append(startup, outputFrame("initialized", nil, json.RawMessage(`{}`))...)
	startup = append(startup, outputFrame("textDocument/didOpen", nil, json.RawMessage(`{"textDocument":{"uri":"file:///owned.env","languageId":"plaintext","version":1,"text":"clean"}}`))...)
	if _, err := input.Write(startup); err != nil {
		t.Fatal(err)
	}
	change := outputFrame("textDocument/didChange", nil, json.RawMessage(`{"textDocument":{"uri":"file:///owned.env","version":2},"contentChanges":[{"text":"AKIANAFGYOEYPXU1DSYP"}]}`))
	if _, err := input.Write(change); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, errOutput) || reader.closed.Load() != 1 || writer.callCount() != 3 {
			t.Fatal("background failure did not terminate the idle session exactly once")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("lost diagnostics left the read loop waiting for another client request")
	}
}

func TestHealthyConcurrentFramesRemainIntact(t *testing.T) {
	raw := &outputFault{}
	w := newSafeWriter(bufio.NewWriter(checkedio.NewWriter(raw)))
	var senders sync.WaitGroup
	for id := 0; id < 32; id++ {
		senders.Add(1)
		go func() {
			defer senders.Done()
			w.send(map[string]any{"jsonrpc": "2.0", "id": id, "result": strings.Repeat("healthy", 1024)})
		}()
	}
	senders.Wait()
	if w.Err() != nil {
		t.Fatal("healthy concurrent output failed")
	}
	reader := bufio.NewReader(bytes.NewReader(raw.buf.Bytes()))
	seen := make(map[int]bool)
	for i := 0; i < 32; i++ {
		body, err := readMessage(reader)
		var msg struct{ ID int }
		if err != nil || json.Unmarshal(body, &msg) != nil || seen[msg.ID] {
			t.Fatal("concurrent frames interleaved or lost correlation IDs")
		}
		seen[msg.ID] = true
	}
	if _, err := readMessage(reader); !errors.Is(err, io.EOF) {
		t.Fatal("unexpected trailing bytes after intact frames")
	}
}
