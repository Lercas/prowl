package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

func TestMCPRejectsAmbiguousArgumentsBeforeRunning(t *testing.T) {
	for _, params := range []string{
		`{"name":"prowl_scan","name":"prowl_domain","arguments":{"path":"."}}`,
		`{"name":"prowl_scan","arguments":{"path":".","path":"other"}}`,
		`{"name":"prowl_scan","arguments":{"path":".","p\u0061th":"other"}}`,
		`{"name":"prowl_scan","arguments":{"path":"\ud800"}}`,
	} {
		var out bytes.Buffer
		w := newMCPWriter(&out)
		called := false
		mcpCallContext(t.Context(), w, mcpRequest{ID: json.RawMessage(`1`), Params: json.RawMessage(params)}, func(context.Context, []string) (string, error) { called = true; return "", nil })
		_ = w.flush()
		if called || !strings.Contains(out.String(), `"code":-32602`) {
			t.Fatal("ambiguous tool arguments reached scanner")
		}
	}
}

func TestMCPBoundsActiveCallsAndCancelsBothAtEOF(t *testing.T) {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	started := make(chan struct{}, 2)
	stopped := make(chan struct{}, 2)
	done := make(chan int, 1)
	replies := make(chan string, 8)
	go func() {
		done <- serveMCPWithRunner(inR, outW, func(ctx context.Context, _ []string) (string, error) {
			started <- struct{}{}
			<-ctx.Done()
			stopped <- struct{}{}
			return "", ctx.Err()
		})
		_ = outW.Close()
	}()
	go func() {
		s := bufio.NewScanner(outR)
		for s.Scan() {
			replies <- s.Text()
		}
		close(replies)
	}()
	t.Cleanup(func() { _ = inW.Close(); _ = inR.Close(); _ = outR.Close(); _ = outW.Close() })
	send := func(body string) {
		t.Helper()
		written := make(chan error, 1)
		go func() { _, err := io.WriteString(inW, body+"\n"); written <- err }()
		select {
		case err := <-written:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("transport stopped reading")
		}
	}
	receive := func() string {
		t.Helper()
		select {
		case s := <-replies:
			return s
		case <-time.After(3 * time.Second):
			t.Fatal("transport stopped replying")
			return ""
		}
	}
	call := func(id string) string {
		return `{"jsonrpc":"2.0","id":` + id + `,"method":"tools/call","params":{"name":"prowl_scan","arguments":{"path":"."}}}`
	}
	for _, id := range []string{"1", "2"} {
		send(call(id))
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("scan did not start")
		}
	}
	send(call("1"))
	if !strings.Contains(receive(), `"code":-32600`) {
		t.Fatal("duplicate active ID was not rejected")
	}
	send(call("3"))
	if !strings.Contains(receive(), `"isError":true`) {
		t.Fatal("third active scan bypassed concurrency budget")
	}
	send(`{"jsonrpc":"2.0","id":4,"method":"ping"}`)
	if !strings.Contains(receive(), `"id":4`) {
		t.Fatal("active scans blocked ping")
	}
	_ = inW.Close()
	for range 2 {
		select {
		case <-stopped:
		case <-time.After(3 * time.Second):
			t.Fatal("EOF left an active scan")
		}
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Fatal(code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("MCP did not exit")
	}
}

func TestMCPOutputBudgetCancelsAndDiscardsOversizeReport(t *testing.T) {
	canceled := false
	w := boundedMCPOutput{cancel: func() { canceled = true }}
	if n, err := w.Write(bytes.Repeat([]byte("x"), 32<<20)); err != nil || n != 32<<20 {
		t.Fatal("exact output boundary rejected")
	}
	if n, err := w.Write([]byte("x")); err != errMCPOutputLimit || n != 0 || !canceled || !w.exceeded || w.Len() != 32<<20 {
		t.Fatal("oversized report escaped MCP budget")
	}
}
