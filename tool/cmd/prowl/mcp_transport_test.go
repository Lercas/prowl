package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

const mcpTransportSecret = "\x4fWNED_G7hJ9kL2mN5p"
const mcpTransportPing = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n"

type mcpReadFailure struct{}

func (mcpReadFailure) Read([]byte) (int, error) { return 0, errors.New(mcpTransportSecret) }

type mcpByteReader struct {
	data  string
	index int
}

func (r *mcpByteReader) Read(p []byte) (int, error) {
	if r.index == len(r.data) {
		return 0, io.EOF
	}
	p[0] = r.data[r.index]
	r.index++
	return 1, nil
}

type mcpWriteFailure struct {
	mode  string
	calls int
}

func (w *mcpWriteFailure) Write(p []byte) (int, error) {
	w.calls++
	switch w.mode {
	case "zero":
		return 0, nil
	case "short":
		return len(p) / 2, nil
	case "negative":
		return -1, nil
	case "oversized":
		return len(p) + 1, nil
	default:
		return 0, errors.New(mcpTransportSecret)
	}
}

func TestMCPTransportReadFailureIsNotSuccess(t *testing.T) {
	for _, input := range []io.Reader{mcpReadFailure{}, io.MultiReader(strings.NewReader(mcpTransportPing), mcpReadFailure{})} {
		var output, stderr bytes.Buffer
		if status := serveMCP(input, &output, &stderr); status != 2 || stderr.Len() == 0 {
			t.Fatal("reader failure became a successful EOF")
		}
		if strings.Contains(stderr.String(), mcpTransportSecret) {
			t.Fatal("reader failure leaked its payload")
		}
	}
}

func TestMCPTransportOutputFailureStopsInput(t *testing.T) {
	for _, mode := range []string{"zero", "short", "negative", "oversized", "error"} {
		reader := &mcpByteReader{data: mcpTransportPing + mcpTransportPing}
		writer := &mcpWriteFailure{mode: mode}
		var stderr bytes.Buffer
		if status := serveMCP(reader, writer, &stderr); status != 2 {
			t.Fatalf("%s output failure returned status %d", mode, status)
		}
		if reader.index != len(mcpTransportPing) || writer.calls != 1 {
			t.Fatal("MCP continued reading or writing after failed output")
		}
		if strings.Contains(stderr.String(), mcpTransportSecret) || stderr.Len() == 0 {
			t.Fatal("output failure was missing or leaked its payload")
		}
	}
}

func TestMCPAsyncOutputFailureInterruptsBlockedInput(t *testing.T) {
	reader, writer := io.Pipe()
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	var stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- serveMCPWithRunnerAndErrors(reader, &mcpWriteFailure{mode: "error"}, &stderr,
			func(context.Context, []string) (string, error) {
				return `{"schema_version":"1.4","complete":true,"count":0,"findings":[]}`, nil
			})
	}()
	_, err := io.WriteString(writer, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"prowl_scan","arguments":{"path":"."}}}`+"\n")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case status := <-done:
		if status != 2 || stderr.Len() == 0 {
			t.Fatalf("output failure returned status %d", status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("output failure left the server blocked on input")
	}
}

func TestMCPTransportEncodingFailureIsSticky(t *testing.T) {
	var output bytes.Buffer
	w := newMCPWriter(&output)
	writeMCP(w, map[string]any{"unsupported": func() {}})
	writeMCP(w, map[string]any{"jsonrpc": "2.0", "id": 1, "result": nil})
	if w.flush() == nil || output.Len() != 0 {
		t.Fatal("encoding failure was silently dropped or followed by another reply")
	}
}

func TestMCPTransportBodyBoundary(t *testing.T) {
	for _, newline := range []bool{false, true} {
		for _, delta := range []int{-1, 0, 1} {
			body := strings.TrimSuffix(mcpTransportPing, "\n")
			body += strings.Repeat(" ", maxMCPMessageBytes+delta-len(body))
			if newline {
				body += "\n"
			}
			var output, stderr bytes.Buffer
			status := serveMCP(strings.NewReader(body), &output, &stderr)
			if delta > 0 {
				if status != 2 || output.Len() != 0 {
					t.Fatal("oversized body was acknowledged")
				}
			} else {
				var reply map[string]any
				if status != 0 || json.Unmarshal(output.Bytes(), &reply) != nil || reply["id"] != float64(1) || stderr.Len() != 0 {
					t.Fatal("bounded body lost its reply or failed at EOF")
				}
			}
		}
	}
}
