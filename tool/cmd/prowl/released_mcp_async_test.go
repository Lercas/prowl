package main

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"
)

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
