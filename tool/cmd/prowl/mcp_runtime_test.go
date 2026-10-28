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

func TestMCPRejectsCoercedAndUnknownArguments(t *testing.T) {
	for _, args := range []map[string]any{{"path": ".", "verify": "true"}, {"path": ".", "show_secrets": 1}, {"path": ".", "typo": true}, {"path": 3}} {
		if _, err := mcpArgv("prowl_scan", args); err == nil {
			t.Fatal("invalid argument accepted")
		}
	}
}
func TestMCPStructuredIncompleteResult(t *testing.T) {
	var b bytes.Buffer
	w := newMCPWriter(&b)
	request := mcpRequest{ID: json.RawMessage(`1`), Params: json.RawMessage(`{"name":"prowl_scan","arguments":{"path":"."}}`)}
	mcpCallContext(context.Background(), w, request, func(context.Context, []string) (string, error) {
		return `{"schema_version":"1.4","complete":false,"count":0,"findings":[],"diagnostics":[{"code":"max_size","incomplete":true}]}`, nil
	})
	_ = w.flush()
	var reply struct {
		Result struct {
			Error      bool           `json:"isError"`
			Structured map[string]any `json:"structuredContent"`
		}
	}
	if json.Unmarshal(b.Bytes(), &reply) != nil || !reply.Result.Error || reply.Result.Structured["complete"] != false {
		t.Fatalf("incomplete scan presented as successful: %s", b.String())
	}
}
func TestMCPCancellationLeavesTransportResponsive(t *testing.T) {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	defer inR.Close()
	defer outR.Close()
	started := make(chan struct{})
	canceled := make(chan struct{})
	done := make(chan int, 1)
	go func() {
		done <- serveMCPWithRunner(inR, outW, func(ctx context.Context, _ []string) (string, error) {
			close(started)
			<-ctx.Done()
			close(canceled)
			return "", ctx.Err()
		})
		_ = outW.Close()
	}()
	replies := make(chan string, 4)
	go func() {
		sc := bufio.NewScanner(outR)
		for sc.Scan() {
			replies <- sc.Text()
		}
		close(replies)
	}()
	_, _ = io.WriteString(inW, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"prowl_scan\",\"arguments\":{\"path\":\".\"}}}\n")
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("scan did not start")
	}
	_, _ = io.WriteString(inW, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":1}}\n")
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation was not observed")
	}
	_ = inW.Close()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatal(code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("transport did not close")
	}
	ping := false
	for r := range replies {
		if strings.Contains(r, `"id":2`) {
			ping = true
		}
	}
	if !ping {
		t.Fatal("scan blocked ping")
	}
}
func TestSelftestProfiles(t *testing.T) {
	for _, profile := range []string{"web", "mobile", "enterprise"} {
		r, err := runSelftest(profile, true)
		if err != nil || !r.Passed || r.Network || len(r.Cases) < 2 {
			t.Fatalf("profile %s failed: %+v %v", profile, r, err)
		}
	}
}
