package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestMCPPathsAndVerifiedOnly(t *testing.T) {
	for _, name := range []string{"prowl_scan", "prowl_mobile"} {
		path := "  file with spaces  "
		argv, err := mcpArgv(name, map[string]any{"path": path})
		if err != nil || argv[1] != path {
			t.Fatalf("%s changed path: %q, %v", name, argv, err)
		}
	}
	for _, tc := range []struct{ name, key, target string }{
		{"prowl_scan", "path", "."}, {"prowl_repo", "url", "https://example.invalid/repo"},
		{"prowl_cicd", "target", "github:owner/repo"}, {"prowl_domain", "target", "example.invalid"},
	} {
		args := map[string]any{tc.key: tc.target, "verified_only": true}
		if tc.name == "prowl_domain" {
			args["authorized"] = true
		}
		argv, err := mcpArgv(tc.name, args)
		if err != nil || !strings.Contains(strings.Join(argv, " "), "--verified-only") {
			t.Fatalf("%s: %v, %v", tc.name, argv, err)
		}
	}
}

func TestMCPReportsProtocolAndOutputErrors(t *testing.T) {
	for _, tc := range []struct {
		params string
		runErr error
		want   string
	}{
		{`{"name":"unknown"}`, nil, `"code":-32602`},
		{`{"name":5}`, nil, `"code":-32602`},
		{`{"name":"prowl_scan","arguments":{"path":"."}}`, errMCPOutputLimit, "32 МиБ"},
		{`{"name":"prowl_scan","arguments":{"path":"."}}`, errors.New("sensitive detail"), "проверьте путь"},
	} {
		var output bytes.Buffer
		w := newMCPWriter(&output)
		mcpCallContext(context.Background(), w, mcpRequest{ID: json.RawMessage(`1`), Params: json.RawMessage(tc.params)}, func(context.Context, []string) (string, error) { return "", tc.runErr })
		_ = w.flush()
		if !strings.Contains(output.String(), tc.want) || strings.Contains(output.String(), "sensitive detail") {
			t.Fatalf("unexpected response: %s", output.String())
		}
	}
}

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

func TestMCPCancelRequestCannotCancelScan(t *testing.T) {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	defer inR.Close()
	defer outR.Close()
	started, release := make(chan struct{}), make(chan struct{})
	done := make(chan int, 1)
	go func() {
		done <- serveMCPWithRunner(inR, outW, func(ctx context.Context, _ []string) (string, error) {
			close(started)
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-release:
				return `{"schema_version":"1.4","complete":true,"count":0,"findings":[]}`, nil
			}
		})
		_ = outW.Close()
	}()
	_, _ = io.WriteString(inW, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"prowl_scan","arguments":{"path":"."}}}`+"\n")
	<-started
	_, _ = io.WriteString(inW, `{"jsonrpc":"2.0","id":2,"method":"notifications/cancelled","params":{"requestId":1}}`+"\n")
	reader := bufio.NewReader(outR)
	line, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(line, `"code":-32600`) {
		t.Fatalf("invalid cancellation: %q, %v", line, err)
	}
	close(release)
	line, err = reader.ReadString('\n')
	if err != nil || !strings.Contains(line, `"id":1`) || !strings.Contains(line, `"isError":false`) {
		t.Fatalf("scan was interrupted: %q, %v", line, err)
	}
	_ = inW.Close()
	if status := <-done; status != 0 {
		t.Fatal(status)
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
