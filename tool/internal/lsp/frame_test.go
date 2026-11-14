package lsp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
)

func messageFrame(body string) string {
	return fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(body), body)
}

func TestFrameRejectsAmbiguousBoundaries(t *testing.T) {
	const body = `{"jsonrpc":"2.0","method":"exit"}`
	length := strconv.Itoa(len(body))
	for name, headers := range map[string]string{
		"duplicate":       "Content-Length: " + length + "\r\nContent-Length: " + length + "\r\n\r\n",
		"conflicting":     "Content-Length: 1\r\nContent-Length: " + length + "\r\n\r\n",
		"malformed-first": "Content-Length: broken\r\nContent-Length: " + length + "\r\n\r\n",
		"substring-name":  "X-Content-Length: " + length + "\r\n\r\n",
		"garbage-prefix":  "garbage Content-Length: " + length + "\r\n\r\n",
		"value-token":     "X-Header: Content-Length: " + length + "\r\n\r\n",
		"folded-name":     " Content-Length: " + length + "\r\n\r\n",
		"plus":            "Content-Length: +" + length + "\r\n\r\n",
		"negative-zero":   "Content-Length: -0\r\n\r\n",
		"negative":        "Content-Length: -1\r\n\r\n",
		"empty":           "Content-Length:\r\n\r\n",
		"comma":           "Content-Length: " + length + "," + length + "\r\n\r\n",
		"overflow":        "Content-Length: 999999999999999999999999999\r\n\r\n",
		"over-cap":        fmt.Sprintf("Content-Length: %d\r\n\r\n", maxMessageBytes+1),
		"bare-lf":         "Content-Length: " + length + "\n\n",
		"bare-blank-lf":   "Content-Length: " + length + "\r\n\n",
		"non-ascii":       "Content-Length: " + length + "\r\nX-Header: Ключ\r\n\r\n",
		"control-value":   "Content-Length: " + length + "\r\nX-Header: a\x00b\r\n\r\n",
		"missing-length":  "Content-Type: application/vscode-jsonrpc\r\n\r\n",
		"extra-cr":        "Content-Length: " + length + "\r\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			r := bufio.NewReader(strings.NewReader(headers + body + messageFrame(body)))
			if got, err := readMessage(r); len(got) != 0 || !errors.Is(err, errFatalFrame) {
				t.Fatal("ambiguous transport boundary was accepted or treated as recoverable")
			}
		})
	}
}

func TestFrameAcceptsCanonicalAndExtensionHeaders(t *testing.T) {
	const body = `{"jsonrpc":"2.0","method":"owned/Ключ😀"}`
	for _, contentType := range []string{
		"", "application/vscode-jsonrpc", "application/vscode-jsonrpc; charset=utf-8",
		"application/vscode-jsonrpc; charset=utf8", `application/vscode-jsonrpc; charset="UTF-8"`,
		"application/json; charset=utf-8; owned=extension",
	} {
		headers := fmt.Sprintf("X-Content-Length: 1\r\ncOnTeNt-LeNgTh:\t000%d \t\r\nX-Owned: value\r\n", len(body))
		if contentType != "" {
			headers += "Content-Type: " + contentType + "\r\n"
		}
		r := bufio.NewReader(strings.NewReader(headers + "\r\n" + body + messageFrame(body)))
		for range 2 {
			if got, err := readMessage(r); err != nil || string(got) != body {
				t.Fatal("valid byte length, casing, whitespace or UTF8 compatibility was lost")
			}
		}
	}
}

type countedFrameReader struct {
	r     io.Reader
	count int
}

func (r *countedFrameReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.count += n
	return n, err
}

func TestFrameHeaderBudgetStopsUnboundedInput(t *testing.T) {
	for _, input := range []string{
		strings.Repeat("x", 1<<20),
		"X-Owned: " + strings.Repeat("x", 1<<20) + "\r\n" + messageFrame(`{}`),
		strings.Repeat("X-Owned: x\r\n", 100000) + messageFrame(`{}`),
	} {
		counter := &countedFrameReader{r: strings.NewReader(input)}
		r := bufio.NewReader(counter)
		if _, err := readMessage(r); !errors.Is(err, errFatalFrame) {
			t.Fatal("oversized or incomplete headers did not fail closed")
		}
		if counter.count > maxHeaderBytes+r.Size() {
			t.Fatalf("read beyond the header budget and fixed reader buffer: %d bytes", counter.count)
		}
	}
}

func TestFrameExactHeaderAndBodyLimits(t *testing.T) {
	const body = `{}`
	base := "Content-Length: 2\r\nX-Owned: \r\n\r\n"
	for _, delta := range []int{-1, 0, 1} {
		headers := strings.Replace(base, "X-Owned: ", "X-Owned: "+strings.Repeat("x", maxHeaderBytes+delta-len(base)), 1)
		if len(headers) != maxHeaderBytes+delta {
			t.Fatal("bad header boundary fixture")
		}
		got, err := readMessage(bufio.NewReader(strings.NewReader(headers + body)))
		if delta <= 0 {
			if err != nil || string(got) != body {
				t.Fatal("header at/below the byte limit was rejected")
			}
		} else if !errors.Is(err, errFatalFrame) {
			t.Fatal("header above the byte limit was accepted")
		}
	}
	for _, n := range []int{0, maxMessageBytes - 1, maxMessageBytes, maxMessageBytes + 1} {
		input := fmt.Sprintf("Content-Length: %d\r\n\r\n", n)
		if n <= maxMessageBytes {
			input += strings.Repeat("x", n)
		}
		got, err := readMessage(bufio.NewReader(strings.NewReader(input)))
		if n <= maxMessageBytes {
			if err != nil || len(got) != n {
				t.Fatal("body at/below the byte limit was rejected")
			}
		} else if !errors.Is(err, errFatalFrame) {
			t.Fatal("body above the byte limit was accepted")
		}
	}
}

func TestRejectedContentCannotInjectAnotherFrame(t *testing.T) {
	injected := messageFrame(`{"jsonrpc":"2.0","method":"exit"}`)
	const good = `{"jsonrpc":"2.0","id":42,"method":"owned/request"}`
	for _, headers := range []string{
		"Content-Type: application/vscode-jsonrpc; charset=utf-16\r\n",
		"Content-Type: broken/\r\n",
		"Content-Type: broken\r\n",
		"Content-Type: application/vscode-jsonrpc; charset=\"\"\r\n",
		"Content-Type: application/vscode-jsonrpc\r\nContent-Type: application/vscode-jsonrpc\r\n",
	} {
		input := headers + fmt.Sprintf("Content-Length: %d\r\n\r\n", len(injected)) + injected + messageFrame(good)
		r := bufio.NewReader(strings.NewReader(input))
		if _, err := readMessage(r); !errors.Is(err, errBadFrame) {
			t.Fatal("invalid content type was not rejected after consuming the trusted body")
		}
		if got, err := readMessage(r); err != nil || string(got) != good {
			t.Fatal("discarded content was reparsed as a new frame or swallowed the valid following frame")
		}
	}
}

func TestFrameDistinguishesCleanAndTruncatedEOF(t *testing.T) {
	if _, err := readMessage(bufio.NewReader(strings.NewReader(""))); !errors.Is(err, io.EOF) {
		t.Fatal("clean EOF was not recognized")
	}
	for _, input := range []string{"Content-Length: 2", "Content-Length: 2\r\n", "Content-Length: 2\r\n\r\n{", "X-Owned:"} {
		if _, err := readMessage(bufio.NewReader(strings.NewReader(input))); !errors.Is(err, errFatalFrame) {
			t.Fatal("truncated frame looked like a clean disconnect")
		}
	}
}

func TestServeFrameFaultsDoNotDispatchBody(t *testing.T) {
	var initial bytes.Buffer
	for _, body := range [][]byte{
		protocolJSON("initialize", 1, []byte(validInitialize)), protocolJSON("initialized", nil, []byte(`{}`)),
		protocolJSON("textDocument/didOpen", nil, documentParams("file:///frame.py", genericSecretLine, 1)),
	} {
		initial.WriteString(messageFrame(string(body)))
	}
	clean := string(protocolJSON("textDocument/didSave", nil, documentParams("file:///frame.py", "", 1)))
	for _, header := range []string{"X-Content-Length: ", "Content-Length: +"} {
		var output bytes.Buffer
		input := initial.String() + header + strconv.Itoa(len(clean)) + "\r\n\r\n" + clean
		if err := serve(strings.NewReader(input), &output, newTestEngine(t)); !errors.Is(err, errFatalFrame) {
			t.Fatal("unsafe framing did not terminate with an error")
		}
		if count, last := drainPublishes(t, &output); count != 1 || !hasDiag(last) {
			t.Fatal("rejected frame cleared current diagnostics")
		}
	}
}

func FuzzReadMessage(f *testing.F) {
	for _, seed := range []string{messageFrame(`{}`), "X-Content-Length: 2\r\n\r\n{}", "Content-Length: 99999999\r\n\r\n", "Content-Length: 1\r\n\r\n"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		// Even an arbitrary stream cannot make a single read consume beyond the transport budgets.
		counter := &countedFrameReader{r: strings.NewReader(input)}
		r := bufio.NewReader(counter)
		body, err := readMessage(r)
		if len(body) > maxMessageBytes {
			t.Fatal("oversized body returned")
		}
		if counter.count > maxHeaderBytes+maxMessageBytes+r.Size() {
			t.Fatal("unbounded transport consumption")
		}
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, errFatalFrame) && !errors.Is(err, errBadFrame) {
			t.Fatal("unstable transport error classification")
		}
		if len(input) <= maxMessageBytes {
			// Header-like bytes in a correctly framed opaque body must never become another message.
			const sentinel = "owned boundary sentinel"
			r = bufio.NewReader(strings.NewReader(messageFrame(input) + messageFrame(sentinel)))
			if got, err := readMessage(r); err != nil || string(got) != input {
				t.Fatal("opaque body was not read by its exact byte length")
			}
			if got, err := readMessage(r); err != nil || string(got) != sentinel {
				t.Fatal("body content corrupted the following frame boundary")
			}
		}
	})
}
