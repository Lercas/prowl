package atlassian

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type bodyTransport struct{ body io.ReadCloser }

func (f bodyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Body: f.body, Header: make(http.Header), Request: r}, nil
}

type failingBody struct {
	io.Reader
	readErr, closeErr error
	closed            bool
}

func (b *failingBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if err == io.EOF && b.readErr != nil {
		err = b.readErr
	}
	return n, err
}

func (b *failingBody) Close() error {
	b.closed = true
	return b.closeErr
}

func integrityClient(body io.ReadCloser) *Client {
	c := NewClient("https://fixture.invalid", Auth{}, 0)
	c.http = &http.Client{Transport: bodyTransport{body}}
	return c
}

func TestClientRejectsCorruptedSuccessfulResponses(t *testing.T) {
	for name, raw := range map[string]string{
		"trailing document": `{"issues":[]} {"issues":[]}`,
		"trailing text":     `{"issues":[]} secret`,
		"invalid UTF8":      "{\"issues\":[{\"key\":\"P\",\"fields\":{\"summary\":\"\xff\"}}]}",
		"unpaired escape":   `{"issues":[{"key":"P","fields":{"summary":"\ud800"}}]}`,
		"duplicate content": `{"issues":[{"key":"P","fields":{"summary":"secret","summary":"clean"}}]}`,
		"folded listing":    `{"issues":[{"key":"P","fields":{"summary":"secret"}}],"ISSUES":[]}`,
		"HTTP 200 error":    `{"error":"secret-from-provider"}`,
		"null document":     `null`,
		"null listing":      `{"issues":null}`,
		"missing fields":    `{"issues":[{"key":"P"}]}`,
		"missing key":       `{"issues":[{"fields":{}}]}`,
		"wrong content":     `{"issues":42}`,
	} {
		t.Run(name, func(t *testing.T) {
			body := &failingBody{Reader: strings.NewReader(raw)}
			out := jiraSearchPage{Issues: []jiraIssue{{Key: "unchanged"}}}
			if err := integrityClient(body).get(context.Background(), "/search", nil, &out); err == nil {
				t.Fatal("corrupted or incomplete response accepted")
			}
			if !body.closed || len(out.Issues) != 1 || out.Issues[0].Key != "unchanged" {
				t.Fatal("failed request left body open or changed caller state")
			}
		})
	}
}

func TestClientReadsAndClosesEntireResponse(t *testing.T) {
	for _, probe := range []bool{false, true} {
		for _, phase := range []string{"read", "close"} {
			t.Run(phase+map[bool]string{true: "/probe", false: "/JSON"}[probe], func(t *testing.T) {
				body := &failingBody{Reader: strings.NewReader(`{"issues":[]}`)}
				if phase == "read" {
					body.readErr = errors.New("transport-failure-with-secret")
				} else {
					body.closeErr = errors.New("close-failure-with-secret")
				}
				out := jiraSearchPage{Issues: []jiraIssue{{Key: "unchanged"}}}
				var destination any = &out
				if probe {
					destination = nil
				}
				err := integrityClient(body).get(context.Background(), "/path", nil, destination)
				if err == nil || strings.Contains(err.Error(), "with-secret") {
					t.Fatalf("body failure accepted or leaked: %v", err)
				}
				if !body.closed || out.Issues[0].Key != "unchanged" {
					t.Fatal("body leaked or failed request changed caller state")
				}
			})
		}
	}
}

// paddingBody simulates a large or infinite HTTP body without allocating it in the fixture.
type paddingBody struct{ remaining, read int64 }

func (b *paddingBody) Read(p []byte) (int, error) {
	if b.remaining == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > b.remaining {
		n = int(b.remaining)
	}
	for i := range p[:n] {
		p[i] = ' '
	}
	b.remaining -= int64(n)
	b.read += int64(n)
	return n, nil
}

func TestClientBodyBudgetIncludesProbesAndTrailingPadding(t *testing.T) {
	for _, probe := range []bool{false, true} {
		padding := &paddingBody{remaining: maxResponseBytes * 2}
		body := &failingBody{Reader: io.MultiReader(strings.NewReader(`{"issues":[]}`), padding)}
		var destination any
		if !probe {
			destination = &jiraSearchPage{}
		}
		if err := integrityClient(body).get(context.Background(), "/path", nil, destination); err == nil {
			t.Fatal("valid JSON prefix concealed an oversized body")
		}
		if !body.closed || padding.read > maxResponseBytes+1 {
			t.Fatalf("body not closed or read budget exceeded: %d", padding.read)
		}
	}
	padding := &paddingBody{remaining: maxResponseBytes}
	body := &failingBody{Reader: padding}
	if err := integrityClient(body).get(context.Background(), "/probe", nil, nil); err != nil || !body.closed || padding.read != maxResponseBytes {
		t.Fatalf("exact-budget probe rejected or not fully read: %v bytes=%d", err, padding.read)
	}
}

func TestEmptyAndUnicodeResponsesRemainValid(t *testing.T) {
	for _, raw := range []string{`{"issues":[]}`, `{"issues":[{"key":"P","fields":{"summary":"é \ud83d\ude00","SUMMARY":"different map field"}}]}`} {
		out := jiraSearchPage{}
		if err := integrityClient(io.NopCloser(strings.NewReader(raw))).get(context.Background(), "/search", nil, &out); err != nil {
			t.Fatal(err)
		}
	}
	for _, raw := range []string{`{"values":[]}`, `{"histories":[]}`} {
		out := jiraChangelogPage{}
		if err := integrityClient(io.NopCloser(strings.NewReader(raw))).get(context.Background(), "/changelog", nil, &out); err != nil || out.entries() == nil {
			t.Fatalf("empty history rejected: %v", err)
		}
	}
	var body confPageBodyV2
	if err := integrityClient(io.NopCloser(strings.NewReader(`{"body":{"storage":{"value":""}}}`))).get(context.Background(), "/page", nil, &body); err != nil || body.Body.Storage.Value == nil {
		t.Fatalf("explicitly empty page body rejected: %v", err)
	}
}

func TestResponseShapesCannotSilentlySkipRequiredData(t *testing.T) {
	for _, destination := range []any{&jiraServerInfo{}, &[]jiraProject{}, &jiraProjectPage{}, &jiraSearchPage{}, &jiraCommentPage{}, &jiraChangelogPage{}, &jiraEmbeddedHistory{}, &jiraBulkHistoryPage{}, &confSpacesPageV1{}, &confSpacesPageV2{}, &confContentPageV1{}, &confPagesPageV2{}, &confVersionsPageV1{}, &confVersionsPageV2{}, &confPageBodyV2{}, &confContentV1{}} {
		for _, raw := range []string{`{}`, `null`, `{"error":"provider-secret"}`} {
			if err := integrityClient(io.NopCloser(strings.NewReader(raw))).get(context.Background(), "/path", nil, destination); err == nil {
				t.Fatalf("missing response shape accepted: %T %s", destination, raw)
			}
		}
	}
}

func TestNonTextCommentBodiesAreIncomplete(t *testing.T) {
	for _, raw := range []string{`{"comments":[{"id":"1","body":true}]}`, `{"comments":[{"id":"1","body":123456}]}`} {
		var out jiraCommentPage
		if err := integrityClient(io.NopCloser(strings.NewReader(raw))).get(context.Background(), "/comments", nil, &out); err == nil {
			t.Fatal("non-text comment body silently accepted")
		}
	}
}

func TestClientHTTPGzipChecksumFailureAfterJSON(t *testing.T) {
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	if _, err := w.Write([]byte(`{"issues":[]}`)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	raw := append([]byte(nil), compressed.Bytes()...)
	raw[len(raw)-8] ^= 0xff // Corrupt the CRC after the otherwise complete JSON document.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(raw)
	}))
	defer srv.Close()
	out := jiraSearchPage{Issues: []jiraIssue{{Key: "unchanged"}}}
	if err := NewClient(srv.URL, Auth{}, 0).get(context.Background(), "/search", nil, &out); err == nil {
		t.Fatal("valid JSON prefix concealed a corrupt gzip checksum")
	}
	if out.Issues[0].Key != "unchanged" {
		t.Fatal("failed compressed response changed caller state")
	}
}
