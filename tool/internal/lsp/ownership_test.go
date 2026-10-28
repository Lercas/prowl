package lsp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strconv"
	"sync"
	"testing"
	"time"
)

func documentParams(uri, text string, version int32) json.RawMessage {
	b, _ := json.Marshal(map[string]any{
		"textDocument": map[string]any{"uri": uri, "text": text, "version": version, "languageId": "python"},
		"text":         text, "contentChanges": []map[string]any{{"text": text}},
	})
	return b
}

func TestStaleChangesAndDuplicateOpenPreserveRevision(t *testing.T) {
	for _, state := range []string{"published", "pending", "in-flight"} {
		for _, event := range []string{"older-change", "equal-change", "duplicate-open"} {
			t.Run(state+"/"+event, func(t *testing.T) {
				e := newTestEngine(t)
				var buf bytes.Buffer
				w := newSafeWriter(bufio.NewWriter(&buf))
				d := newDebouncer(e, w, time.Hour)
				const uri = "file:///version.py"
				entered, release := make(chan struct{}), make(chan struct{})
				var releaseOnce sync.Once
				t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); d.stop() })
				var done <-chan struct{}
				if state == "published" {
					dispatch(w, e, d, "textDocument/didOpen", nil, documentParams(uri, genericSecretLine, 5))
				} else {
					dispatch(w, e, d, "textDocument/didOpen", nil, documentParams(uri, "", 1))
					if count, last := drainPublishes(t, &buf); count != 1 || hasDiag(last) {
						t.Fatal("initial clean document was not published")
					}
					buf.Reset()
					dispatch(w, e, d, "textDocument/didChange", nil, documentParams(uri, genericSecretLine, 5))
					if state == "in-flight" {
						var blockOnce sync.Once
						e.allow = func(_, _ string) bool {
							blockOnce.Do(func() { close(entered); <-release })
							return false
						}
						done = firePending(d, uri)
						awaitScan(t, entered)
					}
				}
				d.mu.Lock()
				previous := d.documents[uri]
				d.mu.Unlock()
				method, version := "textDocument/didChange", int32(4)
				switch event {
				case "equal-change":
					version = 5
				case "duplicate-open":
					method, version = "textDocument/didOpen", 100
				}
				dispatch(w, e, d, method, nil, documentParams(uri, "", version))
				d.mu.Lock()
				preserved := d.documents[uri] == previous
				d.mu.Unlock()
				if !preserved {
					t.Fatal("stale or unbalanced notification invalidated the current revision")
				}
				if state == "pending" {
					awaitScan(t, firePending(d, uri))
				}
				releaseOnce.Do(func() { close(release) })
				if done != nil {
					awaitScan(t, done)
				}
				d.stop()
				if count, last := drainPublishes(t, &buf); count != 1 || !hasDiag(last) {
					t.Fatal("stale event cleared or superseded the latest diagnostics")
				}
			})
		}
	}
}

func TestClosedDocumentEventsCannotResurrectDiagnostics(t *testing.T) {
	for _, opened := range []bool{false, true} {
		for _, method := range []string{"textDocument/didChange", "textDocument/didSave", "textDocument/didClose"} {
			t.Run(method+"/previouslyOpened="+strconv.FormatBool(opened), func(t *testing.T) {
				e := newTestEngine(t)
				var buf bytes.Buffer
				w := newSafeWriter(bufio.NewWriter(&buf))
				d := newDebouncer(e, w, time.Hour)
				t.Cleanup(d.stop)
				const uri = "file:///closed.py"
				if opened {
					dispatch(w, e, d, "textDocument/didOpen", nil, documentParams(uri, "", 1))
					dispatch(w, e, d, "textDocument/didClose", nil, documentParams(uri, "", 1))
					if count, last := drainPublishes(t, &buf); count != 2 || hasDiag(last) {
						t.Fatal("balanced close did not clear diagnostics")
					}
					buf.Reset()
				}
				dispatch(w, e, d, method, nil, documentParams(uri, genericSecretLine, 2))
				d.mu.Lock()
				hasRevision := len(d.documents) != 0
				d.mu.Unlock()
				if hasRevision {
					t.Fatal("closed document acquired a new scan revision")
				}
				d.stop()
				if count, _ := drainPublishes(t, &buf); count != 0 {
					t.Fatal("event for a closed document published diagnostics")
				}
			})
		}
	}
}

func TestVersionJumpsEmptyChangesAndReopen(t *testing.T) {
	e := newTestEngine(t)
	var buf bytes.Buffer
	w := newSafeWriter(bufio.NewWriter(&buf))
	d := newDebouncer(e, w, time.Hour)
	t.Cleanup(d.stop)
	const uri = "file:///epoch.py"
	dispatch(w, e, d, "textDocument/didOpen", nil, documentParams(uri, "", -3))
	_, _ = drainPublishes(t, &buf)
	buf.Reset()
	dispatch(w, e, d, "textDocument/didChange", nil, documentParams(uri, genericSecretLine, 7))
	params, _ := json.Marshal(map[string]any{
		"textDocument": map[string]any{"uri": uri, "version": 100}, "contentChanges": []any{},
	})
	dispatch(w, e, d, "textDocument/didChange", nil, params)
	dispatch(w, e, d, "textDocument/didChange", nil, documentParams(uri, "", 99))
	awaitScan(t, firePending(d, uri))
	if count, last := drainPublishes(t, &buf); count != 1 || !hasDiag(last) {
		t.Fatal("empty change lost the pending snapshot or allowed an older version to replace it")
	}
	buf.Reset()
	dispatch(w, e, d, "textDocument/didChange", nil, documentParams(uri, "", 101))
	awaitScan(t, firePending(d, uri))
	if count, last := drainPublishes(t, &buf); count != 1 || hasDiag(last) {
		t.Fatal("newer clean change was not accepted")
	}
	buf.Reset()
	dispatch(w, e, d, "textDocument/didClose", nil, documentParams(uri, "", 101))
	dispatch(w, e, d, "textDocument/didOpen", nil, documentParams(uri, genericSecretLine, -2147483648))
	if count, last := drainPublishes(t, &buf); count != 2 || !hasDiag(last) {
		t.Fatal("reopened document could not start a new version sequence")
	}
}

func TestInvalidChangeDoesNotConsumeItsVersion(t *testing.T) {
	for _, changes := range []json.RawMessage{json.RawMessage(`null`), json.RawMessage(`[{}]`), json.RawMessage(`[{"text":"","range":null}]`)} {
		t.Run(string(changes), func(t *testing.T) {
			e := newTestEngine(t)
			var buf bytes.Buffer
			w := newSafeWriter(bufio.NewWriter(&buf))
			d := newDebouncer(e, w, time.Hour)
			t.Cleanup(d.stop)
			const uri = "file:///invalid-version.py"
			dispatch(w, e, d, "textDocument/didOpen", nil, documentParams(uri, "", 1))
			_, _ = drainPublishes(t, &buf)
			buf.Reset()
			params, _ := json.Marshal(map[string]any{
				"textDocument": map[string]any{"uri": uri, "version": 100}, "contentChanges": changes,
			})
			dispatch(w, e, d, "textDocument/didChange", nil, params)
			dispatch(w, e, d, "textDocument/didChange", nil, documentParams(uri, genericSecretLine, 2))
			awaitScan(t, firePending(d, uri))
			d.stop()
			if count, last := drainPublishes(t, &buf); count != 1 || !hasDiag(last) {
				t.Fatal("malformed change consumed the document version")
			}
		})
	}
}
