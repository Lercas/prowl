package lsp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"runtime"
	"sync"
	"testing"
	"time"
)

func awaitScan(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("scan did not reach the synchronization barrier")
	}
}

func firePending(d *debouncer, uri string) <-chan struct{} {
	d.mu.Lock()
	revision := d.documents[uri]
	if revision != nil && revision.timer != nil {
		revision.timer.Stop()
	}
	d.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.fire(uri, revision)
	}()
	return done
}

func lifecycleParams(uri, text string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{
		"textDocument":   map[string]any{"uri": uri, "text": text, "version": 1, "languageId": "python"},
		"text":           text,
		"contentChanges": []map[string]any{{"text": text}},
	})
	return b
}

func TestInFlightDiagnosticsSuperseded(t *testing.T) {
	for _, method := range []string{"textDocument/didClose", "textDocument/didOpen", "textDocument/didSave", "textDocument/didChange", "pendingChange", "closeReopen"} {
		t.Run(method, func(t *testing.T) {
			e := newTestEngine(t)
			const uri = "file:///lifecycle.py"
			if len(scanDiagnostics(e, uri, genericSecretLine)) == 0 {
				t.Fatal("fixture secret is not detectable")
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var blockOnce, releaseOnce sync.Once
			e.allow = func(_, _ string) bool {
				blockOnce.Do(func() { close(entered); <-release })
				return false
			}
			var buf bytes.Buffer
			w := newSafeWriter(bufio.NewWriter(&buf))
			d := newDebouncer(e, w, time.Hour)
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); d.stop() })
			if method == "textDocument/didOpen" {
				d.schedule(uri, genericSecretLine)
			} else {
				dispatch(w, e, d, "textDocument/didOpen", nil, documentParams(uri, "", 0))
				if count, last := drainPublishes(t, &buf); count != 1 || hasDiag(last) {
					t.Fatal("initial clean open did not publish")
				}
				buf.Reset()
				dispatch(w, e, d, "textDocument/didChange", nil, documentParams(uri, genericSecretLine, 1))
			}
			oldDone := firePending(d, uri)
			awaitScan(t, entered)
			want := 1
			switch method {
			case "pendingChange":
				d.schedule(uri, "clean")
				want = 0
			case "closeReopen":
				dispatch(w, e, d, "textDocument/didClose", nil, lifecycleParams(uri, ""))
				dispatch(w, e, d, "textDocument/didOpen", nil, lifecycleParams(uri, "clean"))
				want = 2
			default:
				dispatch(w, e, d, method, nil, documentParams(uri, "clean", 2))
				if method == "textDocument/didChange" {
					awaitScan(t, firePending(d, uri))
				}
			}
			releaseOnce.Do(func() { close(release) })
			awaitScan(t, oldDone)
			d.stop()
			count, last := drainPublishes(t, &buf)
			if count != want || hasDiag(last) {
				t.Fatalf("superseded scan published: got %d notifications, last has diagnostics=%v; want %d clean notifications", count, hasDiag(last), want)
			}
		})
	}
}

func TestStoppedDebouncerRejectsScan(t *testing.T) {
	e := newTestEngine(t)
	var buf bytes.Buffer
	w := newSafeWriter(bufio.NewWriter(&buf))
	d := newDebouncer(e, w, time.Hour)
	d.stop()
	d.schedule("file:///stopped.py", genericSecretLine)
	awaitScan(t, firePending(d, "file:///stopped.py"))
	d.immediate("file:///stopped.py", genericSecretLine)
	d.close("file:///stopped.py")
	d.stop()
	if n, _ := drainPublishes(t, &buf); n != 0 {
		t.Fatalf("stopped debouncer published %d notifications", n)
	}
}

func TestExpiredTimerCannotConsumeNewRevision(t *testing.T) {
	e := newTestEngine(t)
	var buf bytes.Buffer
	d := newDebouncer(e, newSafeWriter(bufio.NewWriter(&buf)), time.Hour)
	t.Cleanup(d.stop)
	const uri = "file:///timer.py"
	d.schedule(uri, "old clean text")
	old := d.documents[uri]
	d.schedule(uri, genericSecretLine)
	latest := d.documents[uri]
	d.fire(uri, old)
	if d.documents[uri] != latest || latest.text != genericSecretLine || latest.timer == nil {
		t.Fatal("expired callback consumed the newer pending revision")
	}
	awaitScan(t, firePending(d, uri))
	d.fire(uri, old)
	d.fire(uri, latest)
	d.stop()
	if count, last := drainPublishes(t, &buf); count != 1 || !hasDiag(last) {
		t.Fatalf("latest revision must publish exactly once: count=%d, diagnostics=%v", count, hasDiag(last))
	}
}

func TestInFlightDiagnosticsIndependentDocuments(t *testing.T) {
	e := newTestEngine(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var blockOnce, releaseOnce sync.Once
	e.allow = func(_, path string) bool {
		if path == "/old.py" {
			blockOnce.Do(func() { close(entered); <-release })
		}
		return false
	}
	var buf bytes.Buffer
	w := newSafeWriter(bufio.NewWriter(&buf))
	d := newDebouncer(e, w, time.Hour)
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); d.stop() })
	d.schedule("file:///old.py", genericSecretLine)
	oldDone := firePending(d, "file:///old.py")
	awaitScan(t, entered)
	d.schedule("file:///other.py", genericSecretLine)
	awaitScan(t, firePending(d, "file:///other.py"))
	releaseOnce.Do(func() { close(release) })
	awaitScan(t, oldDone)
	d.stop()
	if count, last := drainPublishes(t, &buf); count != 2 || !hasDiag(last) || last["uri"] != "file:///old.py" {
		t.Fatalf("another document invalidated an active scan: count=%d, uri=%v, diagnostics=%v", count, last["uri"], hasDiag(last))
	}
}

func TestStopDrainsWithoutPublication(t *testing.T) {
	e := newTestEngine(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var blockOnce, releaseOnce sync.Once
	e.allow = func(_, _ string) bool {
		blockOnce.Do(func() { close(entered); <-release })
		return false
	}
	var buf bytes.Buffer
	d := newDebouncer(e, newSafeWriter(bufio.NewWriter(&buf)), time.Hour)
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); d.stop() })
	d.schedule("file:///stop.py", genericSecretLine)
	oldDone := firePending(d, "file:///stop.py")
	awaitScan(t, entered)
	stopped := make(chan struct{})
	go func() { d.stop(); close(stopped) }()
	deadline := time.After(5 * time.Second)
	for {
		d.mu.Lock()
		closing := d.stopped
		d.mu.Unlock()
		if closing {
			break
		}
		select {
		case <-deadline:
			t.Fatal("stop did not invalidate the active scan")
		default:
			runtime.Gosched()
		}
	}
	select {
	case <-stopped:
		t.Fatal("stop returned before the active scan finished")
	default:
	}
	releaseOnce.Do(func() { close(release) })
	awaitScan(t, oldDone)
	awaitScan(t, stopped)
	if count, _ := drainPublishes(t, &buf); count != 0 {
		t.Fatalf("stop allowed %d stale publications", count)
	}
}
