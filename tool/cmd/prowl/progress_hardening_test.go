package main

import (
	"strings"
	"testing"
	"time"
)

func TestProgressOldLoopCannotEraseANewerStage(t *testing.T) {
	out := &lockedBuffer{}
	entry := &progressStage{label: "old stage"}
	oldStop, oldStopped := make(chan struct{}), make(chan struct{})
	meter := &progressMeter{out: out, delay: 0, every: time.Hour, started: time.Now().Add(-2 * time.Second), stages: []*progressStage{entry}, stop: oldStop, stopped: oldStopped}
	joined := make(chan struct{})
	go func() { meter.end(entry); close(joined) }()
	<-oldStop // The old end is now waiting for its renderer to join.
	finish := meter.stage("new stage")
	meter.mu.Lock()
	meter.draw(time.Now())
	meter.mu.Unlock()
	before := out.String()
	if !strings.Contains(before, "new stage…") {
		t.Fatal("new stage was not drawn")
	}
	close(oldStopped)
	<-joined
	if out.String() != before {
		t.Fatal("an old finish erased the newer stage")
	}
	finish()
}

func TestProgressNarrowTerminalLeavesTheLastColumnUnused(t *testing.T) {
	for _, width := range []int{1, 12, 30, 80} {
		out := &lockedBuffer{}
		meter := &progressMeter{out: out, columns: func() int { return width }, started: time.Now().Add(-2 * time.Second), stages: []*progressStage{{label: "scanning and verifying"}}}
		meter.count.Store(1)
		meter.size.Store(1536)
		meter.draw(time.Now())
		line := strings.TrimSuffix(strings.TrimPrefix(out.String(), "\r\x1b[K"), "\r")
		if len([]rune(line)) >= width {
			t.Fatalf("progress wraps width %d: %q", width, line)
		}
		if width == 80 && !strings.Contains(line, "1 file ·") {
			t.Fatalf("singular item label changed: %q", line)
		}
	}
}

func TestProgressLoadingImageCoversLazyReadsAfterScannerStarts(t *testing.T) {
	out := &lockedBuffer{}
	meter := &progressMeter{out: out, columns: func() int { return 80 }, started: time.Now().Add(-2 * time.Second), stages: []*progressStage{{label: "loading image"}, {label: "scanning and verifying"}}}
	meter.draw(time.Now())
	if !strings.Contains(out.String(), "loading image…") {
		t.Fatal("scanner startup hid the still-running image reader")
	}
}

func TestProgressReportFinishIgnoresLateAcquisitionCallbacks(t *testing.T) {
	out := &lockedBuffer{}
	meter := &progressMeter{out: out, delay: 0, every: time.Hour}
	late := meter.stage("loading image")
	meter.mu.Lock()
	meter.draw(time.Now().Add(time.Second))
	meter.mu.Unlock()
	meter.finish()
	before := out.String()
	if !strings.HasSuffix(before, "\r\x1b[K") {
		t.Fatal("report began before the progress line was erased")
	}
	next := meter.stage("next stage")
	meter.mu.Lock()
	meter.draw(time.Now().Add(time.Second))
	meter.mu.Unlock()
	shown := out.String()
	late()
	late()
	if out.String() != shown {
		t.Fatal("late acquisition completion touched the newer invocation")
	}
	next()
	meter.finish()
}
