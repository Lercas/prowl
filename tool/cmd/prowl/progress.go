package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Lercas/prowl/tool/internal/model"
)

const (
	progressDelay = time.Second // work faster than this shows nothing
	progressEvery = 200 * time.Millisecond
	// progressGap joins stages that follow each other (clone, then scan) into one run, so the
	// clock keeps going instead of restarting at every stage.
	progressGap = 500 * time.Millisecond
)

// progressMeter draws one status line on a terminal while a long command works: the current stage,
// the items and bytes handed to the scanner, and the elapsed time. Stages may nest and overlap
// (parallel clones in `org`). Image loading takes precedence during lazy reads; otherwise
// the line names the stage that started last and is still running.
type progressMeter struct {
	mu            sync.Mutex
	out           io.Writer
	columns       func() int
	delay, every  time.Duration
	stages        []*progressStage
	started, idle time.Time
	shown         bool
	stop, stopped chan struct{}
	count, size   atomic.Int64
}

type progressStage struct{ label string }

var progress = &progressMeter{out: os.Stderr, delay: progressDelay, every: progressEvery}

// progressEnabled keys on stderr alone: a report redirected to a file or a pipe is exactly the
// long run where a person is left looking at an empty terminal.
func progressEnabled(c commonFlags) bool {
	return !c.quiet && !c.silence && os.Getenv("TERM") != "dumb" && supportsProgressTerminal(os.Stderr)
}

// startStage begins a named stage and returns the function that ends it.
func startStage(c commonFlags, label string) func() {
	if !progressEnabled(c) {
		return func() {}
	}
	return progress.stage(label)
}

func (m *progressMeter) stage(label string) func() {
	entry := &progressStage{label}
	m.mu.Lock()
	if len(m.stages) == 0 {
		if now := time.Now(); now.Sub(m.idle) > progressGap {
			m.started = now
			m.count.Store(0)
			m.size.Store(0)
		}
		m.stop, m.stopped = make(chan struct{}), make(chan struct{})
		go m.loop(m.stop, m.stopped)
	}
	m.stages = append(m.stages, entry)
	m.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { m.end(entry) }) }
}

func (m *progressMeter) end(entry *progressStage) {
	m.mu.Lock()
	found := false
	for i, stage := range m.stages {
		if stage == entry {
			m.stages = append(m.stages[:i], m.stages[i+1:]...)
			found = true
			break
		}
	}
	// A report may finish before a cancelled acquisition goroutine unwinds.
	if !found {
		m.mu.Unlock()
		return
	}
	if len(m.stages) > 0 {
		m.mu.Unlock()
		return
	}
	stop, stopped := m.stop, m.stopped
	m.idle = time.Now()
	m.mu.Unlock()
	close(stop)
	<-stopped
	m.mu.Lock()
	// A new stage can start while the previous loop is joining. Its line belongs to
	// the new loop and must not be erased by this older finish callback.
	if m.stop == stop {
		m.erase()
	}
	m.mu.Unlock()
}

// finish stops rendering before a report or command exit, including when acquisition
// goroutines are still unwinding cancellation. Their late stage callbacks are harmless.
func (m *progressMeter) finish() {
	m.mu.Lock()
	if len(m.stages) == 0 {
		m.erase()
		m.mu.Unlock()
		return
	}
	m.stages = nil
	stop, stopped := m.stop, m.stopped
	m.idle = time.Now()
	m.mu.Unlock()
	close(stop)
	<-stopped
	m.mu.Lock()
	if m.stop == stop {
		m.erase()
	}
	m.mu.Unlock()
}

func (m *progressMeter) loop(stop <-chan struct{}, stopped chan<- struct{}) {
	defer close(stopped)
	ticker := time.NewTicker(m.every)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			m.mu.Lock()
			m.draw(now)
			m.mu.Unlock()
		}
	}
}

// draw ends the line with a carriage return, so anything written next starts at column zero.
func (m *progressMeter) draw(now time.Time) {
	elapsed := now.Sub(m.started)
	if len(m.stages) == 0 || elapsed < m.delay {
		return
	}
	label := m.stages[len(m.stages)-1].label
	// Image metadata returns before lazy layer reads finish. Merely starting the scanner
	// must not hide the acquisition still feeding it.
	for i := len(m.stages) - 1; i >= 0; i-- {
		if m.stages[i].label == "loading image" {
			label = m.stages[i].label
			break
		}
	}
	width := terminalColumns(os.Stderr)
	if m.columns != nil {
		width = m.columns()
	}
	if width <= 0 {
		width = 72
	}
	limit := max(0, width-1)
	duration := elapsed.Round(time.Second).String()
	line := "  " + label + "…"
	if n := m.count.Load(); n > 0 {
		unit := "files"
		if n == 1 {
			unit = "file"
		}
		line += fmt.Sprintf(" %d %s · %s ·", n, unit, humanBytes(m.size.Load()))
	}
	line += " " + duration
	if len([]rune(line)) > limit {
		prefix, suffix := "  ", "… "+duration
		room := max(0, limit-len([]rune(prefix+suffix)))
		runes := []rune(label)
		line = prefix + string(runes[:min(room, len(runes))]) + suffix
		if len([]rune(line)) > limit {
			line = string([]rune(line)[:limit])
		}
	}
	fmt.Fprintf(m.out, "\r\x1b[K%s\r", line)
	m.shown = true
}

func (m *progressMeter) erase() {
	if m.shown {
		fmt.Fprint(m.out, "\r\x1b[K")
		m.shown = false
	}
}

// track counts the items passing to the scanner.
func (m *progressMeter) track(ctx context.Context, items <-chan model.Item) <-chan model.Item {
	out := make(chan model.Item)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case item, ok := <-items:
				if !ok {
					return
				}
				m.count.Add(1)
				m.size.Add(int64(len(item.Text)))
				select {
				case out <- item:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out
}

// scanProgress shows the scanning stage for one item stream; with --verify the same stage also
// waits on providers, and the label says so.
func scanProgress(ctx context.Context, c commonFlags, items <-chan model.Item) (<-chan model.Item, func()) {
	if !progressEnabled(c) {
		return items, func() {}
	}
	label := "scanning"
	if c.verify {
		label = "scanning and verifying"
	}
	return progress.track(ctx, items), progress.stage(label)
}

// progressLog is the log sink on a terminal: a record first clears the status line, so the two
// never share a row.
type progressLog struct {
	meter *progressMeter
	sink  io.Writer
}

func (w progressLog) Write(record []byte) (int, error) {
	w.meter.mu.Lock()
	defer w.meter.mu.Unlock()
	w.meter.erase()
	return w.sink.Write(record)
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
