// Package logx is the tool's leveled, structured logger over log/slog: a colored console handler,
// a JSON handler for CI, and a silent mode, all switched by --log-format / --log-level / --silence.
package logx

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// LevelSilent disables all output (used by --silence).
const LevelSilent = slog.Level(1000)

type Options struct {
	Level  slog.Level
	Format string // "console" (default) | "json"
	Color  bool
	Out    io.Writer // default os.Stderr
}

var (
	mu  sync.RWMutex
	def = slog.New(newConsoleHandler(os.Stderr, slog.LevelInfo, true))
)

// Setup installs the global logger from Options. Call once at startup after flag parsing.
func Setup(o Options) {
	if o.Out == nil {
		o.Out = os.Stderr
	}
	var h slog.Handler
	switch {
	case o.Level >= LevelSilent:
		h = discardHandler{}
	case o.Format == "json":
		h = slog.NewJSONHandler(o.Out, &slog.HandlerOptions{Level: o.Level})
	default:
		h = newConsoleHandler(o.Out, o.Level, o.Color)
	}
	mu.Lock()
	def = slog.New(h)
	mu.Unlock()
}

func L() *slog.Logger {
	mu.RLock()
	defer mu.RUnlock()
	return def
}

func Debug(msg string, args ...any) { L().Debug(msg, args...) }
func Info(msg string, args ...any)  { L().Info(msg, args...) }
func Warn(msg string, args ...any)  { L().Warn(msg, args...) }
func Error(msg string, args ...any) { L().Error(msg, args...) }

// SanitizeTerminal strips terminal-escape bytes from attacker-controlled text before it is printed:
// C0 controls (0x00–0x1F except TAB) and DEL (0x7F). Dropping ESC blocks any CSI/OSC sequence;
// dropping LF/CR keeps each log/report line single-line. Prowl's own ANSI styling is added afterwards,
// so legitimate colour codes are unaffected. Shared by logx, report, and cmd/prowl.
func SanitizeTerminal(s string) string {
	if strings.IndexFunc(s, isControl) < 0 {
		return s // common case: nothing to strip, avoid an allocation
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if isControl(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// isControl reports whether r is a C0 control char (except TAB) or DEL. LF/CR are stripped too, so an
// attacker can't split a log line / report row to forge a second one.
func isControl(r rune) bool {
	return (r < 0x20 && r != '\t') || r == 0x7f
}

// consoleHandler renders "LEVEL message key=val …" with per-level color.
type consoleHandler struct {
	w     io.Writer
	level slog.Level
	color bool
	attrs []slog.Attr
	mu    *sync.Mutex
}

func newConsoleHandler(w io.Writer, level slog.Level, color bool) *consoleHandler {
	return &consoleHandler{w: w, level: level, color: color, mu: &sync.Mutex{}}
}

func (h *consoleHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level }

func (h *consoleHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(h.tag(r.Level)) // prowl's own colour codes, added before any untrusted text
	b.WriteByte(' ')
	// The message can carry attacker text (interpolated path/url, or passed straight through), so sanitize it.
	b.WriteString(SanitizeTerminal(r.Message))
	// Attr keys are always prowl-authored literals; values are frequently attacker-controlled (path,
	// URL, rationale, wrapped error), so sanitize the rendered value but not the key.
	writeAttr := func(a slog.Attr) bool {
		b.WriteByte(' ')
		b.WriteString(a.Key)
		b.WriteByte('=')
		b.WriteString(SanitizeTerminal(fmt.Sprintf("%v", a.Value.Any())))
		return true
	}
	for _, a := range h.attrs {
		writeAttr(a)
	}
	r.Attrs(writeAttr)
	b.WriteByte('\n')
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, b.String())
	return err
}

func (h *consoleHandler) WithAttrs(as []slog.Attr) slog.Handler {
	nh := *h
	nh.attrs = append(append([]slog.Attr{}, h.attrs...), as...)
	return &nh
}

func (h *consoleHandler) WithGroup(string) slog.Handler { return h }

func (h *consoleHandler) tag(l slog.Level) string {
	name, col := "INFO", "\x1b[36m"
	switch {
	case l >= slog.LevelError:
		name, col = "ERROR", "\x1b[31m"
	case l >= slog.LevelWarn:
		name, col = "WARN", "\x1b[33m"
	case l < slog.LevelInfo:
		name, col = "DEBUG", "\x1b[90m"
	}
	if !h.color {
		return name
	}
	return col + name + "\x1b[0m"
}

type discardHandler struct{}

func (discardHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (discardHandler) Handle(context.Context, slog.Record) error { return nil }
func (discardHandler) WithAttrs([]slog.Attr) slog.Handler        { return discardHandler{} }
func (discardHandler) WithGroup(string) slog.Handler             { return discardHandler{} }
