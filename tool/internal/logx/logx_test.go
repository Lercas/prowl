package logx

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestConsoleLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	Setup(Options{Level: slog.LevelInfo, Format: "console", Color: false, Out: &buf})
	Debug("hidden")
	Info("shown", "count", 3)
	Warn("careful")
	out := buf.String()
	if strings.Contains(out, "hidden") {
		t.Error("debug should be filtered at info level")
	}
	if !strings.Contains(out, "INFO shown count=3") {
		t.Errorf("info line malformed: %q", out)
	}
	if !strings.Contains(out, "WARN careful") {
		t.Error("warn missing")
	}
}

func TestJSONFormat(t *testing.T) {
	var buf bytes.Buffer
	Setup(Options{Level: slog.LevelInfo, Format: "json", Out: &buf})
	Info("event", "host", "acme.com")
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("not valid JSON: %v (%q)", err, buf.String())
	}
	if rec["msg"] != "event" || rec["host"] != "acme.com" || rec["level"] != "INFO" {
		t.Errorf("json fields wrong: %v", rec)
	}
}

func TestSilentMode(t *testing.T) {
	var buf bytes.Buffer
	Setup(Options{Level: LevelSilent, Out: &buf})
	Info("nope")
	Error("also nope")
	if buf.Len() != 0 {
		t.Errorf("silent mode emitted %q", buf.String())
	}
}

func TestColorTags(t *testing.T) {
	var buf bytes.Buffer
	Setup(Options{Level: slog.LevelDebug, Format: "console", Color: true, Out: &buf})
	Error("boom")
	if !strings.Contains(buf.String(), "\x1b[31m") {
		t.Error("error should be colored red when color enabled")
	}
}
