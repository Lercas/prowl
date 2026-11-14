package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/model"
)

// warnMissingPaths names a mistyped path, with the nearest existing name, before any work starts.
// It only informs: the scan still runs and still fails closed on the missing root, because an
// indexed or multi-root scan must record that outcome rather than lose it.
func warnMissingPaths(paths []string) {
	for _, path := range paths {
		if path == "-" {
			return
		}
		if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) { // #nosec G703 -- This local CLI checks the operator-selected scan path without reading its contents.
			continue
		}
		message := fmt.Sprintf("prowl: path not found: %s", logx.SanitizeTerminal(path))
		if near := nearestSibling(path); near != "" {
			message += fmt.Sprintf("; did you mean '%s'?", logx.SanitizeTerminal(near))
		}
		fmt.Fprintln(os.Stderr, message)
	}
}

// nearestSibling suggests an existing entry of the same directory whose name is a typo away.
func nearestSibling(path string) string {
	dir, name := filepath.Split(filepath.Clean(path))
	lookup := dir
	if lookup == "" {
		lookup = "."
	}
	entries, err := os.ReadDir(lookup)
	if err != nil || len(entries) > 4096 {
		return ""
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if near := closest(name, names); near != "" {
		return dir + near
	}
	return ""
}

// typeKey folds the two spellings of a detector id: rule templates report aws-access-key-id while
// the built-in taxonomy and `prowl detectors` use aws_access_key_id.
func typeKey(id string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(id)), "-", "_")
}

const (
	snippetMaxFile  = 16 << 20 // do not load a larger file just to print one line
	snippetMaxRunes = 140
	snippetLead     = 60 // runes kept before the secret when a long line is cut
)

// sourceLines returns a lookup that renders the source line of a finding with every reported secret
// on that line masked. It answers only for a local file that still matches the scanned snapshot:
// the byte range must lie on the reported line and start with the visible prefix of the redaction.
// Anything else (archive member, git blob, changed file) yields "" and the row stays as it was.
func sourceLines(findings []model.Finding) func(model.Finding) string {
	type key struct {
		path string
		line int
	}
	sameLine := map[key][]model.Finding{}
	for _, f := range findings {
		if f.Line > 0 && f.ByteEnd > f.ByteStart && !model.IsIncompleteFinding(f) {
			k := key{f.Path, f.Line}
			sameLine[k] = append(sameLine[k], f)
		}
	}
	files := map[string][]byte{}
	load := func(path string) []byte {
		if data, ok := files[path]; ok {
			return data
		}
		var data []byte
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Size() <= snippetMaxFile {
			data, _ = os.ReadFile(path)
		}
		files[path] = data
		return data
	}
	return func(f model.Finding) string {
		group := sameLine[key{f.Path, f.Line}]
		if len(group) == 0 || f.Source != "code" {
			return ""
		}
		data := load(f.Path)
		if f.ByteStart < 0 || f.ByteEnd > len(data) {
			return ""
		}
		start := bytes.LastIndexByte(data[:f.ByteStart], '\n') + 1
		end := len(data)
		if i := bytes.IndexByte(data[f.ByteStart:], '\n'); i >= 0 {
			end = f.ByteStart + i
		}
		if bytes.Count(data[:start], []byte{'\n'})+1 != f.Line {
			return ""
		}
		sort.Slice(group, func(i, j int) bool { return group[i].ByteStart < group[j].ByteStart })
		var out strings.Builder
		at, lead := start, -1
		for _, g := range group {
			if g.ByteStart < at || g.ByteStart >= end || g.ByteEnd > len(data) || !redactionFits(g.Redacted, data[g.ByteStart:g.ByteEnd]) {
				if g.ByteStart < at && g.ByteEnd <= at {
					continue // nested inside a range that is already masked
				}
				return "" // one unverifiable range would leave a raw secret on the line
			}
			out.Write(data[at:g.ByteStart])
			if g.ByteStart == f.ByteStart {
				lead = utf8.RuneCountInString(out.String())
			}
			mask, _, _ := strings.Cut(g.Redacted, "\n")
			out.WriteString(mask)
			at = min(g.ByteEnd, end)
		}
		out.Write(data[at:end])
		line := strings.TrimRight(strings.ReplaceAll(out.String(), "\t", " "), " \r")
		trimmed := strings.TrimLeft(line, " ")
		lead -= len(line) - len(trimmed)
		return cutSnippet(trimmed, lead)
	}
}

// redactionFits checks the masked form against the bytes it replaces: the characters shown before
// the first mask symbol must be the first characters of the value.
func redactionFits(redacted string, value []byte) bool {
	visible, _, masked := strings.Cut(redacted, "*")
	if !masked {
		return redacted == string(value) // --show-secrets: the full value
	}
	return bytes.HasPrefix(value, []byte(visible))
}

// cutSnippet keeps a long line readable: a window that starts shortly before the secret.
func cutSnippet(line string, lead int) string {
	runes := []rune(line)
	if len(runes) <= snippetMaxRunes {
		return line
	}
	from := 0
	if lead > snippetLead {
		from = lead - snippetLead
	}
	to := min(from+snippetMaxRunes, len(runes))
	cut := string(runes[from:to])
	if from > 0 {
		cut = "…" + cut
	}
	if to < len(runes) {
		cut += "…"
	}
	return cut
}

const (
	progressDelay = time.Second // a scan faster than this shows nothing
	progressEvery = 200 * time.Millisecond
)

// withProgress shows files and bytes handed to the scanner on a terminal while a long scan runs.
// The line ends with a carriage return, so a log record written meanwhile starts at column zero
// instead of being glued to it; the line is erased before the report is printed.
func withProgress(ctx context.Context, c commonFlags, items <-chan model.Item) <-chan model.Item {
	if !interactiveReport(c) || c.quiet {
		return items
	}
	out := make(chan model.Item)
	var count, size atomic.Int64
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		started := time.Now()
		ticker := time.NewTicker(progressEvery)
		defer ticker.Stop()
		shown := false
		for {
			select {
			case <-done:
				if shown {
					fmt.Fprint(os.Stderr, "\r\x1b[K")
				}
				return
			case now := <-ticker.C:
				if elapsed := now.Sub(started); elapsed >= progressDelay {
					shown = true
					fmt.Fprintf(os.Stderr, "\r\x1b[K  scanning… %d files · %s · %s\r", count.Load(), humanBytes(size.Load()), elapsed.Round(time.Second))
				}
			}
		}
	}()
	go func() {
		defer func() {
			close(done)
			<-finished
			close(out)
		}()
		for {
			select {
			case <-ctx.Done():
				return
			case item, ok := <-items:
				if !ok {
					return
				}
				count.Add(1)
				size.Add(int64(len(item.Text)))
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
