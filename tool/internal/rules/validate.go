package rules

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Issue is one validation problem (Level "error" blocks; "warn" is advisory).
type Issue struct {
	Path  string
	Rule  string
	Level string
	Msg   string
}

var validSeverity = map[string]bool{
	"info": true, "low": true, "medium": true, "high": true, "critical": true,
}

// ValidateDir parses and lint-checks every template under the given files/dirs, returning every
// issue found without failing fast.
func ValidateDir(paths ...string) []Issue {
	var issues []Issue
	seen := map[string]string{} // id -> path, for duplicate detection
	walk(paths, func(path string, raw []byte) {
		if len(raw) > MaxTemplateSize { // refuse an oversized (possibly hostile) file pre-install
			issues = append(issues, Issue{path, "", "error",
				fmt.Sprintf("template file too large (%d bytes > %d limit)", len(raw), MaxTemplateSize)})
			return
		}
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		// docN counts only non-skipped documents so the diagnostic suffix names the right doc even
		// when empty documents are interleaved.
		docN := 0
		for {
			var t Template
			if err := dec.Decode(&t); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				issues = append(issues, Issue{path, "", "error", "unparseable YAML: " + err.Error()})
				break // a stream-level decode error invalidates the rest of the file
			}
			if t.isZero() {
				continue // skip an empty document (e.g. a trailing "---")
			}
			where := path
			if docN > 0 {
				where = fmt.Sprintf("%s#doc%d", path, docN)
			}
			docN++
			issues = append(issues, lintTemplate(&t, where, seen)...)
		}
	})
	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].Level != issues[j].Level {
			return issues[i].Level == "error" // errors first
		}
		return issues[i].Path < issues[j].Path
	})
	return issues
}

func lintTemplate(t *Template, where string, seen map[string]string) []Issue {
	var out []Issue
	add := func(level, msg string) { out = append(out, Issue{where, t.ID, level, msg}) }

	if t.ID == "" {
		add("error", "missing id")
	} else if prev, dup := seen[t.ID]; dup {
		add("error", fmt.Sprintf("duplicate id (also in %s)", prev))
	} else {
		seen[t.ID] = where
	}
	if t.Info.Name == "" {
		add("error", "missing info.name")
	}
	if t.Info.Severity == "" {
		add("error", "missing info.severity")
	} else if !validSeverity[strings.ToLower(t.Info.Severity)] {
		add("error", "invalid severity "+t.Info.Severity+" (info|low|medium|high|critical)")
	}
	if t.Info.Tags == "" {
		add("warn", "no tags — cannot be selected with --tags")
	}
	if t.Category == "" {
		add("warn", "no category — severity falls back to medium")
	}
	if len(t.Matchers) == 0 {
		add("error", "no matchers")
	}

	if err := t.compile(); err != nil {
		add("error", err.Error())
		return out // can't lint further without compiled regexes
	}

	// Every word anchor should appear in some regex, else the pre-filter can hide matches.
	var regexBlob strings.Builder
	for _, m := range t.Matchers {
		for _, rx := range m.Regex {
			regexBlob.WriteString(strings.ToLower(rx))
		}
	}
	blob := regexBlob.String()
	for _, m := range t.Matchers {
		if m.Type != "word" || m.Negative {
			continue
		}
		for _, w := range m.Words {
			if blob != "" && !strings.Contains(blob, strings.ToLower(w)) {
				add("warn", fmt.Sprintf("anchor word %q not found in any regex — pre-filter may hide matches", w))
			}
		}
	}
	if len(t.extractRes()) == 0 {
		for _, m := range t.Matchers {
			if m.Type == "entropy" {
				add("warn", "entropy matcher but no regex/extractor to produce a value")
			}
		}
	}
	return out
}

func walk(paths []string, fn func(path string, raw []byte)) {
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			fn(p, nil)
			continue
		}
		if info.IsDir() {
			_ = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				if ext := strings.ToLower(filepath.Ext(path)); ext == ".yaml" || ext == ".yml" {
					if raw, err := os.ReadFile(path); err == nil {
						fn(path, raw)
					}
				}
				return nil
			})
		} else if raw, err := os.ReadFile(p); err == nil {
			fn(p, raw)
		}
	}
}
