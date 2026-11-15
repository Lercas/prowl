package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/post"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
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

// filePreflight rejects, before any scanning, the file arguments that would otherwise fail only
// when the report is written: a long scan must not end with its result thrown away.
func (c *commonFlags) filePreflight() error {
	if c.baseline != "" {
		if _, err := post.LoadBaseline(c.baseline); err != nil {
			return fmt.Errorf("--baseline %s: %w", c.baseline, err)
		}
	}
	for _, target := range []struct{ flag, path string }{{"--output", c.output}, {"--write-baseline", c.writeBaseline}} {
		if target.path == "" {
			continue
		}
		dir := filepath.Dir(target.path)
		info, err := os.Stat(dir) // #nosec G703 -- The operator names the report destination; only its directory is checked.
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return fmt.Errorf("%s %s: directory %s does not exist", target.flag, target.path, dir)
		case err == nil && !info.IsDir():
			return fmt.Errorf("%s %s: %s is not a directory", target.flag, target.path, dir)
		}
	}
	return nil
}

// codeDefinedTypes are finding types produced by the engine itself rather than by the taxonomy or
// a rule template.
var codeDefinedTypes = []string{"generic_password", "generic_api_key", "generic_high_entropy", "generic_semantic_secret", "basic_auth_header", "private_key_pem", "jwt"}

// warnDisableTypos flags a --disable id that names no detector but is one typo away from a real
// one: a misspelt id disables nothing and the scan would not say so. An id far from every known
// name is left alone, since custom rule packs define their own.
func warnDisableTypos(disable string, known []string) {
	exact := map[string]bool{}
	keys := make([]string, 0, len(known)+len(codeDefinedTypes))
	for _, id := range append(append([]string(nil), known...), codeDefinedTypes...) {
		if key := typeKey(id); !exact[key] {
			exact[key] = true
			keys = append(keys, key)
		}
	}
	for _, id := range splitCSV(disable) {
		if exact[typeKey(id)] {
			continue
		}
		if near := closest(typeKey(id), keys); near != "" {
			fmt.Fprintf(os.Stderr, "prowl: --disable %s matches no detector; did you mean '%s'?\n", id, near)
		}
	}
}

// noDetectors explains a selection that leaves nothing to detect with. Such a scan would inspect
// every file, find nothing by construction and exit 0, which reads as a clean tree.
func noDetectors(c commonFlags, taxonomyTypes int, eng *rules.Engine) string {
	if taxonomyTypes > 0 || eng != nil && eng.Len() > 0 {
		return ""
	}
	if c.rulesOnly {
		return "no detectors are active: --rules-only disables the built-in ones, so pass your own with --rules FILE or --rules-dir DIR"
	}
	return "no detectors are active: the configuration disables every built-in detector and no rule template is selected"
}

// detectorPreflight runs after the detectors are loaded and before any input is read: it stops a
// selection with nothing to detect with and points at flag values that select nothing.
func detectorPreflight(c commonFlags, tax *taxonomy.Taxonomy, eng *rules.Engine) int {
	if problem := noDetectors(c, len(tax.Types), eng); problem != "" {
		fmt.Fprintln(os.Stderr, "prowl:", problem)
		return 2
	}
	if c.tags != "" && eng != nil && eng.Len() == 0 {
		logx.Warn("--tags matched no rule template; only built-in detectors run", "tags", c.tags)
	}
	if c.disable != "" && !c.silence {
		known := make([]string, 0, len(tax.Types))
		for _, secretType := range tax.Types {
			known = append(known, secretType.ID)
		}
		if eng != nil {
			for _, template := range eng.Templates() {
				known = append(known, template.ID)
			}
		}
		warnDisableTypos(c.disable, known)
	}
	return 0
}
