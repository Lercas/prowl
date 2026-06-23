package rules

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Lercas/prowl/tool/internal/ahocorasick"
	"github.com/Lercas/prowl/tool/internal/logx"
	"gopkg.in/yaml.v3"
)

// Engine holds compiled templates and runs them over text. Read-only after Load/Filter; the
// Aho-Corasick keyword index is built lazily on first Match.
type Engine struct {
	templates []*Template

	index   sync.Once
	ac      *ahocorasick.Matcher
	kwTpls  [][]int32 // keyword id -> template indices that anchor on it
	always  []int32   // templates with no word anchor
	present sync.Pool
}

// Len reports how many templates are loaded.
func (e *Engine) Len() int { return len(e.templates) }

// Templates exposes the loaded templates.
func (e *Engine) Templates() []*Template { return e.templates }

// Load reads every template under the given files/dirs (dirs walked recursively for *.yaml/*.yml;
// multi-document files are decoded as a proper YAML stream, one Template per document). Invalid
// templates are collected into the returned error.
func Load(paths ...string) (*Engine, error) {
	e := &Engine{}
	var errs []string
	seen := map[string]string{} // rule id -> first path it was defined in, for duplicate detection
	add := func(path string) {
		raw, err := readTemplateFile(path)
		if err != nil {
			errs = append(errs, err.Error())
			return
		}
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		for {
			var t Template
			if err := dec.Decode(&t); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				errs = append(errs, fmt.Sprintf("%s: %v", path, err))
				break // a stream-level decode error invalidates the rest of the file
			}
			if t.isZero() {
				continue // skip an empty document (e.g. a trailing "---")
			}
			t.path = path
			if err := t.compile(); err != nil {
				errs = append(errs, err.Error())
				continue
			}
			// Reject a duplicate rule id (matching ValidateDir): skip the later copy so its matches
			// aren't double-reported, and both warn and record it so the skip isn't silent. Skipping
			// (not just erroring) matters because the engine is used even when Load returns an error.
			if t.ID != "" {
				if prev, dup := seen[t.ID]; dup {
					logx.Warn("duplicate rule id; ignoring the later definition", "id", t.ID, "kept", prev, "ignored", path)
					errs = append(errs, fmt.Sprintf("%s: duplicate rule id %q (also defined in %s); ignoring this copy", path, t.ID, prev))
					continue
				}
				seen[t.ID] = path
			}
			e.templates = append(e.templates, &t)
		}
	}
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if info.IsDir() {
			_ = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				if ext := strings.ToLower(filepath.Ext(path)); ext == ".yaml" || ext == ".yml" {
					add(path)
				}
				return nil
			})
		} else {
			add(p)
		}
	}
	if len(errs) > 0 {
		return e, fmt.Errorf("%d template error(s):\n  %s", len(errs), strings.Join(errs, "\n  "))
	}
	return e, nil
}

// readTemplateFile reads a template file, rejecting one over MaxTemplateSize so a giant file can't be
// loaded and parsed.
func readTemplateFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > MaxTemplateSize {
		return nil, fmt.Errorf("%s: template file too large (%d bytes > %d limit)", path, info.Size(), MaxTemplateSize)
	}
	return os.ReadFile(path)
}

// FilterOpts selects which templates run via include/exclude by tag, severity, and id.
type FilterOpts struct {
	Tags        []string // include only templates with ANY of these tags
	ExcludeTags []string // drop templates with ANY of these tags
	Severities  []string // include only these severities
	IDs         []string // include only these ids
	ExcludeIDs  []string
}

// Filter applies the selection in-place and returns the engine for chaining.
func (e *Engine) Filter(o FilterOpts) *Engine {
	if o.Tags == nil && o.ExcludeTags == nil && o.Severities == nil && o.IDs == nil && o.ExcludeIDs == nil {
		return e
	}
	kept := e.templates[:0]
	for _, t := range e.templates {
		if len(o.IDs) > 0 && !contains(o.IDs, t.ID) {
			continue
		}
		if contains(o.ExcludeIDs, t.ID) {
			continue
		}
		if len(o.Severities) > 0 && !contains(o.Severities, strings.ToLower(t.Info.Severity)) {
			continue
		}
		tags := t.TagList()
		if len(o.Tags) > 0 && !anyShared(tags, o.Tags) {
			continue
		}
		if len(o.ExcludeTags) > 0 && anyShared(tags, o.ExcludeTags) {
			continue
		}
		kept = append(kept, t)
	}
	e.templates = kept
	return e
}

// buildIndex compiles the Aho-Corasick keyword index once.
func (e *Engine) buildIndex() {
	var kws []string
	seen := map[string]int{}
	for ti, t := range e.templates {
		anchors := t.Keywords()
		if len(anchors) == 0 {
			e.always = append(e.always, int32(ti))
			continue
		}
		for _, k := range anchors {
			k = strings.ToLower(k)
			id, ok := seen[k]
			if !ok {
				id = len(kws)
				seen[k] = id
				kws = append(kws, k)
				e.kwTpls = append(e.kwTpls, nil)
			}
			e.kwTpls[id] = append(e.kwTpls[id], int32(ti))
		}
	}
	e.ac = ahocorasick.New(kws)
	e.present = sync.Pool{New: func() any { s := make([]bool, len(kws)); return &s }}
}

// MaxEngineMatches caps a single Match call so a dense file matching a permissive template can't build
// an unbounded []Hit. It mirrors detect.maxScanMatches (50000) but stays local so rules need not
// import detect; scan.Findings passes its own combined budget via MatchN.
const MaxEngineMatches = 50000

// Match runs the templates over text and returns all hits, bounded by MaxEngineMatches. It is the
// signature-stable entry point for the LSP / rules UI; scan.Findings uses MatchN with its own budget.
func (e *Engine) Match(text string) []Hit {
	hits, _ := e.MatchN(text, MaxEngineMatches)
	return hits
}

// MatchN runs the templates over text and returns up to limit hits, plus a bool reporting truncation.
// One Aho-Corasick pass finds the present anchor words; only templates whose anchor matched (plus
// anchor-less ones) run, and extraction stops once the running total reaches limit. A limit <= 0
// produces nothing (the combined cap is already exhausted upstream).
func (e *Engine) MatchN(text string, limit int) ([]Hit, bool) {
	if len(e.templates) == 0 || limit <= 0 {
		return nil, false
	}
	e.index.Do(e.buildIndex)
	lower := strings.ToLower(text)

	pp := e.present.Get().(*[]bool)
	present := *pp
	for i := range present {
		present[i] = false
	}
	e.ac.MatchInto(lower, present)

	active := make([]bool, len(e.templates))
	for _, ti := range e.always {
		active[ti] = true
	}
	for id, ok := range present {
		if ok {
			for _, ti := range e.kwTpls[id] {
				active[ti] = true
			}
		}
	}
	e.present.Put(pp)

	var hits []Hit
	truncated := false
	for ti, t := range e.templates {
		if !active[ti] {
			continue
		}
		// Cap each template's contribution to the remaining budget so no template can push the combined
		// slice past the cap; matchN stops its FindAll walk early.
		th, ttrunc := t.matchN(text, lower, limit-len(hits))
		hits = append(hits, th...)
		if ttrunc || len(hits) >= limit {
			truncated = true
			if len(hits) > limit {
				hits = hits[:limit]
			}
			break
		}
	}
	return hits, truncated
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

func anyShared(a, b []string) bool {
	for _, x := range a {
		if contains(b, x) {
			return true
		}
	}
	return false
}
