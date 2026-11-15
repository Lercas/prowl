package scan

import (
	"context"
	"sort"
	"strings"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/rules"
)

type ruleCandidate struct {
	rules.Hit
	payload *jwtRuleContext
}

type jwtRuleContext struct {
	view  detect.JWTPayloadView
	doc   *literalDocument // nil for the original JSON spelling
	start int              // scoring offset before projection to the encoded source
}

func (h ruleCandidate) record(it model.Item, outer *literalDocument) mlscore.Record {
	if h.payload != nil {
		it.Text = h.payload.view.Text
		if doc := h.payload.doc; doc != nil {
			it.Text = doc.text
			return doc.recordFor(h.Value, it, h.payload.start, h.RuleID)
		}
		record := recordFor(h.Value, it, h.payload.start)
		if name := detect.BindingName(it.Text, h.payload.start); name != "" {
			record.Context.Name = name
		}
		return record
	}
	if outer != nil {
		return outer.recordFor(h.Value, it, h.Start, h.RuleID)
	}
	return recordFor(h.Value, it, h.Start)
}

// Match the raw object for structural templates, and additionally its logical
// strings when JSON escapes change the spelling. Synthetic wrappers never become
// credential values: normalized extractor spans must lie within one scalar.
func (p *Pipeline) ruleCandidates(ctx context.Context, it model.Item, views []detect.JWTPayloadView, limit int) ([]ruleCandidate, bool) {
	engine := p.options.Rules
	match := engine.MatchN
	if p.options.ValueFingerprint != nil || p.options.AllOccurrences {
		match = engine.MatchOccurrencesN
	}
	hits, limited := match(it.Text, limit)
	work := len(hits)
	out := make([]ruleCandidate, 0, len(hits))
	for _, hit := range hits {
		out = append(out, ruleCandidate{Hit: hit})
	}
	if len(views) == 0 {
		return out, limited
	}
	type identity struct {
		rule, value string
		start, end  int
	}
	seen := map[identity]bool{}
	for _, view := range views {
		if ctx.Err() != nil {
			return out, true
		}
		if work >= limit {
			return out, true
		}
		var doc *literalDocument
		var escaped []detect.JWTPayloadString
		if strings.Contains(view.Text, "\\") {
			values, capped := view.Strings(ctx)
			limited = limited || capped
			doc = &literalDocument{original: view.Text, lines: newLineIndex(view.Text), transform: "json-string"}
			doc.lines.resetPragmas()
			for _, value := range values {
				doc.values = append(doc.values, sourceLiteral{name: value.Name, value: value.Value, start: value.Start, end: value.End})
				if value.Escaped {
					escaped = append(escaped, value)
				}
			}
			doc.prepare()
		}
		for _, normalized := range []bool{false, true} {
			if normalized && doc == nil {
				continue
			}
			text := view.Text
			if normalized {
				text = doc.text
			}
			if work >= limit {
				return out, true
			}
			local, capped := match(text, limit-work)
			work += len(local)
			limited = limited || capped
			for _, hit := range local {
				logicalStart := hit.Start
				var localDoc *literalDocument
				if normalized {
					v := doc.locate(hit.Start, hit.End)
					if v == nil {
						continue
					}
					hit.Start, hit.End = doc.sourceSpan(v, hit.Start, hit.End)
					localDoc = doc
				} else {
					i := sort.Search(len(escaped), func(i int) bool { return escaped[i].End > hit.Start })
					if i < len(escaped) && escaped[i].Start < hit.End {
						continue
					}
				}
				hit.Start, hit.End = view.SourceSpan(hit.Start, hit.End)
				key := identity{hit.RuleID, hit.Value, hit.Start, hit.End}
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, ruleCandidate{Hit: hit, payload: &jwtRuleContext{view: view, doc: localDoc, start: logicalStart}})
			}
		}
	}
	return out, limited
}
