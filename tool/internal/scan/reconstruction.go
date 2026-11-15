package scan

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/reconstruct"
)

type reconstructionOrigin struct {
	value reconstruct.Value
	lines *lineIndex
}

func reconstructable(it model.Item) bool {
	switch strings.ToLower(filepath.Ext(model.SafeLocator(it.Path))) {
	case ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx":
		return true
	}
	return false
}

func (p *Pipeline) appendReconstructed(ctx context.Context, it model.Item, out []model.Finding) []model.Finding {
	values, limited := reconstruct.Extract(it.Text)
	if limited {
		model.Note(ctx, "reconstruction_limit", it.Path, true)
	}
	li := newLineIndex(it.Text)
	for _, value := range values {
		if ctx.Err() != nil {
			break
		}
		remaining := *p.options.candidateBudget
		if remaining <= 0 {
			model.Note(ctx, "reconstruction_match_limit", it.Path, true)
			break
		}
		suppressed := li.hasPragma(value.Expression.Start) || li.hasPragma(value.Expression.End-1)
		for _, span := range value.Spans {
			suppressed = suppressed || li.hasPragma(span.Start) || li.hasPragma(span.End-1)
		}
		if !p.options.IgnorePragmas && suppressed {
			model.CoverageFrom(ctx).Filtered()
			continue
		}
		options := p.options
		options.Reconstruct = false
		// Semantic discovery inspects the original source, never each generated expression.
		options.Semantic = false
		options.matchLimit = remaining
		options.reconstruction = &reconstructionOrigin{value: value, lines: li}
		child := it
		child.Text = value.Text
		// A pragma carried by a string is data, not a comment in the original source.
		options.IgnorePragmas = true
		fs := New(options).findings(ctx, child, nil)
		if len(fs) > remaining {
			fs = fs[:remaining]
			model.Note(ctx, "reconstruction_match_limit", it.Path, true)
		}
		out = append(out, fs...)
	}
	return out
}

// Project before observers and ML suppression, so the index never records a
// synthetic location and dropping a candidate cannot rewrite observed history.
func (p *Pipeline) mapReconstructed(fs []model.Finding, it model.Item) {
	origin := p.options.reconstruction
	for i := range fs {
		f := &fs[i]
		f.Line, f.Col = origin.lines.cols(origin.value.Expression.Start)
		f.UTF16Col = origin.lines.utf16Col(origin.value.Expression.Start)
		f.ByteStart, f.ByteEnd = origin.value.Expression.Start, origin.value.Expression.End
		f.IndexLocationID = p.itemLocationFingerprint(it, f.Line, f.Col)
		f.Path, f.URL = model.SafeLocator(f.Path), model.SafeLocator(f.URL)
		f.Stage = "reconstructed/" + f.Stage
		f.Context = nil
		// Existing evidence is relative to the reconstructed value, not the
		// observed file. Preserve its transform chain on the proven expression;
		// the original literal/binding spans below explain that expression.
		for j := range f.Evidence {
			e := &f.Evidence[j]
			e.Path = model.SafeLocator(it.Path)
			e.Start, e.End = origin.value.Expression.Start, origin.value.Expression.End
			e.Line, e.Col = f.Line, f.Col
			e.Transform = "reconstructed/" + origin.value.Transform + "/" + e.Transform
		}
		for _, span := range origin.value.Spans {
			line, col := origin.lines.cols(span.Start)
			f.Evidence = append(f.Evidence, model.Evidence{Path: model.SafeLocator(it.Path), Start: span.Start, End: span.End, Line: line, Col: col, Transform: origin.value.Transform})
		}
		p.annotateOccurrence(f)
	}
}
