package scan

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/reconstruct"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/verify"
)

func reconstructed(ctx context.Context, det *detect.Detector, eng *rules.Engine, vset *verify.Set, it model.Item, allow func(string, string) bool, ml mlscore.Scorer) []model.Finding {
	switch strings.ToLower(filepath.Ext(model.SafeLocator(it.Path))) {
	case ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx":
	default:
		return nil
	}
	values, limited := reconstruct.Extract(it.Text)
	if limited {
		model.Note(ctx, "reconstruction_limit", it.Path, true)
	}
	options := optionsFrom(ctx)
	options.Reconstruct = false
	options.Semantic = false
	li := newLineIndex(it.Text)
	var out []model.Finding
	for _, v := range values {
		if len(out) >= detect.MaxScanMatches() {
			model.Note(ctx, "reconstruction_match_limit", it.Path, true)
			break
		}
		if ctx.Err() != nil {
			break
		}
		if len(v.Spans) == 0 {
			continue
		}
		suppressed := li.hasPragma(v.Expression.Start) || li.hasPragma(v.Expression.End-1)
		for _, span := range v.Spans {
			suppressed = suppressed || li.hasPragma(span.Start) || li.hasPragma(span.End-1)
		}
		if suppressed {
			model.CoverageFrom(ctx).Filtered()
			continue
		}
		meta := map[string]any{"verification_context": it.Text}
		for k, x := range it.Meta {
			meta[k] = x
		}
		child := model.Item{Text: v.Text, Source: it.Source, Path: it.Path, Meta: meta}
		childCoverage := model.NewCoverage()
		childCtx := WithOptions(model.WithCoverage(ctx, childCoverage), options)
		fs := Findings(childCtx, det, eng, vset, child, allow, ml)
		_, _, diagnostics := childCoverage.Snapshot()
		if model.NewResult(nil, childCoverage).Filtered {
			model.CoverageFrom(ctx).Filtered()
		}
		for _, d := range diagnostics {
			model.Note(ctx, d.Code, d.Path, d.Incomplete)
		}
		remaining := detect.MaxScanMatches() - len(out)
		if len(fs) > remaining {
			fs = fs[:remaining]
			model.Note(ctx, "reconstruction_match_limit", it.Path, true)
		}
		for i := range fs {
			fs[i].Line, fs[i].Col = li.cols(v.Expression.Start)
			fs[i].ByteStart, fs[i].ByteEnd = v.Expression.Start, v.Expression.End
			fs[i].Stage = "reconstructed/" + fs[i].Stage
			fs[i].Context = nil // a reconstructed value has no single original plaintext line
			for _, s := range v.Spans {
				line, col := li.cols(s.Start)
				fs[i].Evidence = append(fs[i].Evidence, model.Evidence{Path: model.SafeLocator(it.Path), Start: s.Start, End: s.End, Line: line, Col: col, Transform: v.Transform})
			}
			annotateOccurrence(childCtx, &fs[i])
		}
		out = append(out, fs...)
	}
	return out
}
