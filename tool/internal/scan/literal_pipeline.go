package scan

import (
	"context"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
	"github.com/Lercas/prowl/tool/internal/verify"
)

func literalFormat(it model.Item) string {
	if !pathIsFilesystem(it.Source) {
		return ""
	}
	path := it.Path
	if strings.Contains(path, "://") || strings.HasPrefix(path, "//") {
		path = model.SafeLocator(path)
	}
	switch ext := strings.ToLower(filepath.Ext(path)); ext {
	case ".json", ".toml", ".yaml", ".yml":
		return ext
	}
	return ""
}

func parseLiterals(ctx context.Context, it model.Item, capturePublic bool) (doc *literalDocument) {
	defer func() {
		if doc != nil {
			complete, _, _ := model.CoverageFrom(ctx).Snapshot()
			doc.verificationUnsafe = !complete
		}
	}()
	switch literalFormat(it) {
	case ".json":
		return jsonLiteralsWithPublic(ctx, it, capturePublic)
	case ".toml":
		return tomlLiteralsWithPublic(ctx, it, capturePublic)
	case ".yaml", ".yml":
		return yamlLiteralsWithPublic(ctx, it, capturePublic)
	}
	return nil
}

func (doc *literalDocument) accepts(typ string, start, end int, contextualPassword bool) bool {
	v := doc.locate(start, end)
	if v == nil || v.noPassword && taxonomy.GenericLast[typ] || v.uiPassword && typ == "generic_password" {
		return false
	}
	return typ != "generic_password" || v.raw || start == v.preparedStart && end == v.preparedEnd || contextualPassword && doc.scalars[v.preparedStart].Prose
}

func applyLiteralVerify(ctx context.Context, vset *verify.Set, doc *literalDocument, typ, value string, start, end int, original string, tuning ...*detect.Tuning) (*bool, string, *model.Verification) {
	if vset == nil {
		return nil, "", nil
	}
	if doc == nil {
		return applyVerify(ctx, vset, typ, value, original, tuning...)
	}
	v := doc.locate(start, end)
	if v == nil || doc.verificationUnsafe || doc.unsafeGroups[v.group] {
		return verificationResult(verify.Result{Status: verify.Errored, Note: "structured literal could not be established"})
	}
	return verificationResult(vset.VerifyLiteral(ctx, typ, value, doc.bindings[v.group], verificationExample(value, tuning...)))
}

func (p *Pipeline) literalFindings(ctx context.Context, it model.Item, doc *literalDocument) []model.Finding {
	prepared := it
	prepared.Text = doc.text
	fs := p.findings(ctx, prepared, doc)
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].ByteStart != fs[j].ByteStart {
			return fs[i].ByteStart < fs[j].ByteStart
		}
		return fs[i].ByteEnd < fs[j].ByteEnd
	})
	return fs
}

func (p *Pipeline) mapLiteralFindings(fs []model.Finding, it model.Item, doc *literalDocument) {
	for i := range fs {
		f := &fs[i]
		v := doc.locate(f.ByteStart, f.ByteEnd)
		if v == nil {
			continue
		}
		for j := range f.Evidence {
			e := &f.Evidence[j]
			if strings.HasPrefix(e.Transform, "base64-decode") || e.Transform == "gzip-inflate" || e.Transform == "zlib-inflate" || e.Transform == "hex-decode" || e.Transform == "text-normalize" || e.Transform == "percent-html-decode" || e.Transform == "charcode-decode" || e.Transform == "literal-semantic-span" {
				if original := doc.locate(e.Start, e.End); original != nil {
					e.Start, e.End = doc.sourceSpan(original, e.Start, e.End)
					e.Line, e.Col = doc.lines.cols(e.Start)
				}
			}
		}
		var declarationMatch *model.Evidence
		if v.whole {
			declaration := *v
			declaration.whole = false
			start, end := doc.sourceSpan(&declaration, f.ByteStart, f.ByteEnd)
			line, col := doc.lines.cols(start)
			declarationMatch = &model.Evidence{Path: model.SafeLocator(it.Path), Start: start, End: end, Line: line, Col: col, Transform: "yaml-definition-match"}
		}
		f.ByteStart, f.ByteEnd = doc.sourceSpan(v, f.ByteStart, f.ByteEnd)
		f.Line, f.Col = doc.lines.cols(f.ByteStart)
		f.UTF16Col = doc.lines.utf16Col(f.ByteStart)
		f.IndexLocationID = p.itemLocationFingerprint(it, f.Line, f.Col)
		f.Context = nil // Synthetic source is never presented as the observed source.
		if !v.raw {
			transform := doc.transform
			if v.transform != "" {
				transform = v.transform
			}
			f.Stage = "normalized/" + transform + "/" + f.Stage
			line, col := doc.lines.cols(v.start)
			f.Evidence = append(f.Evidence, model.Evidence{Path: model.SafeLocator(it.Path), Start: v.start, End: v.end, Line: line, Col: col, Transform: transform})
			f.Evidence = append(f.Evidence, v.proof...)
			if declarationMatch != nil {
				f.Evidence = append(f.Evidence, *declarationMatch)
			}
		}
		p.annotateOccurrence(f)
	}
}
