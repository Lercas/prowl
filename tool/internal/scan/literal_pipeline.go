package scan

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
	"github.com/Lercas/prowl/tool/internal/verify"
)

func isJSONItem(it model.Item) bool {
	if !pathIsFilesystem(it.Source) {
		return false
	}
	path := it.Path
	if strings.Contains(path, "://") || strings.HasPrefix(path, "//") {
		path = model.SafeLocator(path)
	}
	return strings.EqualFold(filepath.Ext(path), ".json")
}

func (doc *literalDocument) accepts(typ string, start, end int) bool {
	v := doc.locate(start, end)
	if v == nil || v.noPassword && taxonomy.GenericLast[typ] || v.uiPassword && typ == "generic_password" {
		return false
	}
	return typ != "generic_password" || v.raw || start == v.preparedStart && end == v.preparedEnd
}

func applyLiteralVerify(ctx context.Context, vset *verify.Set, doc *literalDocument, typ, value string, start, end int, original string) (*bool, string) {
	if vset == nil {
		return nil, ""
	}
	if doc == nil {
		return applyVerify(ctx, vset, typ, value, original)
	}
	v := doc.locate(start, end)
	if v == nil || doc.unsafeGroups[v.group] {
		return nil, "verification inconclusive: structured literal could not be established"
	}
	return verificationResult(vset.VerifyLiteral(ctx, typ, value, doc.bindings[v.group], detect.IsExampleOrPlaceholder(value)))
}

func (p *Pipeline) literalFindings(ctx context.Context, it model.Item, doc *literalDocument) []model.Finding {
	prepared := it
	prepared.Text = doc.text
	return p.findings(ctx, prepared, doc)
}

func (p *Pipeline) mapLiteralFindings(fs []model.Finding, it model.Item, doc *literalDocument) {
	for i := range fs {
		f := &fs[i]
		v := doc.locate(f.ByteStart, f.ByteEnd)
		if v == nil {
			continue
		}
		f.ByteStart, f.ByteEnd = doc.sourceSpan(v, f.ByteStart, f.ByteEnd)
		f.Line, f.Col = doc.lines.cols(f.ByteStart)
		f.UTF16Col = doc.lines.utf16Col(f.ByteStart)
		f.IndexLocationID = p.locationFingerprint(it.Source, it.Path, f.Line, f.Col)
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
		}
	}
}
