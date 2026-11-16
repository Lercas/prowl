package detect

import (
	"context"
	"strings"
)

func jwtViewCarrierByte(c byte) bool {
	return base64Byte(c) || c == '.' || c == '=' || c == '\\' || c == '%' || c == '&' || c == '#' || c == ';'
}

func (v *view) sourceSpan(start, end int) (int, int) {
	if start >= 0 && end > start && end <= len(v.start) {
		return int(v.start[start]), int(v.end[end-1])
	}
	return 0, 0
}

// Inspect only containers and encoded containers, without recursively applying
// a normalization to its own output or enabling ordinary generic detection.
func (d *Detector) jwtMappedView(ctx context.Context, v *view, transform string, opts ScanOptions) ([]Match, bool) {
	if v == nil || ctx.Err() != nil {
		return nil, false
	}
	if opts.jwtBudget == nil {
		opts.jwtBudget = &jwtPayloadBudget{}
	}
	budget := opts.jwtBudget
	if opts.jwtViewDepth >= maxDecodeDepth || len(v.text) > maxViewBytes-budget.viewBytes || v.constructs > maxViewConstructs-budget.viewConstructs {
		return nil, true
	}
	budget.viewBytes += len(v.text)
	budget.viewConstructs += v.constructs
	local := opts
	local.jwtViewDepth++
	local.jwtOrigin = &jwtViewOrigin{parent: opts.jwtOrigin, normalized: v, normalization: transform, end: len(v.text)}
	children, limited := d.jwtPayloadFindings(ctx, v.text, nil, local)
	local.jwtOnly = true
	_, encoded, capped := d.base64OccurrencesWithJWT(ctx, v.text, local)
	children, mergedLimited := d.Tuning().mergeJWTPayloadMatches(children, encoded)
	for i := range children {
		m := &children[i]
		left, right := v.sourceSpan(m.jwtContainer.Start, m.jwtContainer.End)
		steps := []DecodeStep{{left, right, transform}}
		for _, step := range m.ProofSteps() {
			step.Start, step.End = v.sourceSpan(step.Start, step.End)
			steps = append(steps, step)
		}
		m.Start, m.End = v.sourceSpan(m.Start, m.End)
		m.jwtContainer = Base64Span{left, right}
		m.DecodeSteps, m.DecodeSpans = normalizeDecodeSteps(steps), nil
	}
	return children, limited || capped || mergedLimited
}

func normalizedJWTConstruct(text string) bool {
	return strings.ContainsAny(text, "\\%&+") || strings.Contains(text, "String")
}
