package detect

import (
	"context"
	"encoding/hex"
)

// Hex views only contribute validated JWT claims. Ordinary decoded values keep
// the existing non-linear detector contract and never gain generic detection.
func (d *Detector) jwtHexCandidate(ctx context.Context, text string, start, end int, opts ScanOptions) ([]Match, bool) {
	budget := opts.jwtBudget
	if budget.hexAttempts >= maxJWTConstructs || budget.hexWork+end-start > maxBase64Work {
		return nil, true
	}
	budget.hexAttempts++
	budget.hexWork += end - start
	decoded, err := hex.DecodeString(text[start:end])
	if err != nil {
		return nil, false
	}
	transform := compressedTransform(decoded)
	if transform == "" && !printableText(decoded) {
		return nil, false
	}
	if opts.jwtHexDepth >= maxDecodeDepth {
		return nil, true
	}
	origin := &jwtViewOrigin{parent: opts.jwtOrigin, start: start, end: end, hex: true}
	local := ScanOptions{
		jwtDepth: opts.jwtDepth, jwtBudget: budget, jwtOrigin: origin,
		jwtHexDepth: opts.jwtHexDepth + 1, jwtInflateDepth: opts.jwtInflateDepth, ObserveJWTPayload: opts.ObserveJWTPayload,
	}
	var inner ScanResult
	if transform != "" {
		inner.Matches, inner.Base64Limited = d.jwtInflatedFindings(ctx, decoded, local)
	} else {
		inner = d.ScanWithStatus(ctx, string(decoded), local)
	}
	var out []Match
	for _, m := range inner.Matches {
		if !m.JWTPayload {
			continue
		}
		m.Start, m.End = start+m.Start*2, min(end, start+m.End*2)
		steps := []DecodeStep{{start, end, "hex-decode"}}
		for _, step := range m.ProofSteps() {
			step.Start, step.End = start+step.Start*2, min(end, start+step.End*2)
			steps = append(steps, step)
		}
		m.DecodeSteps, m.DecodeSpans = normalizeDecodeSteps(steps), nil
		out = append(out, m)
	}
	return out, inner.Base64Limited || inner.CandidateLimited
}
