package detect

import "context"

const maxJWTInflateWork = 8 << 20

func compressedTransform(data []byte) string {
	if len(data) < 6 {
		return ""
	}
	if data[0] == 0x1f && data[1] == 0x8b {
		return "gzip-inflate"
	}
	if data[0]&0x0f == 8 && (uint(data[0])<<8|uint(data[1]))%31 == 0 {
		return "zlib-inflate"
	}
	return ""
}

// Compressed views only contribute validated JWT claims. The whole stream is
// the source proof: plaintext offsets cannot name individual compressed bytes.
func (d *Detector) jwtInflatedFindings(ctx context.Context, data []byte, opts ScanOptions) ([]Match, bool) {
	transform := compressedTransform(data)
	if transform == "" || ctx.Err() != nil {
		return nil, false
	}
	budget := opts.jwtBudget
	if opts.jwtInflateDepth >= maxDecodeDepth || budget.inflateAttempts >= maxJWTConstructs || budget.inflateBytes >= maxJWTInflateWork {
		return nil, true
	}
	budget.inflateAttempts++
	decoded, recognized, limited := inflateStatusLimit(data, min(maxInflateBytes, maxJWTInflateWork-budget.inflateBytes))
	budget.inflateBytes += len(decoded)
	if !recognized || len(decoded) == 0 || ctx.Err() != nil {
		return nil, limited
	}
	local := ScanOptions{
		jwtDepth: opts.jwtDepth, jwtHexDepth: opts.jwtHexDepth, jwtInflateDepth: opts.jwtInflateDepth + 1,
		jwtBudget: budget, ObserveJWTPayload: opts.ObserveJWTPayload,
		jwtOrigin: &jwtViewOrigin{parent: opts.jwtOrigin, start: 0, end: len(data), inflate: transform},
	}
	var inner ScanResult
	if compressedTransform(decoded) != "" {
		inner.Matches, inner.Base64Limited = d.jwtInflatedFindings(ctx, decoded, local)
	} else if printableText(decoded) {
		inner = d.ScanWithStatus(ctx, string(decoded), local)
	}
	var out []Match
	for _, m := range inner.Matches {
		if !m.JWTPayload {
			continue
		}
		steps := []DecodeStep{{0, len(data), transform}}
		for _, step := range m.ProofSteps() {
			step.Start, step.End = 0, len(data)
			steps = append(steps, step)
		}
		m.Start, m.End = 0, len(data)
		m.DecodeSteps, m.DecodeSpans = normalizeDecodeSteps(steps), nil
		out = append(out, m)
	}
	return out, limited || inner.Base64Limited || inner.CandidateLimited
}
