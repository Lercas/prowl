package detect

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"sort"
	"strings"

	"github.com/Lercas/prowl/tool/internal/jsonstrict"
)

const maxJWTPayloads = 128
const maxJWTConstructs = 4096
const maxJWTPayloadWork = 1 << 20
const maxJWTPayloadDepth = 3

type jwtPayloadBudget struct{ count, bytes, escaped int }

// A JWT is a container as well as a finding. Inspect its claims after the ordinary
// overlap pass, so the enclosing token cannot erase credentials in its payload.
// No signature is authenticated and no claim becomes a trusted source binding.
func (d *Detector) jwtPayloadFindings(ctx context.Context, text string, kept []Match, opts ScanOptions) ([]Match, bool) {
	original := len(kept)
	limited := false
	if !strings.Contains(text, ".") {
		return kept, false
	}
	containers, limited := jwtContainers(ctx, text)
	type identity struct {
		typ, value string
		start, end int
	}
	var seen map[identity]bool
	for _, span := range containers {
		if ctx.Err() != nil {
			break
		}
		container := Match{Start: span[0], End: span[1], Value: text[span[0]:span[1]]}
		parts := strings.Split(container.Value, ".")
		if len(parts) != 3 {
			continue
		}
		if len(parts[0]) > maxBase64Blob {
			prefix, _ := base64.RawURLEncoding.DecodeString(parts[0][:64])
			limited = limited || bytes.HasPrefix(bytes.TrimSpace(prefix), []byte("{"))
			continue
		}
		header, headerErr := base64.RawURLEncoding.Strict().DecodeString(parts[0])
		if headerErr != nil || !bytes.HasPrefix(bytes.TrimSpace(header), []byte("{")) {
			continue
		}
		var fields map[string]json.RawMessage
		var algorithm string
		if jsonstrict.ValidateEncoding(header) != nil || json.Unmarshal(header, &fields) != nil || json.Unmarshal(fields["alg"], &algorithm) != nil || algorithm == "" {
			continue
		}
		if opts.jwtDepth >= maxJWTPayloadDepth || len(parts[1]) > maxBase64Blob || len(kept) >= maxScanMatches {
			limited = true
			continue
		}
		if opts.jwtBudget == nil {
			opts.jwtBudget = &jwtPayloadBudget{}
		}
		budget := opts.jwtBudget
		if budget.count >= maxJWTPayloads || budget.bytes+len(parts[0])+len(parts[1]) > maxJWTPayloadWork {
			limited = true
			continue
		}
		budget.count++
		budget.bytes += len(parts[0]) + len(parts[1])
		payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
		if err != nil || len(payload) == 0 || jsonstrict.ValidateEncoding(payload) != nil || !json.Valid(payload) || strings.TrimSpace(string(payload))[0] != '{' {
			limited = true
			continue
		}
		decoded := string(payload)
		childOptions := ScanOptions{jwtDepth: opts.jwtDepth + 1, jwtBudget: budget}
		inner := d.ScanWithStatus(ctx, decoded, childOptions)
		inner = d.jwtEscapedFindings(ctx, decoded, inner, childOptions)
		limited = limited || inner.CandidateLimited || inner.Base64Limited
		if seen == nil {
			seen = make(map[identity]bool, len(kept))
			for _, m := range kept {
				seen[identity{m.Type, m.Value, m.Start, m.End}] = true
			}
		}
		start := container.Start + len(parts[0]) + 1
		frame := &base64Frame{start: start, end: start + len(parts[1])}
		for _, m := range inner.Matches {
			// Bare claim identifiers, hashes and random user IDs are not credentials.
			if m.Type == "generic_high_entropy" {
				continue
			}
			if len(kept) >= maxScanMatches || len(m.DecodeSpans)+1 > maxBase64Depth {
				limited = true
				break
			}
			if m.DecodedText == "" {
				m.DecodedText, m.DecodedStart = decoded, m.Start
			}
			if m.ContextName == "" {
				m.ContextName = BindingName(m.DecodedText, m.DecodedStart)
			}
			m.Start, m.End = frame.sourceSpan(m.Start, m.End)
			key := identity{m.Type, m.Value, m.Start, m.End}
			if seen[key] {
				continue
			}
			seen[key] = true
			proof := make([]Base64Span, 1, len(m.DecodeSpans)+1)
			proof[0] = Base64Span{start, frame.end}
			for _, span := range m.DecodeSpans {
				left, right := frame.sourceSpan(span.Start, span.End)
				proof = append(proof, Base64Span{left, right})
			}
			m.DecodeSpans = proof
			m.JWTPayload = true
			m.Stage = "L1-jwt-payload"
			if m.ChecksumValid {
				m.Stage += "-checksum"
			}
			m.Confidence *= .95
			kept = append(kept, m)
		}
	}
	if len(kept) != original {
		sort.SliceStable(kept, func(i, j int) bool { return kept[i].Start < kept[j].Start })
	}
	return kept, limited
}
