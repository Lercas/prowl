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

type jwtContainerIdentity struct {
	start, end int
	content    string // bounded header + payload, never the potentially long signature
}

type jwtPayloadBudget struct {
	count, bytes, escaped int
	hexWork, hexAttempts  int
	seen                  map[jwtContainerIdentity]bool
}

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
		if len(parts[1]) > maxBase64Blob {
			limited = true
			continue
		}
		if opts.jwtBudget == nil {
			opts.jwtBudget = &jwtPayloadBudget{}
		}
		budget := opts.jwtBudget
		left, right := opts.jwtOrigin.sourceSpan(container.Start, container.End)
		id := jwtContainerIdentity{left, right, container.Value[:len(parts[0])+1+len(parts[1])]}
		if budget.seen[id] {
			continue
		}
		if len(budget.seen) >= maxJWTConstructs {
			limited = true
			continue
		}
		if budget.seen == nil {
			budget.seen = map[jwtContainerIdentity]bool{}
		}
		// Record rejected-depth containers too: another decoding route cannot
		// retry the same physical container with a shallower JWT depth.
		budget.seen[id] = true
		if opts.jwtDepth >= maxJWTPayloadDepth || opts.jwtOrigin.encodedDepth() >= maxBase64Depth || len(kept) >= maxScanMatches {
			limited = true
			continue
		}
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
		start := container.Start + len(parts[0]) + 1
		frame := &base64Frame{start: start, end: start + len(parts[1])}
		origin := &jwtViewOrigin{parent: opts.jwtOrigin, start: start, end: frame.end, base64: true}
		if opts.ObserveJWTPayload != nil {
			left, right := opts.jwtOrigin.sourceSpan(container.Start, container.End)
			opts.ObserveJWTPayload(JWTPayloadView{Text: decoded, origin: origin, container: Base64Span{left, right}, token: container.Value})
		}
		childOptions := ScanOptions{jwtDepth: opts.jwtDepth + 1, jwtBudget: budget, ObserveJWTPayload: opts.ObserveJWTPayload, jwtOrigin: origin, jwtHexDepth: opts.jwtHexDepth}
		inner := d.ScanWithStatus(ctx, decoded, childOptions)
		inner = d.jwtEscapedFindings(ctx, decoded, inner, childOptions)
		limited = limited || inner.CandidateLimited || inner.Base64Limited
		if seen == nil {
			seen = make(map[identity]bool, len(kept))
			for _, m := range kept {
				seen[identity{m.Type, m.Value, m.Start, m.End}] = true
			}
		}
		for _, m := range inner.Matches {
			// Bare claim identifiers, hashes and random user IDs are not credentials.
			if m.Type == "generic_high_entropy" {
				continue
			}
			if len(kept) >= maxScanMatches || m.base64ProofDepth()+1 > maxBase64Depth {
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
			if len(m.DecodeSteps) > 0 {
				steps := []DecodeStep{{start, frame.end, "base64-decode"}}
				for _, step := range m.DecodeSteps {
					step.Start, step.End = frame.sourceSpan(step.Start, step.End)
					steps = append(steps, step)
				}
				m.DecodeSteps = normalizeDecodeSteps(steps)
				m.DecodeSpans = nil
			} else {
				m.DecodeSpans = proof
			}
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

// Payload children survive enclosing-token overlap, while the final combined
// cap still applies. A claims-aware duplicate must keep its binding isolation.
func mergeJWTPayloadMatches(kept, children []Match) ([]Match, bool) {
	if len(children) == 0 {
		return kept, false
	}
	type identity struct {
		typ, value string
		start, end int
	}
	seen := make(map[identity]int, len(kept))
	for i, m := range kept {
		seen[identity{m.Type, m.Value, m.Start, m.End}] = i
	}
	limited := false
	for _, m := range children {
		key := identity{m.Type, m.Value, m.Start, m.End}
		if i, ok := seen[key]; ok {
			if m.JWTPayload && !kept[i].JWTPayload {
				kept[i] = m
			}
			continue
		}
		// The legacy non-linear winner covers the entire encoded blob. Replace
		// it only when this claims proof names that exact same source interval;
		// keeping it as a second finding would allow companion borrowing.
		replaced := false
		for _, step := range m.DecodeSteps {
			coarse := identity{m.Type, m.Value, step.Start, step.End}
			if i, ok := seen[coarse]; ok && kept[i].decodedNonLinear && !kept[i].JWTPayload {
				delete(seen, coarse)
				seen[key], kept[i], replaced = i, m, true
				break
			}
		}
		if replaced {
			continue
		}
		if len(kept) >= maxScanMatches {
			limited = true
			break
		}
		seen[key] = len(kept)
		kept = append(kept, m)
	}
	sort.SliceStable(kept, func(i, j int) bool { return kept[i].Start < kept[j].Start })
	return kept, limited
}
