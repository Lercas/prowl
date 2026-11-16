package detect

import (
	"context"
	"strings"

	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

const maxBase64Blob = 8192
const maxBase64Work = 8 << 20
const maxBase64Depth = 4

type Base64Span struct{ Start, End int }

func base64Byte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
		c == '+' || c == '/' || c == '-' || c == '_'
}

// A decoded byte belongs to a complete four-character encoding quantum. Compose these intervals
// through the bounded parent chain; no coordinate ever refers to an invented decoded document.
type base64Frame struct {
	parent     *base64Frame
	start, end int
}

func (f *base64Frame) sourceSpan(start, end int) (int, int) {
	if f == nil {
		return start, end
	}
	left := f.start + start/3*4
	right := min(f.end, f.start+(end+2)/3*4)
	return f.parent.sourceSpan(left, right)
}

// unmaskBase64 scans maximal encoded runs independently of generic entropy findings. A decoded
// value must still pass a typed detector; arbitrary prose does not become a generic secret.
// All layers share one byte/output budget and a fixed depth; decoded data never creates generics.
func (d *Detector) base64Occurrences(ctx context.Context, text string) ([]Match, bool) {
	opts := ScanOptions{jwtBudget: &jwtPayloadBudget{}}
	_, rawLimited := d.jwtPayloadFindings(ctx, text, nil, opts)
	ordinary, jwt, limited := d.base64OccurrencesWithJWT(ctx, text, opts)
	return append(ordinary, jwt...), limited || rawLimited
}

func (d *Detector) base64OccurrencesWithJWT(ctx context.Context, text string, opts ScanOptions) ([]Match, []Match, bool) {
	if opts.jwtBudget == nil {
		opts.jwtBudget = &jwtPayloadBudget{}
	}
	var out []Match
	var jwtChildren []Match
	work, limited := 0, false
	candidates := 0
	exhausted := false
	var scratch *[]byte
	defer func() {
		if scratch != nil {
			d.lowerPool.Put(scratch)
		}
	}()
	rootRemaining := 0
	var walk func(string, *base64Frame, int, []Base64Span, *int)
	walk = func(text string, parent *base64Frame, depth int, chain []Base64Span, remaining *int) {
		for i := 0; i < len(text); {
			// Poll at the same bounded byte interval as the encoded-run loop.
			// Most source separators need no interface call into the context.
			if exhausted || i&4095 == 0 && ctx.Err() != nil {
				return
			}
			if !base64Byte(text[i]) {
				i++
				continue
			}
			start := i
			for i < len(text) && base64Byte(text[i]) {
				i++
				if i&4095 == 0 && ctx.Err() != nil {
					return
				}
			}
			for i < len(text) && text[i] == '=' {
				i++
				if i&4095 == 0 && ctx.Err() != nil {
					return
				}
			}
			end := i
			if end-start < minBase64CandidateBytes {
				continue
			}
			if end-start > maxBase64Blob {
				limited = true
				continue
			}
			if depth == 0 && IsKnownNonSecretBlob(text, start) {
				continue
			}
			if work+end-start > maxBase64Work || len(out)+len(jwtChildren) >= d.Tuning().MaxMatches {
				limited, exhausted = true, true
				return
			}
			work += end - start
			if depth > 0 {
				if *remaining <= 0 {
					limited = true
					return
				}
				*remaining--
			} else {
				rootRemaining = maxNestedBlobs
				remaining = &rootRemaining
			}
			// Hex is a separate interpretation: retain the existing Base64 route too.
			if end-start >= minHexBlobBytes && (end-start)%2 == 0 && isHex(text[start:end]) {
				local := opts
				local.jwtOrigin = jwtBase64Origin(parent, opts.jwtOrigin)
				children, capped := d.jwtHexCandidate(ctx, text, start, end, local)
				limited = limited || capped
				for _, m := range children {
					if len(out)+len(jwtChildren) >= d.Tuning().MaxMatches {
						limited, exhausted = true, true
						return
					}
					if len(chain)+m.base64ProofDepth() > maxBase64Depth {
						limited = true
						continue
					}
					m.Start, m.End = parent.sourceSpan(m.Start, m.End)
					m.jwtContainer.Start, m.jwtContainer.End = parent.sourceSpan(m.jwtContainer.Start, m.jwtContainer.End)
					steps := make([]DecodeStep, 0, len(chain)+len(m.DecodeSteps))
					for _, span := range chain {
						steps = append(steps, DecodeStep{span.Start, span.End, "base64-decode"})
					}
					for _, step := range m.DecodeSteps {
						step.Start, step.End = parent.sourceSpan(step.Start, step.End)
						steps = append(steps, step)
					}
					m.DecodeSteps = normalizeDecodeSteps(steps)
					jwtChildren = append(jwtChildren, m)
				}
			}
			enc := base64Encoding(text[start:end])
			if enc == nil {
				continue
			}
			if scratch == nil {
				scratch = d.lowerPool.Get().(*[]byte)
			}
			needed := enc.DecodedLen(end - start)
			if cap(*scratch) < needed {
				*scratch = make([]byte, needed)
			}
			dec := (*scratch)[:needed]
			n, err := enc.Decode(dec, []byte(text[start:end]))
			if err != nil {
				continue
			}
			dec = dec[:n]
			if compressedTransform(dec) != "" {
				if depth >= maxBase64Depth {
					limited = true
					continue
				}
				frame := &base64Frame{parent: parent, start: start, end: end}
				local := opts
				local.jwtOrigin = jwtBase64Origin(frame, opts.jwtOrigin)
				children, capped := d.jwtInflatedFindings(ctx, dec, local)
				limited = limited || capped
				left, right := parent.sourceSpan(start, end)
				for _, m := range children {
					if len(out)+len(jwtChildren) >= d.Tuning().MaxMatches {
						limited, exhausted = true, true
						return
					}
					if len(chain)+1+m.base64ProofDepth() > maxBase64Depth {
						limited = true
						continue
					}
					m.Start, m.End = frame.sourceSpan(m.Start, m.End)
					m.jwtContainer.Start, m.jwtContainer.End = frame.sourceSpan(m.jwtContainer.Start, m.jwtContainer.End)
					steps := make([]DecodeStep, 0, len(chain)+1+len(m.DecodeSteps))
					for _, span := range chain {
						steps = append(steps, DecodeStep{span.Start, span.End, "base64-decode"})
					}
					steps = append(steps, DecodeStep{left, right, "base64-decode"})
					for _, step := range m.DecodeSteps {
						step.Start, step.End = frame.sourceSpan(step.Start, step.End)
						steps = append(steps, step)
					}
					m.DecodeSteps = normalizeDecodeSteps(steps)
					jwtChildren = append(jwtChildren, m)
				}
				continue
			}
			if !printableText(dec) {
				continue
			}
			if candidates >= d.Tuning().MaxMatches {
				limited, exhausted = true, true
				return
			}
			candidates++
			if depth >= maxBase64Depth {
				limited = true
				continue
			}
			decoded := string(dec)
			left, right := parent.sourceSpan(start, end)
			proof := append(append([]Base64Span(nil), chain...), Base64Span{left, right})
			frame := &base64Frame{parent: parent, start: start, end: end}
			if strings.Contains(decoded, ".") || normalizedJWTConstruct(decoded) {
				local := opts
				local.jwtOrigin = jwtBase64Origin(frame, opts.jwtOrigin)
				children, capped := d.jwtPayloadFindings(ctx, decoded, nil, local)
				if normalizedJWTConstruct(decoded) {
					local.jwtOnly = true
					_, extra, viewLimited, _ := d.scanViewsWithJWT(ctx, decoded, local)
					children = append(children, extra...)
					capped = capped || viewLimited
				}
				limited = limited || capped
				for _, m := range children {
					if len(out)+len(jwtChildren) >= d.Tuning().MaxMatches {
						limited, exhausted = true, true
						return
					}
					if len(proof)+m.base64ProofDepth() > maxBase64Depth {
						limited = true
						continue
					}
					m.Start, m.End = frame.sourceSpan(m.Start, m.End)
					m.jwtContainer.Start, m.jwtContainer.End = frame.sourceSpan(m.jwtContainer.Start, m.jwtContainer.End)
					steps := append([]Base64Span(nil), proof...)
					for _, span := range m.DecodeSpans {
						left, right := frame.sourceSpan(span.Start, span.End)
						steps = append(steps, Base64Span{left, right})
					}
					if len(m.DecodeSteps) > 0 {
						mixed := make([]DecodeStep, 0, len(proof)+len(m.DecodeSteps))
						for _, span := range proof {
							mixed = append(mixed, DecodeStep{span.Start, span.End, "base64-decode"})
						}
						for _, step := range m.DecodeSteps {
							step.Start, step.End = frame.sourceSpan(step.Start, step.End)
							mixed = append(mixed, step)
						}
						m.DecodeSteps, m.DecodeSpans = normalizeDecodeSteps(mixed), nil
					} else {
						m.DecodeSpans = steps
					}
					jwtChildren = append(jwtChildren, m)
				}
			}
			var matches []Match
			capped := false
			if !opts.jwtOnly {
				matches, capped = d.collect(ctx, decoded, "", "", d.keywordsPresent(strings.ToLower(decoded)), scanStructure(decoded, 32))
			}
			limited = limited || capped
			for _, m := range matches {
				if taxonomy.GenericLast[m.Type] || depth == 0 && !HasSecretNameContext(text, start) && m.Confidence < 0.9 {
					continue
				}
				if len(out)+len(jwtChildren) >= d.Tuning().MaxMatches {
					limited, exhausted = true, true
					return
				}
				stage := "L1-base64"
				if m.ChecksumValid {
					stage += "-checksum"
				}
				left, right := frame.sourceSpan(m.Start, m.End)
				out = append(out, Match{
					Type: m.Type, Value: m.Value, Start: left, End: right,
					Confidence: m.Confidence * 0.95, ChecksumValid: m.ChecksumValid,
					Category: m.Category, Stage: stage, DecodedText: decoded, DecodedStart: m.Start, DecodeSpans: proof,
				})
			}
			walk(decoded, frame, depth+1, proof, remaining)

		}
	}
	walk(text, nil, 0, nil, nil)
	return out, jwtChildren, limited
}
