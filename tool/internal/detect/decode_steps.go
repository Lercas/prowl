package detect

import (
	"strconv"
	"strings"
)

// DecodeStep is an operation over an observed source interval. Mixed-codec
// chains retain their order even when their intervals overlap after projection.
type DecodeStep struct {
	Start, End int
	Transform  string
}

func normalizeDecodeSteps(steps []DecodeStep) []DecodeStep {
	base64Layer := 0
	for i := range steps {
		if strings.HasPrefix(steps[i].Transform, "base64-decode") {
			base64Layer++
			steps[i].Transform = "base64-decode"
			if base64Layer > 1 {
				steps[i].Transform += "-layer-" + strconv.Itoa(base64Layer)
			}
		}
	}
	return steps
}

// ProofSteps supplies the legacy Base64 representation without changing its
// existing storage cost; mixed proofs use the explicit operation sequence.
func (m Match) ProofSteps() []DecodeStep {
	if len(m.DecodeSteps) > 0 {
		return m.DecodeSteps
	}
	out := make([]DecodeStep, 0, len(m.DecodeSpans))
	for _, span := range m.DecodeSpans {
		out = append(out, DecodeStep{span.Start, span.End, "base64-decode"})
	}
	return normalizeDecodeSteps(out)
}

func (m Match) base64ProofDepth() int {
	if len(m.DecodeSteps) == 0 {
		return len(m.DecodeSpans)
	}
	count := 0
	for _, s := range m.DecodeSteps {
		if strings.HasPrefix(s.Transform, "base64-decode") {
			count++
		}
	}
	return count
}
