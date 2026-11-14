package detect

import (
	"strings"
	"testing"
)

func TestNamedRejectedCandidatesPreserveIncompleteStatus(t *testing.T) {
	d := newDetector(t)
	// Rejected identifiers still consume the regex candidate budget. A real
	// credential after them must not turn the bounded result into a complete scan.
	text := strings.Repeat("api_key = invalidIdentifierValue123456\n", 4) + "api_key = uYPIcjDG4DmisHIv80lPq7Zx\n"
	hits, capped := d.namedSecrets(t.Context(), text, strings.ToLower(text), 3)
	if !capped || len(hits) != 0 {
		t.Fatal("rejected candidate exhaustion was not reported")
	}
	hits, capped = d.namedSecrets(t.Context(), text, strings.ToLower(text), 10)
	if capped || len(hits) != 1 {
		t.Fatal("complete candidate walk did not retain the credential")
	}
}
