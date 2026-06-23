package detect

// Detection thresholds, overridable from the config's `detection:` section. Process-wide and set once
// at startup via ApplyTuning before any scan, so the concurrent read-only workers see a race-free value.
var (
	genericEntropyMin         = 3.5   // min Shannon entropy for a generic high-entropy hit
	weakPlaceholderMaxEntropy = 4.2   // below this, a value with a placeholder word is treated as a placeholder
	maxScanMatches            = 50000 // DoS backstop: stop collecting after this many raw matches per Scan
)

// pwdCueLookback bounds how far back collect() scans for a generic_password assignment cue. A real
// `name = value` cue sits in the immediate prefix, so this fixed window keeps per-match cost O(1)
// instead of O(line length) on a single long line.
const pwdCueLookback = 256

// ApplyTuning overrides the detection thresholds; a zero/negative argument keeps the current default.
// Call once at startup before scanning (the values are read by concurrent scan workers).
func ApplyTuning(genericEntropy, placeholderMaxEntropy float64, maxMatches int) {
	if genericEntropy > 0 {
		genericEntropyMin = genericEntropy
	}
	if placeholderMaxEntropy > 0 {
		weakPlaceholderMaxEntropy = placeholderMaxEntropy
	}
	if maxMatches > 0 {
		maxScanMatches = maxMatches
	}
}
