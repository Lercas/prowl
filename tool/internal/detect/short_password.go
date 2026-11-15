package detect

import (
	"strings"
	"unicode/utf8"
)

// Short values need an established credential binding, not a nearby prose cue.
// Boolean/null atoms, example words and masks do not become password candidates.
func (d *Detector) shortPasswordAllowed(name, value string) bool {
	n := utf8.RuneCountInString(value)
	if n == 0 || n >= 6 || !utf8.ValidString(value) || strings.TrimSpace(value) == "" || comparisonField(name).kind != "password" {
		return false
	}
	switch strings.ToLower(value) {
	case "true", "false", "null", "none", "nil", "test", "yes", "no", "on", "off":
		return false
	}
	mask := true
	for _, r := range value {
		mask = mask && (r == '*' || r == 'x' || r == 'X' || r == '•')
	}
	if mask || shortPasswordRamp(value) {
		return false
	}
	// A custom taxonomy retaining a six-character minimum has not opted into
	// short scalar nominations. Probe only the binding and logical length.
	probe := "\"" + name + "\": \"" + strings.Repeat("Q", n) + "\""
	actual := "\"" + name + "\": \"" + value + "\""
	for _, ct := range d.types {
		if ct.st.ID == "generic_password" && (ct.st.RE.MatchString(probe) || ct.st.RE.MatchString(actual)) {
			return true
		}
	}
	return false
}

// Whole three-to-five-character alphabet/digit ramps are documentation filler,
// like the existing long sequence placeholders; mixed strings remain eligible.
func shortPasswordRamp(value string) bool {
	value = strings.ToLower(value)
	if len(value) < 3 || len(value) > 5 {
		return false
	}
	first := value[0]
	if !(first >= 'a' && first <= 'z' || first >= '0' && first <= '9') {
		return false
	}
	step := int(value[1]) - int(first)
	if step != 1 && step != -1 {
		return false
	}
	letters := first >= 'a' && first <= 'z'
	for i := 1; i < len(value); i++ {
		sameClass := letters && value[i] >= 'a' && value[i] <= 'z' || !letters && value[i] >= '0' && value[i] <= '9'
		if !sameClass || int(value[i])-int(value[i-1]) != step {
			return false
		}
	}

	return true
}
