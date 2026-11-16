package reconstruct

import (
	"slices"
	"strings"
	"unicode/utf16"
)

// Revision participates only in the policy of an enabled reconstruction pass.
const Revision = "static-string-order-v2"
const maxSplitParts = 4096

// stringOrder accepts only a complete split(string), optional reverse(), join(string)
// chain on a proven string. Arrays never escape, and unknown calls are not executed.
func (p *parser) stringOrder(v Value) (Value, bool) {
	if !p.take(".") || !p.take("split") || !p.take("(") {
		return Value{}, false
	}
	if p.orderIntrinsicUnknown {
		// Observed prototype access can replace the methods being interpreted.
		p.limited = true
		return Value{}, false
	}
	separator, ok := p.expr()
	if !ok || !p.take(")") {
		return Value{}, false
	}
	reverse := false
	if p.i+1 < len(p.tokens) && p.tokens[p.i].text == "." && p.tokens[p.i+1].text == "reverse" {
		p.i += 2
		if !p.take("(") || !p.take(")") {
			return Value{}, false
		}
		reverse = true
	}
	if !p.take(".") || !p.take("join") || !p.take("(") {
		return Value{}, false
	}
	joiner, ok := p.expr()
	if !ok || !p.take(")") {
		return Value{}, false
	}
	parts, ok := splitStringUnits(v.Text, separator.Text)
	if !ok {
		p.limited = true
		return Value{}, false
	}
	if reverse {
		slices.Reverse(parts)
	}
	text, ok := joinStringUnits(parts, joiner.Text)
	if !ok {
		p.limited = true
		return Value{}, false
	}
	v.Text = text
	v.Spans = append(v.Spans, separator.Spans...)
	v.Spans = append(v.Spans, joiner.Spans...)
	v.Transform = chain(v.Transform, separator.Transform, "constant-string-split")
	if reverse {
		v.Transform = chain(v.Transform, "constant-array-reverse")
	}
	v.Transform = chain(v.Transform, joiner.Transform, "constant-array-join")
	if len(v.Spans) > 128 || v.Transform == "transform-budget" {
		p.limited = true
		return Value{}, false
	}
	return v, true
}

func splitStringUnits(text, separator string) ([][]uint16, bool) {
	if separator == "" {
		// JS split("") separates UTF-16 code units, including surrogate halves.
		units := utf16.Encode([]rune(text))
		if len(units) > maxSplitParts {
			return nil, false
		}
		parts := make([][]uint16, len(units))
		for i := range units {
			parts[i] = units[i : i+1]
		}
		return parts, true
	}
	// Both operands are proven well-formed Unicode strings, so nonempty string
	// separators have the same boundaries in UTF-8. SplitN bounds allocations and
	// avoids a quadratic naive search through long, almost matching separators.
	stringParts := strings.SplitN(text, separator, maxSplitParts+1)
	if len(stringParts) > maxSplitParts {
		return nil, false
	}
	parts := make([][]uint16, len(stringParts))
	for i, s := range stringParts {
		parts[i] = utf16.Encode([]rune(s))
	}
	return parts, true
}

func joinStringUnits(parts [][]uint16, separator string) (string, bool) {
	sep := utf16.Encode([]rune(separator))
	var units []uint16
	for i, part := range parts {
		if i > 0 {
			if len(units) > maxValue-len(sep) {
				return "", false
			}
			units = append(units, sep...)
		}
		if len(units) > maxValue-len(part) {
			return "", false
		}
		units = append(units, part...)
	}
	// Reject malformed UTF-16 instead of replacing it and inventing a credential.
	for i := 0; i < len(units); i++ {
		unit := units[i]
		if unit >= 0xd800 && unit <= 0xdbff {
			if i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				return "", false
			}
			i++
		} else if unit >= 0xdc00 && unit <= 0xdfff {
			return "", false
		}
	}
	text := string(utf16.Decode(units))
	return text, len(text) <= maxValue
}
