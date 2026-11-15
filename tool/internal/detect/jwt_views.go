package detect

import (
	"context"
	"strconv"
	"unicode/utf8"
)

// JWTPayloadView is an untrusted JSON object, not an authenticated claims set.
// Its coordinates always project back to the input of the outermost detector call.
type JWTPayloadView struct {
	Text      string
	origin    *jwtViewOrigin
	container Base64Span
}

type JWTPayloadString struct {
	Name, Value string
	Start, End  int
	Escaped     bool
}

// Strings preserves duplicate members, keys and logical escaped scalar values.
func (v JWTPayloadView) Strings(ctx context.Context) ([]JWTPayloadString, bool) {
	values, limited := jwtStrings(ctx, v.Text)
	out := make([]JWTPayloadString, 0, len(values))
	for _, value := range values {
		if len(value.value) > 4096 {
			limited = true
			continue
		}
		out = append(out, JWTPayloadString{value.name, value.value, value.start, value.end, value.escaped})
	}
	return out, limited
}

func (v JWTPayloadView) SourceSpan(start, end int) (int, int) {
	return v.origin.sourceSpan(start, end)
}

func (v JWTPayloadView) ContainerSpan() Base64Span { return v.container }

// EncodedSpans returns outer-to-inner Base64 proofs. Escaped JSON steps are
// composed into their source intervals before exposing any coordinates.
func (v JWTPayloadView) EncodedSpans() []Base64Span {
	var out []Base64Span
	for origin := v.origin; origin != nil; origin = origin.parent {
		if origin.base64 {
			left, right := origin.parent.sourceSpan(origin.start, origin.end)
			out = append(out, Base64Span{left, right})
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

type jwtViewOrigin struct {
	parent     *jwtViewOrigin
	start, end int
	base64     bool
	bytes      []Base64Span // decoded scalar bytes -> original JSON spellings
}

func (o *jwtViewOrigin) sourceSpan(start, end int) (int, int) {
	if o == nil {
		return start, end
	}
	left, right := o.start, o.end
	if o.base64 {
		left = o.start + start/3*4
		right = min(o.end, o.start+(end+2)/3*4)
	} else if start >= 0 && end > start && end <= len(o.bytes) {
		left, right = o.bytes[start].Start, o.bytes[end-1].End
	}
	return o.parent.sourceSpan(left, right)
}

// The caller has already validated JSON encoding and surrogate pairs. Build
// this bounded projection only for observers of nested escaped JWT strings.
func jwtScalarOrigin(parent *jwtViewOrigin, text string, value jwtString) *jwtViewOrigin {
	o := &jwtViewOrigin{parent: parent, start: value.start, end: value.end}
	raw := text[value.start:value.end]
	for i := 0; i < len(raw); {
		left, width := i, 1
		if raw[i] != '\\' {
			i++
		} else {
			i += 2
			if raw[left+1] == 'u' {
				u, _ := strconv.ParseUint(raw[i:i+4], 16, 16)
				i += 4
				if u >= 0xD800 && u <= 0xDBFF {
					low, _ := strconv.ParseUint(raw[i+2:i+6], 16, 16)
					u = 0x10000 + (u-0xD800)*1024 + low - 0xDC00
					i += 6
				}
				width = utf8.RuneLen(rune(u))
			}
		}
		for j := 0; j < width; j++ {
			o.bytes = append(o.bytes, Base64Span{value.start + left, value.start + i})
		}
	}
	return o
}
