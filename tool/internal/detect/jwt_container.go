package detect

import (
	"context"
	"strings"
)

func jwtSegmentByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

func jwtJSONPrefix(c byte) bool { return c == 'e' || c == 'I' || c == 'C' || c == 'D' }

// The first decoded byte must be '{' or one of the four JSON whitespace bytes.
func jwtHeaderPrefix(a, b byte) bool {
	switch a {
	case 'e':
		return b >= 'w' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_'
	case 'I':
		return b >= 'A' && b <= 'P'
	case 'C':
		return b >= 'Q' && b <= 'Z' || b >= 'a' && b <= 'v'
	case 'D':
		return b >= 'Q' && b <= 'Z' || b >= 'a' && b <= 'f'
	}
	return false
}

// Skip to dots using the optimized byte search, then inspect each maximal
// compact-token run once. Long dotted identifiers cannot cause quadratic work.
// JSON object/whitespace header and payload bytes start with e/I/C/D in base64url;
// the caller still decodes and validates the header before recognizing a JWT.
func jwtContainers(ctx context.Context, text string) ([][2]int, bool) {
	var out [][2]int
	for cursor := 0; cursor < len(text) && ctx.Err() == nil; {
		next := strings.IndexByte(text[cursor:], '.')
		if next < 0 {
			break
		}
		dot := cursor + next
		start := dot
		for start > cursor && jwtSegmentByte(text[start-1]) {
			start--
			if start&4095 == 0 && ctx.Err() != nil {
				return out, true
			}
		}
		end, dots, second := dot+1, 1, -1
		for end < len(text) && (jwtSegmentByte(text[end]) || text[end] == '.') {
			if text[end] == '.' {
				dots++
				if dots == 2 {
					second = end
				}
			}
			end++
			if end&4095 == 0 && ctx.Err() != nil {
				return out, true
			}
		}
		cursor = end
		// A terminal prose period is separate from a three-part token.
		if dots >= 3 && text[end-1] == '.' {
			end--
			dots--
		}
		if dots != 2 || dot-start < 2 || second-dot < 3 || !jwtHeaderPrefix(text[start], text[start+1]) || !jwtJSONPrefix(text[dot+1]) {
			continue
		}
		if len(out) >= maxJWTConstructs {
			return out, true
		}
		out = append(out, [2]int{start, end})
	}
	return out, false
}
