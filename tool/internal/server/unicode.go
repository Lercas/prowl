package server

import "io"

// encoding/json replaces malformed UTF-8 and isolated UTF-16 escapes with U+FFFD.
// Reject that lossy transport before token decoding, with constant space across reader chunks.
type losslessJSONReader struct {
	reader                  io.Reader
	inString, escaped, low  bool
	digits, lowPrefix, need int
	unit                    uint16
	min, max                byte
	err                     error
}

func (r *losslessJSONReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	n, err := r.reader.Read(p)
	for _, b := range p[:n] {
		if !r.validUTF8Byte(b) || !r.validJSONByte(b) {
			r.err = errIntake
			return 0, r.err
		}
	}
	if err == io.EOF && (r.need != 0 || r.digits != 0 || r.lowPrefix != 0 || r.escaped || r.inString) {
		r.err = errIntake
		return 0, r.err
	}
	return n, err
}

func (r *losslessJSONReader) validUTF8Byte(b byte) bool {
	if r.need > 0 {
		if b < r.min || b > r.max {
			return false
		}
		r.need--
		r.min, r.max = 0x80, 0xbf
		return true
	}
	r.min, r.max = 0x80, 0xbf
	switch {
	case b < 0x80:
		return true
	case b >= 0xc2 && b <= 0xdf:
		r.need = 1
	case b >= 0xe0 && b <= 0xef:
		r.need = 2
		switch b {
		case 0xe0:
			r.min = 0xa0
		case 0xed:
			r.max = 0x9f
		}
	case b >= 0xf0 && b <= 0xf4:
		r.need = 3
		switch b {
		case 0xf0:
			r.min = 0x90
		case 0xf4:
			r.max = 0x8f
		}
	default:
		return false
	}
	return true
}

func (r *losslessJSONReader) validJSONByte(b byte) bool {
	if r.digits > 0 {
		var hex byte
		switch {
		case b >= '0' && b <= '9':
			hex = b - '0'
		case b >= 'a' && b <= 'f':
			hex = b - 'a' + 10
		case b >= 'A' && b <= 'F':
			hex = b - 'A' + 10
		default:
			return false
		}
		r.unit = r.unit<<4 | uint16(hex)
		r.digits--
		if r.digits == 0 {
			if r.low {
				r.low = false
				return r.unit >= 0xdc00 && r.unit <= 0xdfff
			}
			if r.unit >= 0xd800 && r.unit <= 0xdbff {
				r.lowPrefix = 1
			} else if r.unit >= 0xdc00 && r.unit <= 0xdfff {
				return false
			}
		}
		return true
	}
	if r.lowPrefix != 0 {
		if r.lowPrefix == 1 && b == '\\' {
			r.lowPrefix = 2
			return true
		}
		if r.lowPrefix == 2 && b == 'u' {
			r.lowPrefix, r.digits, r.unit, r.low = 0, 4, 0, true
			return true
		}
		return false
	}
	if r.escaped {
		r.escaped = false
		if b == 'u' {
			r.digits, r.unit = 4, 0
		}
		return true // Other escape syntax is validated by encoding/json.
	}
	if b == '"' {
		r.inString = !r.inString
	} else if r.inString && b == '\\' {
		r.escaped = true
	}
	return true
}
