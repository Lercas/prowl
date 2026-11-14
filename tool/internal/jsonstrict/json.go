// Package jsonstrict checks JSON without the silent repairs and duplicate-key replacement of
// encoding/json. Callers still own their schema and application-level validation.
package jsonstrict

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ValidateEncoding requires one complete JSON value, valid UTF-8 and paired Unicode surrogates.
func ValidateEncoding(raw []byte) error {
	if !utf8.Valid(raw) || !json.Valid(raw) {
		return errors.New("invalid JSON encoding")
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if raw[i] != 'u' {
			continue
		}
		r, _ := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		i += 4
		if !utf16.IsSurrogate(rune(r)) { //nolint:gosec // ParseUint is bounded to 16 bits.
			continue
		}
		if r >= 0xdc00 || i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
			return errors.New("unpaired JSON surrogate")
		}
		low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
		if err != nil || low < 0xdc00 || low > 0xdfff {
			return errors.New("unpaired JSON surrogate")
		}
		i += 6
	}
	return nil
}

// Object returns an object's fields and rejects duplicates after JSON decoding. foldCase supports
// schemas encoding/json otherwise matches case-insensitively; path maps should leave it false.
func Object(raw []byte, foldCase bool) (map[string]json.RawMessage, error) {
	if err := ValidateEncoding(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("JSON value must be an object")
	}
	fields := map[string]json.RawMessage{}
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok {
			return nil, errors.New("invalid JSON object field")
		}
		if foldCase {
			key = strings.ToLower(key)
		}
		if _, exists := fields[key]; exists {
			return nil, errors.New("duplicate JSON object field")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		fields[key] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	return fields, nil
}
