package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"github.com/Lercas/prowl/tool/internal/jsonstrict"
)

// validateRequestJSON rejects inputs encoding/json would silently repair before scanning.
// json.Valid also enforces one complete value and bounds nesting before the escape walk.
func validateRequestJSON(raw []byte) error {
	return jsonstrict.ValidateEncoding(raw)
}

// UnmarshalJSON rejects duplicate scan fields, including aliases encoding/json matches by case.
// Unknown fields remain accepted for compatibility; they cannot replace content/source/path.
func (item *scanItem) UnmarshalJSON(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("scan item must be an object")
	}
	var parsed scanItem
	seen := map[string]bool{}
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("invalid scan field")
		}
		key = strings.ToLower(key)
		var field *string
		switch key {
		case "content":
			field = &parsed.Content
		case "source":
			field = &parsed.Source
		case "path":
			field = &parsed.Path
		default:
			var ignored json.RawMessage
			if err := dec.Decode(&ignored); err != nil {
				return err
			}
			continue
		}
		if seen[key] {
			return errors.New("duplicate scan field")
		}
		seen[key] = true
		value, err := dec.Token()
		if err != nil {
			return err
		}
		text, ok := value.(string)
		if !ok {
			return errors.New("scan fields must be strings")
		}
		*field = text
	}
	if _, err := dec.Token(); err != nil {
		return err
	}
	if !seen["content"] {
		return errors.New("scan item requires content")
	}
	*item = parsed
	return nil
}
