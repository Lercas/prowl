package forge

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

// Check requested row bounds before allocating typed result slices. Strict decoding below also
// checks the entire document, duplicate fields, encoding and destination schema.
func boundListingRows(raw []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if _, array := out.(*[]map[string]json.RawMessage); !array {
		start, err := dec.Token()
		if err != nil || start != json.Delim('{') {
			return errors.New("invalid repository listing object")
		}
		found := false
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return errors.New("invalid repository listing field")
			}
			if name, ok := key.(string); ok && strings.EqualFold(name, "values") {
				found = true
				break
			}
			var ignored json.RawMessage
			if dec.Decode(&ignored) != nil {
				return errors.New("invalid repository listing value")
			}
		}
		if !found {
			return errors.New("missing repository listing array")
		}
	}
	start, err := dec.Token()
	if err != nil || start != json.Delim('[') {
		return errors.New("invalid repository listing array")
	}
	for rows := 0; dec.More(); rows++ {
		if rows >= maxListingRows {
			return errors.New("repository listing exceeds requested page size")
		}
		var row json.RawMessage
		if dec.Decode(&row) != nil {
			return errors.New("invalid repository listing row")
		}
	}
	return nil
}
