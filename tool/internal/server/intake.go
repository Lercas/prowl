package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

var errIntake = errors.New("invalid scan item")
var errBatchItems = errors.New("too many batch items")

// Read the small schema directly from the stream. Do not buffer/reparse whole payloads to detect
// duplicate fields: a last-wins content override must never manufacture a complete empty scan.
func readScanItem(d *json.Decoder) (scanItem, error) {
	var item scanItem
	open, err := d.Token()
	if err != nil {
		return item, err
	}
	if open != json.Delim('{') {
		return item, errIntake
	}
	seen := uint8(0)
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return item, err
		}
		var bit uint8
		field, ok := key.(string)
		if !ok {
			return item, errIntake
		}
		switch strings.ToLower(field) {
		case "content":
			bit = 1
		case "source":
			bit = 2
		case "path":
			bit = 4
		case "verify", "ml", "ocr", "show_secrets":
			return item, errIntake
		default:
			var ignored json.RawMessage
			if err := d.Decode(&ignored); err != nil {
				return item, err
			}
			continue
		}
		if seen&bit != 0 {
			return item, errIntake
		}
		seen |= bit
		token, err := d.Token()
		if err != nil {
			return item, err
		}
		value, ok := token.(string)
		if !ok {
			return item, errIntake
		}
		switch bit {
		case 1:
			item.Content = value
		case 2:
			item.Source = value
		case 4:
			item.Path = value
		}
	}
	closeToken, err := d.Token()
	if err != nil {
		return item, err
	}
	if closeToken != json.Delim('}') || seen&1 == 0 {
		return item, errIntake
	}
	return item, nil
}

func decode(w http.ResponseWriter, r *http.Request, target any, maxBytes int64) error {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBytes))
	if err != nil {
		return err
	}
	if err := validateRequestJSON(raw); err != nil {
		return err
	}
	d := json.NewDecoder(&losslessJSONReader{reader: bytes.NewReader(raw)})
	switch target := target.(type) {
	case *scanItem:
		item, err := readScanItem(d)
		if err != nil {
			return err
		}
		*target = item
	case *[]scanItem:
		open, err := d.Token()
		if err != nil {
			return err
		}
		if open != json.Delim('[') {
			return errIntake
		}
		for d.More() {
			if len(*target) >= maxBatchItems {
				return errBatchItems
			}
			item, err := readScanItem(d)
			if err != nil {
				return err
			}
			*target = append(*target, item)
		}
		closeToken, err := d.Token()
		if err != nil {
			return err
		}
		if closeToken != json.Delim(']') {
			return errIntake
		}
	default:
		return errIntake
	}
	if _, err := d.Token(); err != io.EOF {
		if err != nil {
			return err
		}
		return errIntake
	}
	return nil
}
