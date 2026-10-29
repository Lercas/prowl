package lsp

import (
	"bytes"
	"encoding/json"
	"net/url"

	"github.com/Lercas/prowl/tool/internal/jsonstrict"
)

func stringField(raw json.RawMessage) (string, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	return value, true
}

func documentFields(p json.RawMessage) (fields, document map[string]json.RawMessage, uri string, ok bool) {
	fields, err := jsonstrict.Object(p, false)
	if err != nil {
		return nil, nil, "", false
	}
	document, err = jsonstrict.Object(fields["textDocument"], false)
	if err != nil {
		return nil, nil, "", false
	}
	uri, ok = uriField(document["uri"])
	return fields, document, uri, ok
}

func uriField(raw json.RawMessage) (string, bool) {
	uri, ok := stringField(raw)
	if !ok || uri == "" {
		return "", false
	}
	for _, r := range uri {
		if r <= ' ' || r == 0x7f {
			return "", false
		}
	}
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Scheme == "" {
		return "", false
	}
	// Parse leaves opaque paths and raw queries escaped; validate their escapes as well.
	if _, err := url.PathUnescape(uri); err != nil {
		return "", false
	}
	return uri, true
}

func documentVersion(document map[string]json.RawMessage) (int32, bool) {
	return integerField(document["version"])
}

func integerField(raw json.RawMessage) (int32, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || (raw[0] != '-' && (raw[0] < '0' || raw[0] > '9')) {
		return 0, false
	}
	var version int32
	if json.Unmarshal(raw, &version) != nil {
		return 0, false
	}
	return version, true
}

type documentUpdate struct {
	uri, text string
	version   int32
	hasText   bool
}

func openParams(p json.RawMessage) (documentUpdate, bool) {
	_, document, uri, ok := documentFields(p)
	if !ok {
		return documentUpdate{}, false
	}
	version, ok := documentVersion(document)
	if !ok {
		return documentUpdate{}, false
	}
	if _, ok := stringField(document["languageId"]); !ok {
		return documentUpdate{}, false
	}
	text, ok := stringField(document["text"])
	return documentUpdate{uri: uri, text: text, version: version, hasText: ok}, ok
}

func changeParams(p json.RawMessage) (documentUpdate, bool) {
	fields, document, uri, ok := documentFields(p)
	if !ok {
		return documentUpdate{}, false
	}
	version, ok := documentVersion(document)
	if !ok {
		return documentUpdate{}, false
	}
	var changes []json.RawMessage
	raw := bytes.TrimSpace(fields["contentChanges"])
	if len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &changes) != nil {
		return documentUpdate{}, false
	}
	update := documentUpdate{uri: uri, version: version}
	// Validate every event before admitting the final full snapshot. Incremental patches cannot
	// replace full text, even when a later event in the same notification looks valid.
	for _, change := range changes {
		event, err := jsonstrict.Object(change, false)
		if err != nil || event["range"] != nil || event["rangeLength"] != nil {
			return documentUpdate{}, false
		}
		update.text, ok = stringField(event["text"])
		if !ok {
			return documentUpdate{}, false
		}
		update.hasText = true
	}
	return update, true
}

func closeParams(p json.RawMessage) (uri string, ok bool) {
	_, _, uri, ok = documentFields(p)
	return uri, ok
}

// A missing save text is a valid no-op. Invalid fields also leave the current revision intact.
func saveParams(p json.RawMessage) (uri, text string, hasText bool) {
	fields, _, uri, ok := documentFields(p)
	if !ok {
		return "", "", false
	}
	text, hasText = stringField(fields["text"])
	return uri, text, hasText
}
