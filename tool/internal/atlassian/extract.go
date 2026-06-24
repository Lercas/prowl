package atlassian

import "strings"

// adfText recursively extracts scannable text from an Atlassian Document Format (ADF) node — the
// JSON body Jira Cloud v3 returns for description / comment / textarea fields. It collects every
// node's `text` AND the secret-bearing `attrs` of link / inlineCard / mention / media nodes
// (href / url / value can hide a token), per API_REFERENCE.md §4 and pitfall T16.
func adfText(node any) string {
	var b strings.Builder
	collectADF(node, &b)
	return strings.TrimSpace(b.String())
}

// adfAttrKeys are the ADF node/mark attributes that can carry a literal secret (a link href, a
// smart-link url, a mention value, a media collection/file id). Scanning node text alone misses a
// token pasted as a link target or a select-option value.
var adfAttrKeys = []string{"href", "url", "value", "text", "id", "shortName", "alt", "title", "name", "key", "collection"}

func writeAttrs(attrs map[string]any, b *strings.Builder) {
	for _, k := range adfAttrKeys {
		if v, ok := attrs[k].(string); ok && v != "" {
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}
	// an attr whose value is itself a nested object/array (e.g. media metadata) may hide a token too.
	for _, v := range attrs {
		switch v.(type) {
		case map[string]any, []any:
			collectADF(v, b)
		}
	}
}

func collectADF(node any, b *strings.Builder) {
	switch n := node.(type) {
	case map[string]any:
		if t, ok := n["text"].(string); ok && t != "" {
			b.WriteString(t)
			b.WriteByte('\n')
		}
		// option / select / user custom fields aren't ADF docs — their content sits in scalar
		// value/name keys (no text/content); harvest them so a secret in such a field is scanned.
		for _, k := range []string{"value", "name"} {
			if t, ok := n[k].(string); ok && t != "" {
				b.WriteString(t)
				b.WriteByte('\n')
			}
		}
		// node attrs (inlineCard/mention/media url|value|id) ...
		if attrs, ok := n["attrs"].(map[string]any); ok {
			writeAttrs(attrs, b)
		}
		// ... and mark attrs: a `link` is a MARK on a text node, so its href lives under marks[].attrs.
		if marks, ok := n["marks"].([]any); ok {
			for _, m := range marks {
				if mm, ok := m.(map[string]any); ok {
					if attrs, ok := mm["attrs"].(map[string]any); ok {
						writeAttrs(attrs, b)
					}
				}
			}
		}
		if content, ok := n["content"].([]any); ok {
			for _, c := range content {
				collectADF(c, b)
			}
		}
	case []any:
		for _, c := range n {
			collectADF(c, b)
		}
	case string:
		b.WriteString(n)
		b.WriteByte('\n')
	}
}

// fieldText returns scannable text for a Jira field value that may be an ADF document (Cloud v3, a
// JSON object), a wiki-markup / plain string (Cloud v2 or Server/DC), or absent. Confluence page
// bodies are NOT passed here: their raw `storage` XHTML is scanned as-is (CDATA in code macros and
// macro params would be mangled by tag-stripping — pitfall T23), so the walker feeds it directly.
func fieldText(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case map[string]any, []any:
		return adfText(x)
	default:
		return ""
	}
}
