package atlassian

import (
	"sort"
	"strings"
)

// adfText recursively extracts scannable text from an Atlassian Document Format (ADF) node — the
// JSON body Jira Cloud v3 returns for description / comment / textarea fields. Visible text and
// metadata are collected separately so a link's attributes cannot interrupt a formatted token.
func adfText(node any) string {
	var text, metadata strings.Builder
	collectADF(node, &text, &metadata)
	if metadata.Len() > 0 {
		adfBoundary(&text)
		text.WriteString(metadata.String())
	}
	return strings.TrimSpace(text.String())
}

func adfBoundary(b *strings.Builder) {
	if b.Len() > 0 && b.String()[b.Len()-1] != '\n' {
		b.WriteByte('\n')
	}
}

// collectFieldData reads every string leaf in selected custom fields and node/mark attributes.
// Key context makes password-like scalar values scannable without escaping their literal bytes.
// Sorting object keys keeps emitted positions and ML context independent of Go map iteration.
func collectFieldData(node any, b *strings.Builder, key string) {
	switch n := node.(type) {
	case map[string]any:
		keys := make([]string, 0, len(n))
		for k := range n {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			collectFieldData(n[k], b, k)
		}
	case []any:
		for _, v := range n {
			collectFieldData(v, b, key)
		}
	case string:
		if n != "" {
			if key != "" {
				b.WriteString(key)
				b.WriteString(" = ")
			}
			b.WriteString(n)
			b.WriteByte('\n')
		}
	}
}

func collectADF(node any, text, metadata *strings.Builder) {
	switch n := node.(type) {
	case map[string]any:
		kind, _ := n["type"].(string)
		// Adjacent text nodes belong to one visible span regardless of their formatting marks.
		// Other inline objects occupy space; blocks and hard breaks must separate their neighbours.
		block := false
		switch kind {
		case "text":
		case "hardBreak":
			text.WriteByte('\n')
		case "emoji", "mention", "inlineCard", "status", "date", "mediaInline", "inlineExtension":
			text.WriteByte(' ')
		case "doc", "paragraph", "heading", "codeBlock", "blockquote", "bulletList", "orderedList", "listItem",
			"table", "tableRow", "tableCell", "tableHeader", "panel", "expand", "nestedExpand", "rule",
			"media", "mediaGroup", "mediaSingle", "extension", "bodiedExtension", "multiBodiedExtension",
			"syncBlock", "bodiedSyncBlock", "blockTaskItem", "taskItem", "taskList", "decisionItem", "decisionList",
			"extensionFrame", "blockCard", "layoutSection", "layoutColumn":
			block = true
			adfBoundary(text)
		default:
			// Custom objects and unknown node types keep all their string values, including type.
			adfBoundary(text)
			collectFieldData(n, metadata, "")
			return
		}
		if t, ok := n["text"].(string); ok && t != "" {
			text.WriteString(t)
		} else if !ok {
			collectFieldData(n["text"], metadata, "text")
		}
		if content, ok := n["content"].([]any); ok {
			for _, c := range content {
				collectADF(c, text, metadata)
			}
		} else {
			collectFieldData(n["content"], metadata, "content")
		}
		if block {
			adfBoundary(text)
		}
		collectFieldData(n["attrs"], metadata, "")
		if marks, ok := n["marks"].([]any); ok {
			for _, m := range marks {
				if mm, ok := m.(map[string]any); ok {
					markKind, _ := mm["type"].(string)
					switch markKind {
					case "backgroundColor", "border", "code", "em", "link", "strike", "strong", "subsup", "textColor", "underline", "alignment", "annotation":
					default:
						collectFieldData(mm["type"], metadata, "type")
					}
					collectFieldData(mm["attrs"], metadata, "")
					for _, k := range sortedExtraKeys(mm, "type", "attrs") {
						collectFieldData(mm[k], metadata, k)
					}
				} else {
					collectFieldData(m, metadata, "marks")
				}
			}
		} else {
			collectFieldData(n["marks"], metadata, "marks")
		}
		for _, k := range sortedExtraKeys(n, "type", "text", "content", "attrs", "marks") {
			collectFieldData(n[k], metadata, k)
		}
	case []any:
		for _, c := range n {
			collectADF(c, text, metadata)
		}
	case string:
		adfBoundary(text)
		text.WriteString(n)
		text.WriteByte('\n')
	}
}

func sortedExtraKeys(n map[string]any, excluded ...string) []string {
	var keys []string
	for k := range n {
		skip := false
		for _, e := range excluded {
			if k == e {
				skip = true
				break
			}
		}
		if !skip {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
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
