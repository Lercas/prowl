package scan

import (
	"context"
	"encoding/xml"
	"io"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/Lercas/prowl/tool/internal/model"
)

const maxFirebaseXMLBytes = 1 << 20
const maxFirebaseXMLTokens = 100000
const maxFirebaseXMLDepth = 64
const maxFirebaseXMLFields = 4096

type firebaseXMLNode struct {
	name       xml.Name
	attrs      []xml.Attr
	children   []*firebaseXMLNode
	body       strings.Builder
	start, end int
	dataSpans  [][2]int
}

type firebaseXMLBindings struct {
	fields map[string]string
	keys   []*firebaseXMLNode
}

func firebaseXMLKind(path string) string {
	path = model.SafeLocator(path)
	if filepath.Base(path) == "GoogleService-Info.plist" {
		return "plist"
	}
	if strings.EqualFold(filepath.Ext(path), ".xml") {
		return "resources"
	}
	return ""
}

// The only accepted DTD is Apple's conventional declaration. encoding/xml never
// resolves it; custom declarations/entities are rejected rather than interpreted.
func firebaseXMLDoctype(d string) bool {
	switch strings.TrimSpace(d) {
	case `DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"`,
		`DOCTYPE plist PUBLIC "-//Apple Inc//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"`:
		return true
	}
	return false
}

func parseFirebaseXML(ctx context.Context, text, kind string) *firebaseXMLBindings {
	if len(text) > maxFirebaseXMLBytes || !utf8.ValidString(text) || ctx.Err() != nil {
		return nil
	}
	decoder := xml.NewDecoder(strings.NewReader(text))
	var root *firebaseXMLNode
	var stack []*firebaseXMLNode
	declaration, doctype := false, false
	for tokens := 0; ; tokens++ {
		if tokens >= maxFirebaseXMLTokens || ctx.Err() != nil {
			return nil
		}
		before := int(decoder.InputOffset())
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil
		}
		switch token := token.(type) {
		case xml.StartElement:
			if token.Name.Space != "" || len(stack) >= maxFirebaseXMLDepth {
				return nil
			}
			seen := map[xml.Name]bool{}
			for _, attr := range token.Attr {
				if seen[attr.Name] {
					return nil
				}
				seen[attr.Name] = true
			}
			node := &firebaseXMLNode{name: token.Name, attrs: token.Attr, start: int(decoder.InputOffset())}
			if len(stack) == 0 {
				if root != nil {
					return nil
				}
				root = node
			} else {
				parent := stack[len(stack)-1]
				parent.children = append(parent.children, node)
			}
			stack = append(stack, node)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil
			}
			stack[len(stack)-1].end = before
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) == 0 {
				if strings.TrimSpace(strings.TrimPrefix(string(token), "\uFEFF")) != "" {
					return nil
				}
			} else {
				stack[len(stack)-1].body.Write(token)
				stack[len(stack)-1].dataSpans = append(stack[len(stack)-1].dataSpans, [2]int{before, int(decoder.InputOffset())})
			}
		case xml.ProcInst:
			if root != nil || declaration || token.Target != "xml" {
				return nil
			}
			declaration = true
		case xml.Directive:
			if kind != "plist" || root != nil || doctype || !firebaseXMLDoctype(string(token)) {
				return nil
			}
			doctype = true
		}
	}
	if root == nil || len(stack) != 0 {
		return nil
	}
	if kind == "plist" {
		return firebasePlistBindings(root)
	}
	if kind == "resources" {
		return firebaseResourceBindings(root)
	}
	return nil
}

func firebaseXMLStatic(node *firebaseXMLNode, android bool) (string, bool) {
	if node.name.Local != "string" || len(node.children) != 0 || node.end < node.start || node.body.Len() > 4096 {
		return "", false
	}
	value := node.body.String()
	if android {
		// Android escaping, quotes, references, formatting and whitespace rules
		// run after XML decoding. Only their unambiguous literal subset is bound.
		if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\\\"' \t\r\n%") || strings.HasPrefix(value, "@") || strings.HasPrefix(value, "?") {
			return "", false
		}
	}
	return value, true
}

func firebasePlistBindings(root *firebaseXMLNode) *firebaseXMLBindings {
	if root.name.Local != "plist" || len(root.attrs) != 1 || len(root.children) != 1 || strings.TrimSpace(root.body.String()) != "" {
		return nil
	}
	for _, attr := range root.attrs {
		if attr.Name.Space != "" || attr.Name.Local != "version" || attr.Value != "1.0" {
			return nil
		}
	}
	dict := root.children[0]
	if dict.name.Local != "dict" || len(dict.attrs) != 0 || strings.TrimSpace(dict.body.String()) != "" || len(dict.children)%2 != 0 || len(dict.children) > 2*maxFirebaseXMLFields {
		return nil
	}
	out := &firebaseXMLBindings{fields: map[string]string{"firebaseConfig": "GoogleService-Info.plist"}}
	seen := map[string]bool{}
	for i := 0; i < len(dict.children); i += 2 {
		key, value := dict.children[i], dict.children[i+1]
		if key.name.Local != "key" || len(key.attrs) != 0 || len(key.children) != 0 || key.body.Len() > 4096 {
			return nil
		}
		name := key.body.String()
		if name == "" || seen[name] {
			return nil
		}
		seen[name] = true
		logical, ok := firebaseXMLStatic(value, false)
		if len(value.attrs) != 0 {
			ok = false
		}
		switch name {
		case "API_KEY":
			if ok {
				out.keys = append(out.keys, value)
			}
		case "PROJECT_ID":
			if !ok {
				logical = ""
			}
			out.fields["projectId"] = logical
		case "DATABASE_URL":
			if !ok {
				logical = ""
			}
			out.fields["databaseURL"] = logical
		case "STORAGE_BUCKET":
			if !ok {
				logical = ""
			}
			out.fields["storageBucket"] = logical
		}
	}
	return out
}

func firebaseResourceBindings(root *firebaseXMLNode) *firebaseXMLBindings {
	if root.name.Local != "resources" || strings.TrimSpace(root.body.String()) != "" || len(root.children) > maxFirebaseXMLFields {
		return nil
	}
	for _, attr := range root.attrs {
		if attr.Name.Space != "xmlns" && attr.Name.Local != "xmlns" {
			return nil
		}
	}
	out := &firebaseXMLBindings{fields: map[string]string{"firebaseConfig": "android-resources"}}
	seen := map[string]bool{}
	for _, node := range root.children {
		name := ""
		valid := true
		for _, attr := range node.attrs {
			if attr.Name.Space != "" {
				valid = false
				continue
			}
			switch attr.Name.Local {
			case "name":
				name = attr.Value
			case "translatable", "formatted":
				if attr.Value != "true" && attr.Value != "false" {
					valid = false
				}
			default:
				valid = false
			}
		}
		if name == "" {
			continue
		}
		if seen[name] {
			return nil
		}
		seen[name] = true
		logical, ok := firebaseXMLStatic(node, true)
		ok = ok && valid
		switch name {
		case "google_api_key", "google_crash_reporting_api_key":
			if ok {
				out.keys = append(out.keys, node)
			}
		case "project_id":
			if !ok {
				logical = ""
			}
			out.fields["projectId"] = logical
		case "firebase_database_url":
			if !ok {
				logical = ""
			}
			out.fields["databaseURL"] = logical
		case "google_storage_bucket":
			if !ok {
				logical = ""
			}
			out.fields["storageBucket"] = logical
		}
	}
	for _, key := range out.keys {
		if key.body.String() != out.keys[0].body.String() {
			return nil
		}
	}
	return out
}

func (b *firebaseXMLBindings) forSpan(start, end int, value string) map[string]string {
	if b == nil || start < 0 || start >= end {
		return nil
	}
	for _, key := range b.keys {
		if start >= key.start && end <= key.end && value == key.body.String() {
			// Container bounds alone include comments. Only an observed XML data
			// token can own the candidate, even when a comment repeats its value.
			for _, span := range key.dataSpans {
				if start < span[0] || end > span[1] {
					continue
				}
				out := make(map[string]string, len(b.fields))
				for k, v := range b.fields {
					out[k] = v
				}
				return out
			}
		}
	}
	return nil
}
