package scan

import (
	"context"
	"regexp"
	"strings"

	"github.com/Lercas/prowl/tool/internal/model"
)

type algoliaXMLKey struct {
	name, value string
	start, end  int
}
type algoliaXMLBindings struct {
	fields     map[string]string
	keys       []algoliaXMLKey
	valid      bool
	incomplete bool
}

var algoliaXMLSignal = regexp.MustCompile(`(?i)algolia[_-]?(?:(?:search|admin)[_-]?(?:api[_-]?)?key|api[_-]?key|key|token)`)

func algoliaXMLRole(name string) string {
	name = strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(name))
	switch name {
	case "algoliaappid", "algoliaapplicationid":
		return "app"
	case "algoliaapikey", "algoliakey", "algoliatoken", "algoliasearchkey", "algoliasearchapikey", "algoliaadminkey", "algoliaadminapikey":
		return "key"
	}
	return ""
}

// Only one root resource group or root plist dictionary can own these fields.
// Values are XML literals; no Android references, overlays, imports or execution.
func parseAlgoliaXML(root *firebaseXMLNode, kind, text string) *algoliaXMLBindings {
	out := &algoliaXMLBindings{fields: map[string]string{}, valid: true}
	type field struct {
		name  string
		node  *firebaseXMLNode
		valid bool
	}
	var fields []field
	switch kind {
	case "resources":
		if root.name.Local != "resources" || strings.TrimSpace(root.body.String()) != "" || len(root.children) > maxFirebaseXMLFields {
			return nil
		}
		for _, a := range root.attrs {
			if a.Name.Space != "xmlns" && a.Name.Local != "xmlns" {
				return nil
			}
		}
		for _, node := range root.children {
			name, valid := "", true
			for _, a := range node.attrs {
				if a.Name.Space != "" {
					valid = false
					continue
				}
				switch a.Name.Local {
				case "name":
					name = a.Value
				case "translatable", "formatted":
					valid = valid && (a.Value == "true" || a.Value == "false")
				default:
					valid = false
				}
			}
			if name != "" {
				fields = append(fields, field{name, node, valid})
			}
		}
	case "plist":
		if root.name.Local != "plist" || len(root.attrs) != 1 || len(root.children) != 1 || strings.TrimSpace(root.body.String()) != "" {
			return nil
		}
		a := root.attrs[0]
		if a.Name.Space != "" || a.Name.Local != "version" || a.Value != "1.0" {
			return nil
		}
		dict := root.children[0]
		if dict.name.Local != "dict" || len(dict.attrs) != 0 || strings.TrimSpace(dict.body.String()) != "" || len(dict.children)%2 != 0 || len(dict.children) > 2*maxFirebaseXMLFields {
			return nil
		}
		for i := 0; i < len(dict.children); i += 2 {
			key, value := dict.children[i], dict.children[i+1]
			if key.name.Local != "key" || len(key.attrs) != 0 || len(key.children) != 0 || key.body.Len() == 0 || key.body.Len() > 4096 {
				return nil
			}
			fields = append(fields, field{key.body.String(), value, len(value.attrs) == 0})
		}
	default:
		return nil
	}
	seen := map[string]bool{}
	for _, f := range fields {
		if seen[f.name] {
			out.valid = false
		}
		seen[f.name] = true
		role := algoliaXMLRole(f.name)
		if role == "" {
			continue
		}
		value, ok := firebaseXMLStatic(f.node, kind == "resources")
		ok = ok && f.valid
		if role == "app" {
			if !ok {
				value = ""
			}
			out.fields[f.name] = value
			continue
		}
		if !ok {
			out.incomplete = true
			continue
		}
		if len(f.node.dataSpans) == 0 {
			continue
		}
		start, end := f.node.dataSpans[0][0], f.node.dataSpans[len(f.node.dataSpans)-1][1]
		// Offsets include CDATA delimiters. Strip only the outer wrappers; internal
		// comments/CDATA boundaries remain part of the proven value expression.
		if strings.HasPrefix(text[start:end], "<![CDATA[") {
			start += 9
		}
		if strings.HasSuffix(text[start:end], "]]>") {
			end -= 3
		}
		out.keys = append(out.keys, algoliaXMLKey{f.name, value, start, end})
	}
	return out
}

func (b *algoliaXMLBindings) forSpan(start, end int, value string) map[string]string {
	if b == nil || !b.valid {
		return nil
	}
	for _, key := range b.keys {
		if key.start != start || key.end != end || key.value != value {
			continue
		}
		out := make(map[string]string, len(b.fields))
		for k, v := range b.fields {
			out[k] = v
		}
		return out
	}
	return nil
}

func (p *Pipeline) algoliaXMLCandidates(ctx context.Context, limit int) ([]ruleCandidate, bool) {
	b := p.options.publicBindings
	if b == nil || publicXMLKind(b.path) == "" {
		return nil, false
	}
	enabled := false
	for _, t := range p.options.Rules.Templates() {
		if t.ID == "algolia-api-key" {
			enabled = true
			break
		}
	}
	if !enabled {
		return nil, false
	}
	b.parse(ctx)
	if b.algolia == nil {
		if algoliaXMLSignal.MatchString(b.text) {
			model.Note(ctx, "public_xml_binding_unavailable", b.path, true)
		}
		return nil, false
	}
	if b.algolia.incomplete {
		model.Note(ctx, "public_xml_binding_unavailable", b.path, true)
	}
	// Projection only nominates through the actual selected rule (including its
	// entropy/custom constraints). It cannot enable a disabled rule or bind a peer.
	var projection strings.Builder
	type span struct {
		start, end int
		key        algoliaXMLKey
	}
	var spans []span
	for _, key := range b.algolia.keys {
		// Bound the projection independently of arbitrary literal values and names.
		if len(key.value) != 32 || strings.ContainsAny(key.value, "\"\r\n\\") {
			continue
		}
		projection.WriteString(key.name + ` = "`)
		start := projection.Len()
		projection.WriteString(key.value)
		spans = append(spans, span{start, projection.Len(), key})
		projection.WriteString("\"\n")
	}
	hits, limited := p.options.Rules.MatchOccurrencesN(projection.String(), limit)
	var out []ruleCandidate
	for _, hit := range hits {
		if hit.RuleID != "algolia-api-key" {
			continue
		}
		for _, s := range spans {
			if hit.Start == s.start && hit.End == s.end && hit.Value == s.key.value {
				hit.Start, hit.End = s.key.start, s.key.end
				out = append(out, ruleCandidate{Hit: hit, xmlName: s.key.name})
				break
			}
		}
	}
	return out, limited
}
