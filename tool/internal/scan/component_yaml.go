package scan

import (
	"context"

	"gopkg.in/yaml.v3"
)

const componentYAMLRevision = "indexed-namespaces-yaml-v2"

// Resolve only explicit edges inside the one document accepted by componentFields.
// Arrays retain their exact ordinal positions; merge operands must still be mappings.
type componentYAMLDecoder struct {
	ctx    context.Context
	active map[*yaml.Node]bool
	visits int
	bytes  int
}

func (d *componentYAMLDecoder) value(node *yaml.Node, depth int) (any, bool) {
	if node == nil || d.ctx.Err() != nil || depth > 64 || d.active[node] || d.visits >= componentMaxLiterals {
		return nil, false
	}
	d.visits++
	d.bytes += len(node.Value)
	if d.bytes > componentMaxNamespaceBytes {
		return nil, false
	}
	d.active[node] = true
	defer delete(d.active, node)
	switch node.Kind {
	case yaml.AliasNode:
		return d.value(node.Alias, depth+1)
	case yaml.ScalarNode:
		if !yamlKnownTag(node.Tag) {
			return nil, false
		}
		if node.Tag == "!!str" {
			return node.Value, true
		}
		return nil, true // An explicit unknown role must still poison borrowing.
	case yaml.SequenceNode:
		if node.Tag != "!!seq" || len(node.Content) > componentMaxLiterals-d.visits {
			return nil, false
		}
		out := make([]any, len(node.Content))
		for i, child := range node.Content {
			value, ok := d.value(child, depth+1)
			if !ok {
				return nil, false
			}
			out[i] = value
		}
		return out, true
	case yaml.MappingNode:
		if node.Tag != "!!map" || len(node.Content)%2 != 0 {
			return nil, false
		}
		out := make(map[string]any)
		var merge *yaml.Node
		for i := 0; i < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if key.Tag == "!!merge" && key.Kind == yaml.ScalarNode {
				if merge != nil || key.Value != "<<" {
					return nil, false
				}
				merge = value
				continue
			}
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return nil, false
			}
			d.bytes += len(key.Value)
			if d.bytes > componentMaxNamespaceBytes {
				return nil, false
			}
			if _, duplicate := out[key.Value]; duplicate {
				return nil, false
			}
			decoded, ok := d.value(value, depth+1)
			if !ok {
				return nil, false
			}
			out[key.Value] = decoded
		}
		if merge != nil && !d.merge(out, merge, depth+1) {
			return nil, false
		}
		return out, true
	}
	return nil, false
}

func (d *componentYAMLDecoder) merge(out map[string]any, node *yaml.Node, depth int) bool {
	if node == nil || d.ctx.Err() != nil || depth > 64 {
		return false
	}
	if node.Kind == yaml.SequenceNode {
		if d.active[node] || d.visits >= componentMaxLiterals {
			return false
		}
		d.visits++
		d.active[node] = true
		defer delete(d.active, node)
		if node.Tag != "!!seq" || len(node.Content) > componentMaxLiterals-d.visits {
			return false
		}
		for _, child := range node.Content {
			if !d.mergeMapping(out, child, depth+1) {
				return false
			}
		}
		return true
	}
	return d.mergeMapping(out, node, depth)
}

func (d *componentYAMLDecoder) mergeMapping(out map[string]any, node *yaml.Node, depth int) bool {
	value, ok := d.value(node, depth)
	mapping, mapped := value.(map[string]any)
	if !ok || !mapped {
		return false
	}
	for key, value := range mapping {
		if _, explicitOrEarlier := out[key]; !explicitOrEarlier {
			out[key] = value
		}
	}
	return true
}
