package scan

import (
	"context"
	"encoding/base64"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Lercas/prowl/tool/internal/model"
	"gopkg.in/yaml.v3"
)

func yamlLiterals(ctx context.Context, it model.Item) *literalDocument {
	ext := strings.ToLower(filepath.Ext(model.SafeLocator(it.Path)))
	if !pathIsFilesystem(it.Source) || ext != ".yaml" && ext != ".yml" {
		return nil
	}
	note := func(code string) { model.Note(ctx, code, it.Path, true) }
	if len(it.Text) > 1<<20 {
		note("yaml_scalar_limit")
		return nil
	}
	if !utf8.ValidString(it.Text) {
		note("yaml_scalar_parse")
		return nil
	}
	source := newYAMLSource(it.Text)
	physical := map[*yaml.Node]*yamlPhysical{}
	membership := map[*yaml.Node]int{}
	var inventory []*yamlPhysical
	var roots []*yaml.Node
	mapGroups := map[*yaml.Node]int{}
	docGroups := map[*yaml.Node]int{}
	roles := map[int]literalRole{}
	group := 0
	decoder := yaml.NewDecoder(strings.NewReader(it.Text))
	count := 0
	for ctx.Err() == nil {
		var root yaml.Node
		if err := decoder.Decode(&root); err != nil {
			if err != io.EOF {
				note("yaml_scalar_parse")
				return nil
			}
			break
		}
		roots = append(roots, &root)
		type frame struct {
			node  *yaml.Node
			depth int
			flow  bool
			group int
			key   *yaml.Node
			role  literalRole
		}
		stack := []frame{{node: &root}}
		for len(stack) > 0 {
			if ctx.Err() != nil {
				return nil
			}
			f := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			n := f.node
			if f.key != nil && (n.Kind == yaml.MappingNode || n.Kind == yaml.SequenceNode) {
				f.role = f.role.child(f.key.Value)
			}
			if n.Kind == yaml.DocumentNode {
				group++
				f.group = group
				docGroups[n] = group
			}
			count++
			if count > 100000 || f.depth > 64 || len(n.Value) > 4096 {
				note("yaml_scalar_limit")
				return nil
			}
			membership[n] = len(roots)
			if n.Tag != "" && !yamlKnownTag(n.Tag) {
				note("yaml_tag_unresolved")
			}
			if n.Kind == yaml.MappingNode {
				group++
				mapGroups[n] = group
				roles[group] = f.role
				for i := 0; i+1 < len(n.Content); i += 2 {
					key, value := n.Content[i], n.Content[i+1]
					flow := f.flow || n.Style&yaml.FlowStyle != 0
					stack = append(stack, frame{node: key, depth: f.depth + 1, flow: flow, group: group, role: f.role}, frame{node: value, depth: f.depth + 1, flow: flow, group: group, key: key, role: f.role})
				}
			} else {
				for _, child := range n.Content {
					stack = append(stack, frame{node: child, depth: f.depth + 1, flow: f.flow || n.Style&yaml.FlowStyle != 0, group: f.group, role: f.role})
				}
			}
			if n.Kind != yaml.ScalarNode && n.Kind != yaml.AliasNode {
				continue
			}
			start, ok := source.offset(n)
			if !ok {
				note("yaml_scalar_mapping")
				return nil
			}
			p := &yamlPhysical{node: n, start: start, flow: f.flow, group: f.group, key: f.key}
			physical[n] = p
			inventory = append(inventory, p)
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	if !source.physical(inventory) {
		note("yaml_scalar_mapping")
		return nil
	}
	// The binary tag explicitly identifies Base64 data. YAML presentation whitespace is not part
	// of the binary payload; map each decoded byte back through its exact encoded quartet.
	for _, p := range inventory {
		if p.node.Tag != "!!binary" {
			continue
		}
		v := &p.literal
		var encoded []byte
		var positions []int
		for i, c := range []byte(v.value) {
			if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
				continue
			}
			encoded = append(encoded, c)
			positions = append(positions, i)
		}
		decoded, err := base64.StdEncoding.DecodeString(string(encoded))
		if err != nil {
			note("yaml_binary_parse")
			continue
		}
		starts, ends := make([]int, len(decoded)), make([]int, len(decoded))
		for i := range decoded {
			quartet := i / 3 * 4
			starts[i] = v.sourceStarts[positions[quartet]]
			ends[i] = v.sourceEnds[positions[min(quartet+3, len(positions)-1)]]
		}
		v.value, v.sourceStarts, v.sourceEnds, v.transform = string(decoded), starts, ends, "yaml-binary"
	}
	doc := &literalDocument{original: it.Text, lines: newLineIndex(it.Text), transform: "yaml-scalar", roles: roles, unsafeGroups: map[int]bool{}}
	doc.lines.resetPragmas()
	doc.pragmas = &lineIndex{text: it.Text, starts: source.starts, pragmaCache: make([]int8, len(source.starts))}
	visits, work := 0, 0
	limited := false
	add := func(v sourceLiteral) {
		if len(doc.values) >= 10000 || work+len(v.value)+len(v.name) > 8<<20 {
			limited = true
			return
		}
		work += len(v.value) + len(v.name)
		doc.values = append(doc.values, v)
	}
	evidence := func(p *yamlPhysical, transform string) model.Evidence {
		start, end := p.start, p.end
		if p.node.Kind == yaml.ScalarNode {
			start, end = p.literal.start, p.literal.end
		}
		line, col := doc.lines.cols(start)
		return model.Evidence{Path: model.SafeLocator(it.Path), Start: start, End: end, Line: line, Col: col, Transform: transform}
	}
	resolveKey := func(n *yaml.Node) (string, []model.Evidence) {
		if n == nil {
			return "", nil
		}
		var proof []model.Evidence
		seen := map[*yaml.Node]bool{}
		for n.Kind == yaml.AliasNode {
			if seen[n] || len(seen) >= 32 || n.Alias == nil || membership[n] != membership[n.Alias] {
				return "", nil
			}
			seen[n] = true
			proof = append(proof, evidence(physical[n], "yaml-binding-alias"))
			n = n.Alias
		}
		if n.Kind != yaml.ScalarNode {
			return "", nil
		}
		if len(proof) > 0 {
			proof = append(proof, evidence(physical[n], "yaml-anchor-key"))
		}
		return n.Value, proof
	}
	// Physical declarations are always scanned, including defaults overridden by a later merge.
	// Alias expansion adds use sites while preserving each declaration's own object context.
	for _, p := range inventory {
		if p.node.Kind != yaml.ScalarNode {
			continue
		}
		v := p.literal
		v.name, v.proof = resolveKey(p.key)
		v.group, v.noPassword = p.group, !yamlPasswordScalar(p.node) && (v.transform != "yaml-binary" || !utf8.ValidString(v.value))
		add(v)
	}
	path := map[*yaml.Node]bool{}
	var walk func(*yaml.Node, string, int, *yamlPhysical, []model.Evidence, int)
	var mapping func(*yaml.Node, int, *yamlPhysical, []model.Evidence, int, map[string]bool)
	var merge func(*yaml.Node, int, *yamlPhysical, []model.Evidence, int, map[string]bool)
	merge = func(n *yaml.Node, gid int, ref *yamlPhysical, proof []model.Evidence, depth int, assigned map[string]bool) {
		if ctx.Err() != nil || limited {
			return
		}
		visits++
		if visits > 100000 || depth > 32 {
			limited = true
			return
		}
		if path[n] {
			note("yaml_alias_cycle")
			return
		}
		path[n] = true
		defer delete(path, n)
		switch n.Kind {
		case yaml.AliasNode:
			if n.Alias == nil || membership[n] != membership[n.Alias] {
				note("yaml_alias_cross_document")
				return
			}
			if ref == nil {
				ref = physical[n]
			}
			proof = append(append([]model.Evidence(nil), proof...), evidence(physical[n], "yaml-alias-reference"))
			merge(n.Alias, gid, ref, proof, depth+1, assigned)
		case yaml.MappingNode:
			mapping(n, gid, ref, proof, depth+1, assigned)
		case yaml.SequenceNode:
			for _, child := range n.Content {
				merge(child, gid, ref, proof, depth+1, assigned)
			}
		default:
			note("yaml_merge_unresolved")
		}
	}
	mapping = func(n *yaml.Node, gid int, ref *yamlPhysical, proof []model.Evidence, depth int, assigned map[string]bool) {
		keys := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			key := n.Content[i]
			if key.Tag == "!!merge" {
				continue
			}
			name, keyProof := resolveKey(key)
			if name == "" && key.Kind != yaml.ScalarNode {
				note("yaml_complex_key")
			}
			if keys[name] {
				note("yaml_duplicate_key")
				doc.unsafeGroups[gid] = true
			}
			keys[name] = true
			if assigned != nil && assigned[name] {
				continue
			}
			walk(key, "", gid, ref, proof, depth+1)
			valueProof := append(append([]model.Evidence(nil), proof...), keyProof...)
			walk(n.Content[i+1], name, gid, ref, valueProof, depth+1)
		}
		if assigned == nil {
			assigned = map[string]bool{}
		}
		for name := range keys {
			assigned[name] = true
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Tag == "!!merge" {
				primary, mergeProof := ref, proof
				if primary == nil && n.Content[i+1].Kind != yaml.AliasNode {
					primary = physical[n.Content[i]]
					mergeProof = append(append([]model.Evidence(nil), proof...), evidence(primary, "yaml-merge-reference"))
				}
				merge(n.Content[i+1], gid, primary, mergeProof, depth+1, assigned)
			}
		}
	}
	walk = func(n *yaml.Node, name string, gid int, ref *yamlPhysical, proof []model.Evidence, depth int) {
		if ctx.Err() != nil || limited {
			return
		}
		visits++
		if visits > 100000 || depth > 64 {
			limited = true
			return
		}
		if path[n] {
			note("yaml_alias_cycle")
			return
		}
		path[n] = true
		defer delete(path, n)
		switch n.Kind {
		case yaml.DocumentNode, yaml.SequenceNode:
			for _, child := range n.Content {
				walk(child, name, gid, ref, proof, depth+1)
			}
		case yaml.MappingNode:
			mappingGroup := mapGroups[n]
			if ref != nil {
				group++
				mappingGroup = group
				roles[group] = roles[gid].child(name)
			}
			mapping(n, mappingGroup, ref, proof, depth+1, nil)
		case yaml.AliasNode:
			if n.Alias == nil || membership[n] != membership[n.Alias] {
				note("yaml_alias_cross_document")
				return
			}
			if ref == nil {
				ref = physical[n]
			}
			proof = append(append([]model.Evidence(nil), proof...), evidence(physical[n], "yaml-alias-reference"))
			walk(n.Alias, name, gid, ref, proof, depth+1)
		case yaml.ScalarNode:
			if ref == nil {
				return // The physical declaration is already in the inventory.
			}
			v := physical[n].literal
			v.name, v.group, v.proof = name, gid, proof
			v.noPassword = !yamlPasswordScalar(n) && (v.transform != "yaml-binary" || !utf8.ValidString(v.value))
			if ref != nil {
				if v.transform == "yaml-binary" {
					v.proof = append(append([]model.Evidence(nil), proof...), evidence(physical[n], "yaml-binary"))
				}
				v.start, v.end, v.whole, v.transform = ref.start, ref.end, true, "yaml-alias"
				if ref.node.Tag == "!!merge" {
					v.transform = "yaml-merge"
				}
				v.proof = append(append([]model.Evidence(nil), v.proof...), evidence(physical[n], "yaml-anchor-value"))
			}
			add(v)
		}
	}
	for _, root := range roots {
		walk(root, "", docGroups[root], nil, nil, 0)
	}
	// Keep the source outside literal bodies, including comments, anchors, tags and alias names.
	// This complement prevents normalization from hiding credentials carried by presentation data.
	uses := map[int]map[string]bool{}
	for _, v := range doc.values {
		if v.whole {
			if uses[v.start] == nil {
				uses[v.start] = map[string]bool{}
			}
			uses[v.start][v.value] = true
		}
	}
	last := 0
	addGap := func(start, end int) {
		if end > start && strings.TrimSpace(it.Text[start:end]) != "" {
			add(sourceLiteral{value: it.Text[start:end], start: start, end: end, raw: true})
		}
	}
	for _, p := range inventory {
		if p.node.Kind == yaml.AliasNode {
			addGap(last, p.start)
			// A credential-shaped reference naming that same canonical credential is one use site.
			// Avoid submitting its presentation spelling to verification as an extra occurrence.
			if !uses[p.start][p.node.Value] {
				addGap(p.start, p.end)
			}
			last = p.end
			continue
		}
		addGap(last, p.body)
		last = p.literal.end
	}
	addGap(last, len(it.Text))
	// Comments cannot originate inside quoted or block string bodies. Plain-scalar comments are
	// separated by whitespace; comments outside the inventory are retained by the complement above.
	for _, v := range doc.values {
		if !v.raw {
			continue
		}
		for i := v.start; i < v.end; i++ {
			if it.Text[i] == '#' && yamlSpaceBefore(it.Text, i) {
				end, _ := yamlLineEnd(it.Text, i, v.end)
				doc.pragmas.markCommentPragmas(i, end)
				i = end - 1
			}
		}
	}
	if limited {
		note("yaml_scalar_limit")
	}
	sort.SliceStable(doc.values, func(i, j int) bool { return doc.values[i].start < doc.values[j].start })
	doc.prepare()
	return doc
}

func yamlPasswordScalar(n *yaml.Node) bool {
	if n.Tag == "!!str" {
		return true
	}
	if n.Tag != "!!int" || n.Value == "" || len(n.Value) > 1 && n.Value[0] == '0' {
		return false
	}
	for _, c := range n.Value {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true // Explicit decimal passwords retain the established weak-password contract.
}

func yamlKnownTag(tag string) bool {
	switch tag {
	case "!!str", "!!int", "!!float", "!!bool", "!!null", "!!timestamp", "!!binary", "!!merge", "!!map", "!!seq":
		return true
	}
	return false
}
