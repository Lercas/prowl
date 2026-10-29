package scan

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/model"
	"gopkg.in/yaml.v3"
)

// yamlPasswordScalars uses the YAML parser's values without expanding aliases or converting nodes
// to application objects. Only bounded, single-line source scalars are mapped; folded/block scalars
// and alias references are not represented as literal credentials by this adapter.
func yamlPasswordScalars(ctx context.Context, it model.Item) map[int]detect.PasswordScalar {
	ext := strings.ToLower(filepath.Ext(model.SafeLocator(it.Path)))
	if ext != ".yaml" && ext != ".yml" {
		return nil
	}
	if len(it.Text) > 1<<20 {
		model.Note(ctx, "yaml_scalar_limit", it.Path, true)
		return nil
	}
	starts := []int{0}
	for i := range it.Text {
		if it.Text[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	result := map[int]detect.PasswordScalar{}
	columns := map[int][]int{}
	decoder := yaml.NewDecoder(strings.NewReader(it.Text))
	count := 0
	for ctx.Err() == nil {
		var doc yaml.Node
		if err := decoder.Decode(&doc); err != nil {
			if err != io.EOF {
				// The lexical pipeline still scans malformed files; parser recovery is not assumed.
				model.Note(ctx, "yaml_scalar_parse", it.Path, true)
			}
			return result
		}
		stack := []*yaml.Node{&doc}
		for len(stack) > 0 {
			if ctx.Err() != nil {
				return result
			}
			n := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			count++
			if count > 100000 {
				model.Note(ctx, "yaml_scalar_limit", it.Path, true)
				return result
			}
			stack = append(stack, n.Content...) // Alias is intentionally never followed.
			if n.Kind != yaml.ScalarNode || n.Line < 1 || n.Line > len(starts) || len(n.Value) < 6 || len(n.Value) > 4096 || strings.ContainsAny(n.Value, "\r\n") || n.Style&(yaml.LiteralStyle|yaml.FoldedStyle|yaml.TaggedStyle) != 0 {
				continue
			}
			positions, ok := columns[n.Line]
			if !ok {
				// Convert each requested line once, avoiding quadratic prefix walks on flow mappings.
				for i := starts[n.Line-1]; ; {
					positions = append(positions, i)
					if i == len(it.Text) || it.Text[i] == '\n' {
						break
					}
					_, size := utf8.DecodeRuneInString(it.Text[i:])
					i += size
				}
				columns[n.Line] = positions
			}
			if n.Column < 1 || n.Column > len(positions) {
				continue
			}
			start := positions[n.Column-1]
			end, ok := yamlScalarEnd(it.Text, start, n)
			if !ok {
				continue
			}
			if n.Style&(yaml.SingleQuotedStyle|yaml.DoubleQuotedStyle) != 0 {
				start++
			}
			result[start] = detect.PasswordScalar{Value: n.Value, End: end}
		}
	}
	return result
}

func yamlScalarEnd(text string, start int, node *yaml.Node) (int, bool) {
	if start >= len(text) {
		return 0, false
	}
	if node.Style&(yaml.SingleQuotedStyle|yaml.DoubleQuotedStyle) == 0 {
		end := start + len(node.Value)
		return end, end <= len(text) && text[start:end] == node.Value
	}
	quote := text[start]
	for end := start + 1; end < len(text) && end-start <= 4096; end++ {
		if text[end] == '\r' || text[end] == '\n' {
			return 0, false
		}
		if quote == '"' && text[end] == '\\' {
			end++
		} else if text[end] == quote {
			if quote == '\'' && end+1 < len(text) && text[end+1] == quote {
				end++
				continue
			}
			return end, true
		}
	}
	return 0, false
}
