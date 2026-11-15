package reconstruct

import (
	"context"
	"reflect"
	"sort"
	"unicode/utf8"

	"github.com/grafana/sobek/ast"
	jsparser "github.com/grafana/sobek/parser"
	jstoken "github.com/grafana/sobek/token"
)

const maxBindingNodes = 100000
const maxBindingFields = 4096
const maxBindingGroups = 512
const maxBindingNumericAtom = 4096

type boundScalar struct {
	span   Span
	value  string
	fields map[string]string
}

// ObjectBindings retains only explicitly co-located static values. It never resolves
// identifiers, executes code, or merges sibling objects or separate declarations.
type ObjectBindings struct{ scalars []boundScalar }

// ForSpan requires both a source-contained expression and its complete decoded value.
// Equal secrets in other objects cannot supply this occurrence's companion fields.
func (b *ObjectBindings) ForSpan(start, end int, value string) map[string]string {
	if b == nil || start < 0 || start >= end {
		return nil
	}
	index := sort.Search(len(b.scalars), func(i int) bool { return b.scalars[i].span.End > start })
	if index == len(b.scalars) {
		return nil
	}
	scalar := b.scalars[index]
	if start < scalar.span.Start || end > scalar.span.End || value != scalar.value {
		return nil
	}
	found := scalar.fields
	result := make(map[string]string, len(found))
	for k, v := range found {
		result[k] = v
	}
	return result
}

// ParseObjectBindings parses source with pinned Sobek AST code only, without its runtime.
// Module/script parsing is bounded and source-map I/O is disabled in both modes.
// Any syntax error, cancellation, panic or budget failure discards all bindings.
func ParseObjectBindings(ctx context.Context, text string) (result *ObjectBindings) {
	defer func() {
		if recover() != nil {
			result = nil
		}
	}()
	if ctx.Err() != nil || len(text) > maxInput || !utf8.ValidString(text) || !boundedNumericAtoms(text) {
		return nil
	}
	program, err := jsparser.ParseFile(nil, "", text, 0, jsparser.IsModule, jsparser.WithDisableSourceMaps)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		program, err = jsparser.ParseFile(nil, "", text, 0, jsparser.WithDisableSourceMaps)
	}
	if err != nil || ctx.Err() != nil {
		return nil
	}
	out := &ObjectBindings{}
	base := program.File.Base()
	groups, fields := 0, 0
	visit := func(node any) bool {
		var entries []bindingField
		switch n := node.(type) {
		case *ast.ObjectLiteral:
			entries = objectFields(n)
		case *ast.LexicalDeclaration:
			if n.Token == jstoken.CONST {
				entries = declarationFields(n)
			}
		}
		if len(entries) == 0 {
			return true
		}
		groups++
		fields += len(entries)
		if groups > maxBindingGroups || fields > maxBindingFields {
			return false
		}
		values := make(map[string]string, len(entries))
		for _, field := range entries {
			if _, exists := values[field.name]; exists {
				return true
			} // Reject the complete ambiguous group.
			values[field.name] = ""
		}
		var scalars []boundScalar
		for _, field := range entries {
			value, ok := staticString(field.value, 0)
			if !ok {
				continue
			} // Unknown aliases remain explicit empty values, never silently omitted.
			values[field.name] = value
			span := Span{int(field.value.Idx0()) - base, int(field.value.Idx1()) - base}
			if span.Start < 0 || span.Start >= span.End || span.End > len(text) {
				return false
			}
			scalars = append(scalars, boundScalar{span, value, values})
		}
		out.scalars = append(out.scalars, scalars...)
		return true
	}
	if !walkBindings(ctx, reflect.ValueOf(program), visit) {
		return nil
	}
	sort.Slice(out.scalars, func(i, j int) bool { return out.scalars[i].span.Start < out.scalars[j].span.Start })
	for i := 1; i < len(out.scalars); i++ {
		if out.scalars[i-1].span.End > out.scalars[i].span.Start {
			return nil
		}
	}
	return out
}

type bindingField struct {
	name  string
	value ast.Expression
}

func objectFields(object *ast.ObjectLiteral) []bindingField {
	if len(object.Value) > 128 {
		return nil
	}
	fields := make([]bindingField, 0, len(object.Value))
	for _, property := range object.Value {
		switch p := property.(type) {
		case *ast.PropertyKeyed:
			if p.Computed || p.Kind != ast.PropertyKindValue {
				return nil
			}
			var name string
			switch key := p.Key.(type) {
			case *ast.Identifier:
				name = key.Name.String()
			case *ast.StringLiteral:
				name = key.Value.String()
			default:
				return nil
			}
			fields = append(fields, bindingField{name, p.Value})
		case *ast.PropertyShort:
			// Shorthand values are unresolved, including aliases which could conflict.
			fields = append(fields, bindingField{p.Name.Name.String(), nil})
		default:
			return nil // Spread, getters, methods and computed names cannot override known fields.
		}
	}
	return fields
}

func declarationFields(declaration *ast.LexicalDeclaration) []bindingField {
	if len(declaration.List) > 128 {
		return nil
	}
	fields := make([]bindingField, 0, len(declaration.List))
	for _, binding := range declaration.List {
		identifier, ok := binding.Target.(*ast.Identifier)
		if !ok {
			return nil
		}
		fields = append(fields, bindingField{identifier.Name.String(), binding.Initializer})
	}
	return fields
}

func staticString(expression ast.Expression, depth int) (string, bool) {
	if depth > 8 {
		return "", false
	}
	switch e := expression.(type) {
	case *ast.StringLiteral:
		value := e.Value.String()
		return value, !e.Sloppy && len(value) <= maxValue && utf8.ValidString(value)
	case *ast.TemplateLiteral:
		if e.Tag != nil || len(e.Expressions) != 0 || len(e.Elements) != 1 || !e.Elements[0].Valid {
			return "", false
		}
		value := e.Elements[0].Parsed.String()
		return value, len(value) <= maxValue && utf8.ValidString(value)
	case *ast.BinaryExpression:
		if e.Operator != jstoken.PLUS {
			return "", false
		}
		left, ok := staticString(e.Left, depth+1)
		if !ok {
			return "", false
		}
		right, ok := staticString(e.Right, depth+1)
		if !ok || len(left)+len(right) > maxValue {
			return "", false
		}
		return left + right, true
	}
	return "", false
}

// Reflect only through AST-owned containers, skipping file metadata and other packages.
// Pointer de-duplication also skips declaration-list aliases of already visited nodes.
func walkBindings(ctx context.Context, root reflect.Value, visit func(any) bool) bool {
	const astPackage = "github.com/grafana/sobek/ast"
	seen := make(map[uintptr]bool)
	nodes := 0
	var walk func(reflect.Value, int) bool
	walk = func(v reflect.Value, depth int) bool {
		if !v.IsValid() {
			return true
		}
		if depth > 256 || ctx.Err() != nil {
			return false
		}
		if v.Kind() == reflect.Interface {
			if v.IsNil() {
				return true
			}
			return walk(v.Elem(), depth+1)
		}
		if v.Kind() == reflect.Pointer {
			if v.IsNil() || v.Type().Elem().PkgPath() != astPackage {
				return true
			}
			pointer := v.Pointer()
			if seen[pointer] {
				return true
			}
			seen[pointer] = true
			nodes++
			if nodes > maxBindingNodes || !visit(v.Interface()) {
				return false
			}
			return walk(v.Elem(), depth+1)
		}
		switch v.Kind() {
		case reflect.Struct:
			if v.Type().PkgPath() != astPackage {
				return true
			}
			for i := 0; i < v.NumField(); i++ {
				if !walk(v.Field(i), depth+1) {
					return false
				}
			}
		case reflect.Slice:
			if v.Len() > maxBindingNodes {
				return false
			}
			for i := 0; i < v.Len(); i++ {
				if !walk(v.Index(i), depth+1) {
					return false
				}
			}
		}
		return true
	}
	return walk(root, 0)
}

// Bound numeral conversion before the third-party parser constructs big.Int values.
// This conservative byte check may reject a long digit-led atom inside text too.
func boundedNumericAtoms(text string) bool {
	for i := 0; i < len(text); i++ {
		if text[i] < '0' || text[i] > '9' {
			continue
		}
		start := i
		for i < len(text) && (ident(text[i]) || text[i] >= '0' && text[i] <= '9') {
			i++
		}
		if i-start > maxBindingNumericAtom {
			return false
		}
	}
	return true
}
