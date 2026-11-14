package jsonstrict

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"unicode"
)

// UnmarshalContext rejects ambiguous fields and lossy encodings before decoding a complete JSON
// document. Keys in dynamic maps remain case-sensitive; keys matched to struct fields use the same
// case-insensitive comparison as encoding/json. Dynamic numbers use json.Number without float64
// rounding. The destination is changed only after success.
func UnmarshalContext(ctx context.Context, raw []byte, out any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dst := reflect.ValueOf(out)
	if dst.Kind() != reflect.Pointer || dst.IsNil() {
		return errors.New("JSON destination must be a non-nil pointer")
	}
	if err := ValidateEncoding(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	fields := make(map[reflect.Type]map[string]reflect.Type)
	if err := checkValue(ctx, dec, dst.Type().Elem(), fields); err != nil {
		return err
	}
	parsed := reflect.New(dst.Type().Elem())
	reader := json.NewDecoder(bytes.NewReader(raw))
	reader.UseNumber()
	if err := reader.Decode(parsed.Interface()); err != nil {
		// Syntax/type errors may quote an attacker-controlled field or value.
		return errors.New("JSON response does not match the destination type")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	dst.Elem().Set(parsed.Elem())
	return nil
}

func dereference(t reflect.Type) reflect.Type {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

func checkValue(ctx context.Context, dec *json.Decoder, shape reflect.Type, cache map[reflect.Type]map[string]reflect.Type) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	token, err := dec.Token()
	if err != nil {
		return errors.New("invalid JSON value")
	}
	shape = dereference(shape)
	switch token {
	case json.Delim('{'):
		var fields map[string]reflect.Type
		if shape != nil && shape.Kind() == reflect.Struct {
			fields = cache[shape]
			if fields == nil {
				fields = structFields(shape)
				cache[shape] = fields
			}
		}
		// encoding/json selects the first field in name order for a folded-name match.
		names := make([]string, 0, len(fields))
		for name := range fields {
			names = append(names, name)
		}
		sort.Strings(names)
		seen := make(map[string]bool)
		for dec.More() {
			if err := ctx.Err(); err != nil {
				return err
			}
			token, err := dec.Token()
			key, ok := token.(string)
			if err != nil || !ok {
				return errors.New("invalid JSON object key")
			}
			identity := key
			child := fields[key]
			if child == nil {
				for _, name := range names {
					if strings.EqualFold(key, name) {
						identity, child = name, fields[name]
						break
					}
				}
			}
			if child == nil && shape != nil && shape.Kind() == reflect.Map {
				child = shape.Elem()
			}
			if seen[identity] {
				return errors.New("duplicate JSON object field")
			}
			seen[identity] = true
			if err := checkValue(ctx, dec, child, cache); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	case json.Delim('['):
		var child reflect.Type
		if shape != nil && (shape.Kind() == reflect.Array || shape.Kind() == reflect.Slice) {
			child = shape.Elem()
		}
		for dec.More() {
			if err := checkValue(ctx, dec, child, cache); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	}
	return nil
}

// structFields follows encoding/json's embedding dominance rules: shallow fields win, then tagged
// fields at the same depth. Ambiguous embedded fields are ignored, as they are by encoding/json.
func structFields(t reflect.Type) map[string]reflect.Type {
	type candidate struct {
		t      reflect.Type
		depth  int
		tagged bool
	}
	candidates := make(map[string][]candidate)
	var visit func(reflect.Type, int, map[reflect.Type]bool)
	visit = func(t reflect.Type, depth int, ancestors map[reflect.Type]bool) {
		if ancestors[t] {
			return
		}
		ancestors[t] = true
		defer delete(ancestors, t)
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			ft := dereference(f.Type)
			if f.PkgPath != "" && (!f.Anonymous || ft.Kind() != reflect.Struct) {
				continue
			}
			tag := f.Tag.Get("json")
			if tag == "-" {
				continue
			}
			name := strings.Split(tag, ",")[0]
			if !validTagName(name) {
				name = ""
			}
			if name == "" && f.Anonymous && ft.Kind() == reflect.Struct {
				visit(ft, depth+1, ancestors)
				continue
			}
			tagged := name != ""
			if name == "" {
				name = f.Name
			}
			candidates[name] = append(candidates[name], candidate{f.Type, depth, tagged})
		}
	}
	visit(t, 0, make(map[reflect.Type]bool))
	fields := make(map[string]reflect.Type)
	for name, entries := range candidates {
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].depth != entries[j].depth {
				return entries[i].depth < entries[j].depth
			}
			return entries[i].tagged && !entries[j].tagged
		})
		if len(entries) > 1 && entries[0].depth == entries[1].depth && entries[0].tagged == entries[1].tagged {
			continue
		}
		fields[name] = entries[0].t
	}
	return fields
}

func validTagName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if !strings.ContainsRune("!#$%&()*+-./:;<=>?@[]^_{|}~ ", r) && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}
