package model

import (
	"encoding"
	"encoding/json"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/Lercas/prowl/tool/internal/jsonstrict"
)

// Scope policies must survive JSON without silent string repairs. Byte slices
// are safe because JSON represents them as base64, not as UTF-8 strings.
func scopePolicyBytes(policy any) (raw []byte, valid bool) {
	defer func() {
		if recover() != nil {
			raw = nil
			valid = false
		}
	}()
	remaining := 1_000_000
	if !scopeValueUTF8(reflect.ValueOf(policy), 0, &remaining) {
		return nil, false
	}
	var err error
	raw, err = json.Marshal(policy)
	if err != nil || jsonstrict.ValidateEncoding(raw) != nil {
		return nil, false
	}
	return raw, true
}

func scopeValueUTF8(value reflect.Value, depth int, remaining *int) bool {
	if !value.IsValid() {
		return true
	}
	(*remaining)--
	if depth > 128 || *remaining < 0 {
		return false
	}
	// Text marshalers can introduce bytes that JSON silently repairs. Scope policies
	// use plain data or raw JSON; do not certify an opaque text conversion.
	if value.Type().Implements(reflect.TypeFor[encoding.TextMarshaler]()) {
		return false
	}
	switch value.Kind() {
	case reflect.Interface, reflect.Pointer:
		return value.IsNil() || scopeValueUTF8(value.Elem(), depth+1, remaining)
	case reflect.String:
		return utf8.ValidString(value.String())
	case reflect.Map:
		iter := value.MapRange()
		for iter.Next() {
			if !scopeValueUTF8(iter.Key(), depth+1, remaining) || !scopeValueUTF8(iter.Value(), depth+1, remaining) {
				return false
			}
		}
	case reflect.Slice, reflect.Array:
		if value.Type().Elem() == reflect.TypeFor[byte]() {
			return true
		}
		for i := 0; i < value.Len(); i++ {
			if !scopeValueUTF8(value.Index(i), depth+1, remaining) {
				return false
			}
		}
	case reflect.Struct:
		typ := value.Type()
		for i := 0; i < value.NumField(); i++ {
			field := typ.Field(i)
			fieldType := field.Type
			if fieldType.Kind() == reflect.Pointer {
				fieldType = fieldType.Elem()
			}
			// JSON promotes exported members of unexported embedded structs.
			promoted := field.Anonymous && fieldType.Kind() == reflect.Struct
			if (field.PkgPath != "" && !promoted) || strings.Split(field.Tag.Get("json"), ",")[0] == "-" {
				continue
			}
			if !scopeValueUTF8(value.Field(i), depth+1, remaining) {
				return false
			}
		}
	}
	return true
}
