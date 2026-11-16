package model

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
)

type scopeEmbedded struct{ Path string }
type scopeEmbeddedPolicy struct{ scopeEmbedded }
type scopePointerPolicy struct{ *scopeEmbedded }
type scopePanicPolicy struct{}

func (scopePanicPolicy) MarshalJSON() ([]byte, error) { panic("private policy") }

type scopeTextPolicy int

func (scopeTextPolicy) MarshalText() ([]byte, error) { return []byte{0xff}, nil }

type scopeTextByte byte

func (scopeTextByte) MarshalText() ([]byte, error) { return []byte{0xff}, nil }

func TestScopeEncodingFailureCannotCertifyCompleteness(t *testing.T) {
	cycle := map[string]any{}
	cycle["self"] = cycle
	invalid := "owned-\xff.env"
	cases := map[string]any{
		"string": invalid, "map-value": map[string]any{"path": invalid}, "map-key": map[string]int{"owned-\xfe": 1},
		"nested-pointer": &struct{ Paths []string }{[]string{invalid}},
		"embedded":       scopeEmbeddedPolicy{scopeEmbedded{invalid}}, "embedded-pointer": scopePointerPolicy{&scopeEmbedded{invalid}},
		"nan": math.NaN(), "infinity": math.Inf(1), "function": func() {}, "cycle": cycle, "panic": scopePanicPolicy{},
		"opaque-text": scopeTextPolicy(1), "opaque-map-key": map[scopeTextPolicy]int{1: 1},
		"opaque-byte-slice": []scopeTextByte{1}, "opaque-byte-array": [1]scopeTextByte{1},
		"raw-invalid-utf8": json.RawMessage{'"', 0xff, '"'}, "raw-unpaired-surrogate": json.RawMessage(`"\ud800"`),
	}
	for name, policy := range cases {
		t.Run(name, func(t *testing.T) {
			c := NewCoverage()
			c.RegisterScope("valid", "/owned", map[string]int{"version": 1})
			c.RegisterScope("filesystem", "/private-target", policy)
			finding := Finding{Type: "owned-test"}
			result := NewResult([]Finding{finding}, c)
			if result.Complete || result.CompletionReason != "incomplete" || len(result.Scope) != 1 || result.Scope[0].Kind != "valid" {
				t.Fatalf("invalid scope certified: %+v", result)
			}
			if !reflect.DeepEqual(result.Findings, []Finding{finding}) {
				t.Fatal("source finding lost")
			}
			if !reflect.DeepEqual(result.Diagnostics, []Diagnostic{{Code: "scope_policy_failed", Incomplete: true}}) {
				t.Fatalf("unsafe diagnostic: %+v", result.Diagnostics)
			}
		})
	}
	for _, pair := range [][2]string{{invalid, "/owned"}, {"filesystem", invalid}} {
		c := NewCoverage()
		c.RegisterScope(pair[0], pair[1], nil)
		result := NewResult(nil, c)
		if result.Complete || len(result.Scope) != 0 || len(result.Diagnostics) != 1 || result.Diagnostics[0].Path != "" {
			t.Fatalf("invalid locator certified: %+v", result)
		}
	}
}
func TestScopeEncodingPreservesValidPolicyDigests(t *testing.T) {
	cases := []any{nil, "Unicode: \ufffd 日本語", map[string]any{"paths": []string{"a", "é"}}, []byte{0xff, 0xfe}, [2]byte{0xff, 0xfe},
		struct {
			Path    string
			Ignored string `json:"-"`
			private string
		}{"owned", "\xff", "\xfe"},
		scopeEmbeddedPolicy{scopeEmbedded{"owned"}}, json.RawMessage(`{"path":"\ud83d\ude00"}`),
	}
	for i, policy := range cases {
		raw, err := json.Marshal(policy)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range [][]byte{nil, []byte(strings.Repeat("k", 32))} {
			c := NewCoverage()
			c.SetIdentityScope(key)
			c.RegisterScope("filesystem", "/owned", policy)
			sum := sha256.Sum256(raw)
			digest := sum[:]
			if len(key) > 0 {
				mac := hmac.New(sha256.New, key)
				_, _ = mac.Write(raw)
				digest = mac.Sum(nil)
			}
			result := NewResult(nil, c)
			if !result.Complete || len(result.Scope) != 1 || result.Scope[0].Policy != hex.EncodeToString(digest) {
				t.Fatalf("valid policy %d changed: %+v", i, result)
			}
		}
	}
}
func TestScopeEncodingValidationBounds(t *testing.T) {
	var nested any = "owned"
	for range 130 {
		nested = []any{nested}
	}
	for _, policy := range []any{nested, make([]int, 1_000_001)} {
		c := NewCoverage()
		c.RegisterScope("filesystem", "/owned", policy)
		if NewResult(nil, c).Complete {
			t.Fatal("unbounded policy certified")
		}
	}
	remaining := 1
	if !scopeValueUTF8(reflect.ValueOf("owned"), 128, &remaining) || remaining != 0 {
		t.Fatal("inclusive validation boundary changed")
	}
	remaining = 1
	if scopeValueUTF8(reflect.ValueOf("owned"), 129, &remaining) {
		t.Fatal("depth bound ignored")
	}
	remaining = 0
	if scopeValueUTF8(reflect.ValueOf("owned"), 0, &remaining) {
		t.Fatal("node bound ignored")
	}
}
