package rules

import "testing"

// FuzzParseTemplate asserts loading a malformed rule template never panics, and a parsed template
// can be run safely.
func FuzzParseTemplate(f *testing.F) {
	f.Add([]byte("id: x\nmatchers:\n  - type: regex\n    regex: ['a+']"))
	f.Add([]byte("id: y\nmatchers:\n  - type: word\n    words: [k]\n  - type: entropy\n    min: 3"))
	f.Add([]byte("{{{"))
	f.Add([]byte("matchers: not-a-list"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		tmpl, err := ParseTemplate(raw, "fuzz")
		if err == nil && tmpl != nil {
			_ = tmpl.Match("api_key = AKIA1234567890ABCDEF token sk-abc", "api_key = akia1234567890abcdef token sk-abc")
		}
	})
}
