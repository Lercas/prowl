package verify

import "testing"

// FuzzInterpolate asserts secret interpolation (incl. {{base64(...)}}) never panics on arbitrary
// templates or values.
func FuzzInterpolate(f *testing.F) {
	f.Add("token {{secret}}", "abc")
	f.Add("Basic {{base64(secret:)}}", "k")
	f.Add("{{base64(", "")
	f.Add("{{base64(secret){{secret}})}}", "x")
	f.Fuzz(func(t *testing.T, tmpl, val string) {
		_ = interpolate(tmpl, map[string]string{"secret": val})
	})
}
