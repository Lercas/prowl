package scan

import "testing"

// TestImageFileName: the image label/layer prefix must be stripped before path heuristics so the user's
// arg (which may contain test/example) can't demote an image's findings, while an in-layer test/ path still does.
func TestImageFileName(t *testing.T) {
	cases := map[string]string{
		"test/app|layer0:config.py":   "config.py",          // label segment "test" -> stripped, not seen by isExamplePath
		"app|layer3:src/test/key.env": "src/test/key.env",   // in-layer "test" -> kept (real example path)
		"img|image:config/env":        "config/env",         // config item prefix stripped too
		"plain/file/path.go":          "plain/file/path.go", // non-image path unchanged
	}
	for in, want := range cases {
		if got := imageFileName(in); got != want {
			t.Errorf("imageFileName(%q) = %q, want %q", in, got, want)
		}
	}
}
