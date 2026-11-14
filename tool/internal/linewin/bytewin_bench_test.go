package linewin

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

func BenchmarkMinifiedRuleSearch(b *testing.B) {
	const count = 32
	res := make([]*regexp.Regexp, count)
	var content strings.Builder
	for i := range count {
		res[i] = regexp.MustCompile(fmt.Sprintf(`(?i)provider_%02d\s*[=:]\s*["']?([a-z0-9]{24,48})`, i))
		content.WriteString(strings.Repeat("var x=0;", 2048))
		fmt.Fprintf(&content, "provider_%02d='a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6';", i)
	}
	text := content.String()
	set := New(res)
	for _, windowed := range []bool{false, true} {
		b.Run(fmt.Sprintf("windowed=%v", windowed), func(b *testing.B) {
			b.SetBytes(int64(len(text)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var windows *Windows
				if windowed {
					windows = set.Prepare(text, "", "", nil)
				}
				for id, re := range res {
					if hits := windows.FindAll(id, re, text, 10); len(hits) != 1 {
						b.Fatalf("pattern %d: hits=%d", id, len(hits))
					}
				}
				windows.Release()
			}
		})
	}
}
