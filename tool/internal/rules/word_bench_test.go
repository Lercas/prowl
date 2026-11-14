package rules

import (
	"fmt"
	"strings"
	"testing"
)

func BenchmarkWordMatchers(b *testing.B) {
	for _, size := range []int{1024, 1 << 20} {
		for _, positive := range []bool{false, true} {
			b.Run(fmt.Sprintf("bytes=%d/active=%v", size, positive), func(b *testing.B) {
				e := &Engine{}
				for i := range 128 {
					tpl := &Template{ID: fmt.Sprintf("word-%d", i), Matchers: []Matcher{
						{Type: "word", Words: []string{"CONTEXT"}},
						{Type: "word", Words: []string{fmt.Sprintf("ABSENT_%d", i)}, Negative: true},
					}}
					if err := tpl.compile(); err != nil {
						b.Fatal(err)
					}
					e.templates = append(e.templates, tpl)
				}
				text := strings.Repeat("PUBLIC PAYLOAD;", size/15)
				if positive {
					text += "CONTEXT"
				}
				e.Match(text)
				b.ReportAllocs()
				b.SetBytes(int64(len(text)))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					e.Match(text)
				}
			})
		}
	}
}
