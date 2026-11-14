package scan

import "strings"

// Parsers start with no exceptions and mark only established comment spans.
func (li *lineIndex) resetPragmas() {
	for i := range li.pragmaCache {
		li.pragmaCache[i] = 0
	}
}

func (li *lineIndex) markCommentPragmas(start, end int) {
	for start < end {
		line := li.lineAt(start)
		right := end
		if line+1 < len(li.starts) {
			right = min(right, li.starts[line+1])
		}
		comment := strings.ToLower(li.text[start:right])
		for _, marker := range allowPragmas {
			for from := 0; from < len(comment); {
				off := strings.Index(comment[from:], marker)
				if off < 0 {
					break
				}
				off += from
				left, right := off-1, off+len(marker)
				if (left < 0 || !pragmaWordByte(comment[left])) && (right == len(comment) || !pragmaWordByte(comment[right])) {
					li.pragmaCache[line] = 1
					break
				}
				from = off + len(marker)
			}
		}
		start = right
	}
}

func pragmaWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c >= 0x80
}
