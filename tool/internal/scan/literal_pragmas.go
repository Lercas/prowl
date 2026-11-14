package scan

// JSON has no operator comments: even a literal prowl:allow is only data.
func (li *lineIndex) resetPragmas() {
	for i := range li.pragmaCache {
		li.pragmaCache[i] = 0
	}
}
