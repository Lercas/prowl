package scan

import (
	"sort"
	"unicode/utf8"
)

const utf16Stride = 256

type utf16Checkpoint struct {
	offset, units int
}

// utf16Col converts a byte offset using the scanned text, never by reopening the reported path.
// Checkpoints bound each lookup even when thousands of matches share one long line.
func (li *lineIndex) utf16Col(pos int) int {
	if pos < 0 {
		pos = 0
	} else if pos > len(li.text) {
		pos = len(li.text)
	}
	start := li.starts[li.lineAt(pos)]
	return li.utf16Prefix(pos) - li.utf16Prefix(start) + 1
}

func (li *lineIndex) utf16Prefix(off int) int {
	if len(li.utf16Checkpoints) == 0 {
		li.utf16Checkpoints = make([]utf16Checkpoint, 1, len(li.text)/utf16Stride+1)
		units := 0
		for pos := 0; pos < len(li.text); {
			if pos-li.utf16Checkpoints[len(li.utf16Checkpoints)-1].offset >= utf16Stride {
				li.utf16Checkpoints = append(li.utf16Checkpoints, utf16Checkpoint{pos, units})
			}
			r, size := utf8.DecodeRuneInString(li.text[pos:])
			units++
			if r > 0xFFFF {
				units++
			}
			pos += size
		}
	}
	i := sort.Search(len(li.utf16Checkpoints), func(i int) bool { return li.utf16Checkpoints[i].offset > off }) - 1
	c := li.utf16Checkpoints[i]
	for pos := c.offset; pos < off; {
		r, size := utf8.DecodeRuneInString(li.text[pos:])
		c.units++
		if r > 0xFFFF {
			c.units++
		}
		pos += size
	}
	return c.units
}
