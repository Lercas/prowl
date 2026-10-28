package lsp

import (
	"sort"
	"unicode/utf8"
)

const positionStride = 256

type positionCheckpoint struct {
	offset, line, character int
}

// positionIndex shares UTF-16 checkpoints across every range in one document. It is built lazily
// after the first surviving finding, so empty/allowlisted scans don't need another document pass.
type positionIndex struct {
	text        string
	checkpoints []positionCheckpoint
}

func (p *positionIndex) build() {
	p.checkpoints = make([]positionCheckpoint, 1, len(p.text)/positionStride+1)
	line, character := 0, 0
	for i := 0; i < len(p.text); {
		if i-p.checkpoints[len(p.checkpoints)-1].offset >= positionStride {
			// Always checkpoint at a rune boundary, including on a long line with no newlines.
			p.checkpoints = append(p.checkpoints, positionCheckpoint{i, line, character})
		}
		r, size := utf8.DecodeRuneInString(p.text[i:])
		if r == '\n' || r == '\r' {
			line, character = line+1, 0
			if r == '\r' && i+1 < len(p.text) && p.text[i+1] == '\n' {
				size = 2
			}
		} else if r > 0xFFFF {
			character += 2
		} else {
			character++
		}
		i += size
	}
}

func (p *positionIndex) at(off int) (int, int) {
	if off < 0 {
		off = 0
	} else if off > len(p.text) {
		off = len(p.text)
	}
	if len(p.checkpoints) == 0 {
		p.build()
	}
	i := sort.Search(len(p.checkpoints), func(i int) bool { return p.checkpoints[i].offset > off }) - 1
	c := p.checkpoints[i]
	for pos := c.offset; pos < off; {
		r, size := utf8.DecodeRuneInString(p.text[pos:])
		if r == '\n' || r == '\r' {
			c.line, c.character = c.line+1, 0
			if r == '\r' && pos+1 < len(p.text) && p.text[pos+1] == '\n' {
				size = 2
			}
		} else if r > 0xFFFF {
			c.character += 2
		} else {
			c.character++
		}
		pos += size
	}
	return c.line, c.character
}
