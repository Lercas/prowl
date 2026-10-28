package scan

import (
	"path/filepath"
	"strings"

	"github.com/Lercas/prowl/tool/internal/model"
)

const (
	pragmaHash uint8 = 1 << iota
	pragmaSlash
	pragmaBlock
	pragmaSQL
	pragmaINI
	pragmaHTML
	pragmaAll = pragmaHash | pragmaSlash | pragmaBlock | pragmaSQL | pragmaINI | pragmaHTML
)

func newSourceLineIndex(text, path string) *lineIndex {
	li := newLineIndex(text)
	path = strings.ToLower(model.SafeLocator(path))
	switch filepath.Ext(path) {
	case ".json":
		li.resetPragmas()
	case ".env", ".toml", ".yaml", ".yml", ".py", ".sh", ".bash", ".zsh", ".rb", ".pl", ".ps1", ".properties":
		li.pragmaSyntax = pragmaHash
	case ".ini", ".cfg", ".conf":
		li.pragmaSyntax = pragmaHash | pragmaINI
	case ".sql":
		li.pragmaSyntax = pragmaSQL | pragmaBlock
	case ".html", ".htm", ".xml", ".svg", ".md", ".rst":
		li.pragmaSyntax = pragmaHTML
	case ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".rs", ".c", ".h", ".cpp", ".hpp", ".java", ".kt", ".swift", ".cs", ".css":
		li.pragmaSyntax = pragmaSlash | pragmaBlock
	}
	if strings.HasPrefix(filepath.Base(path), ".env") {
		li.pragmaSyntax = pragmaHash
	}
	return li
}

// Only operator comments can suppress findings. A marker inside credential/data strings is data.
// Structured adapters replace this conservative lexer with their parser-established comment spans.
func (li *lineIndex) initPragmas() {
	for i := range li.pragmaCache {
		li.pragmaCache[i] = 0
	}
	text := li.text
	leading := true
	for i := 0; i < len(text); {
		if text[i] == '\'' || text[i] == '"' || text[i] == '`' {
			leading = false
			quote, width := text[i], 1
			if quote != '`' && i+2 < len(text) && text[i+1] == quote && text[i+2] == quote {
				width = 3
			}
			i += width
			for i < len(text) {
				if text[i] == '\\' {
					i += min(2, len(text)-i)
					continue
				}
				if text[i] == quote && (width == 1 || i+2 < len(text) && text[i+1] == quote && text[i+2] == quote) {
					i += width
					break
				}
				i++
			}
			continue
		}
		start, terminator := i, ""
		lineComment := false
		whiteBefore := i == 0 || strings.ContainsRune(" \t\r\n", rune(text[i-1]))
		switch {
		case li.pragmaSyntax&pragmaHTML != 0 && strings.HasPrefix(text[i:], "<!--"):
			terminator = "-->"
		case li.pragmaSyntax&pragmaBlock != 0 && strings.HasPrefix(text[i:], "/*"):
			terminator = "*/"
		case li.pragmaSyntax&pragmaSlash != 0 && strings.HasPrefix(text[i:], "//") && (i == 0 || text[i-1] != ':'):
			lineComment = true
		case li.pragmaSyntax&pragmaHash != 0 && text[i] == '#' && whiteBefore:
			lineComment = true
		case li.pragmaSyntax&pragmaSQL != 0 && strings.HasPrefix(text[i:], "--") && whiteBefore && i+2 < len(text) && strings.ContainsRune(" \t\r\n", rune(text[i+2])):
			lineComment = true
		case li.pragmaSyntax&pragmaINI != 0 && text[i] == ';' && leading:
			lineComment = true
		}
		if !lineComment && terminator == "" {
			if text[i] == '\n' || text[i] == '\r' {
				leading = true
			} else if text[i] != ' ' && text[i] != '\t' && text[i] != '\r' {
				leading = false
			}
			i++
			continue
		}
		if lineComment {
			for i < len(text) && text[i] != '\n' && text[i] != '\r' {
				i++
			}
		} else if end := strings.Index(text[i+2:], terminator); end >= 0 {
			i += 2 + end + len(terminator)
		} else {
			i = len(text)
		}
		li.markCommentPragmas(start, i)
		leading = false
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

func (li *lineIndex) resetPragmas() {
	for i := range li.pragmaCache {
		li.pragmaCache[i] = 0
	}
}
