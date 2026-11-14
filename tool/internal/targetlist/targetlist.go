// Package targetlist loads bounded operator-supplied inventories before discovery starts.
package targetlist

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/Lercas/prowl/tool/internal/localfile"
)

const (
	MaxBytes   = 16 * 1024 * 1024
	MaxEntries = 10000
	MaxLine    = 4096
)

// Read requires a complete regular UTF-8 file. Comments and blanks are skipped; exact duplicates
// retain their first occurrence. Entry limits count all non-comment lines, including duplicates.
// Host/IP validation is owned by the caller. No partial list is returned on a read or parse error.
func Read(path string) ([]string, error) {
	raw, err := localfile.ReadRegular(path, MaxBytes)
	if err != nil {
		return nil, fmt.Errorf("target inventory read: %w", err)
	}
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("target inventory must be valid UTF-8")
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	// Allow a maximum-length line plus CRLF and Scanner's lookahead, then check its actual size.
	sc.Buffer(make([]byte, MaxLine+3), MaxLine+3)
	seen := map[string]bool{}
	var out []string
	entries, lineNumber := 0, 0
	for sc.Scan() {
		lineNumber++
		if len(sc.Bytes()) > MaxLine {
			return nil, fmt.Errorf("target inventory line %d exceeds %d bytes", lineNumber, MaxLine)
		}
		target := strings.TrimSpace(sc.Text())
		if target == "" || strings.HasPrefix(target, "#") {
			continue
		}
		entries++
		if entries > MaxEntries {
			return nil, fmt.Errorf("target inventory exceeds %d entries", MaxEntries)
		}
		if !seen[target] {
			seen[target] = true
			out = append(out, target)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("target inventory parse: %w", err)
	}
	return out, nil
}
