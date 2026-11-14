package localfile

import (
	"encoding/hex"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

// ParseSHA256Manifest parses sha256sum lines, preserving filename bytes and refusing ambiguous
// duplicates or paths outside the selected library. name is only a diagnostic label.
func ParseSHA256Manifest(raw []byte, name string) (map[string]string, error) {
	out := map[string]string{}
	for ln, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		escaped := strings.HasPrefix(line, `\`)
		if escaped {
			line = line[1:]
		}
		if len(line) < 66 {
			return nil, fmt.Errorf("%s:%d: malformed manifest line", name, ln+1)
		}
		if _, err := hex.DecodeString(line[:64]); err != nil {
			return nil, fmt.Errorf("%s:%d: malformed manifest checksum", name, ln+1)
		}
		rest := line[64:]
		var rel string
		switch {
		case strings.HasPrefix(rest, "  "), strings.HasPrefix(rest, " *"):
			rel = rest[2:]
		case rest[0] == ' ' || rest[0] == '\t':
			rel = strings.TrimLeft(rest, " \t")
		default:
			return nil, fmt.Errorf("%s:%d: missing checksum separator", name, ln+1)
		}
		if escaped {
			var b strings.Builder
			for i := 0; i < len(rel); i++ {
				if rel[i] != '\\' {
					b.WriteByte(rel[i])
					continue
				}
				i++
				if i >= len(rel) {
					return nil, fmt.Errorf("%s:%d: incomplete filename escape", name, ln+1)
				}
				switch rel[i] {
				case '\\':
					b.WriteByte('\\')
				case 'n':
					b.WriteByte('\n')
				case 'r':
					b.WriteByte('\r')
				default:
					return nil, fmt.Errorf("%s:%d: unknown filename escape", name, ln+1)
				}
			}
			rel = b.String()
		}
		rel = filepath.ToSlash(rel)
		if !fs.ValidPath(rel) || rel == "." {
			return nil, fmt.Errorf("%s:%d: invalid relative path %q", name, ln+1, rel)
		}
		if _, exists := out[rel]; exists {
			return nil, fmt.Errorf("%s:%d: duplicate path %q", name, ln+1, rel)
		}
		out[rel] = strings.ToLower(line[:64])
	}
	return out, nil
}

// SHA256ManifestLine encodes a filename using the untagged sha256sum escaping convention.
func SHA256ManifestLine(sum [32]byte, rel string) string {
	prefix := ""
	if strings.ContainsAny(rel, "\\\n\r") {
		prefix = `\`
		rel = strings.NewReplacer(`\`, `\\`, "\n", `\n`, "\r", `\r`).Replace(rel)
	}
	return fmt.Sprintf("%s%x  %s\n", prefix, sum, rel)
}
