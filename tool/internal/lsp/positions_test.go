package lsp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

func TestPositionIndexPreservesUTF16Coordinates(t *testing.T) {
	for _, text := range []string{"", "Русский😀\r\nsecond line\n", strings.Repeat("a😀К\xff", 300), strings.Repeat("\n", 1000)} {
		index := positionIndex{text: text}
		for off := -1; off <= len(text)+1; off++ {
			line, character := index.at(off)
			wantLine, wantCharacter := offsetPos(text, off)
			if line != wantLine || character != wantCharacter {
				t.Fatalf("UTF-16 position changed at byte %d: got (%d,%d), want (%d,%d)", off, line, character, wantLine, wantCharacter)
			}
		}
	}
}

func TestDenseDiagnosticsShareCorrectPositionsAcrossBothEngines(t *testing.T) {
	tax := &taxonomy.Taxonomy{Types: []taxonomy.SecretType{{ID: "owned_position_cascade", Category: "cloud", RE: regexp.MustCompile(`CASCADE_[A-Za-z0-9]{12}`)}}}
	dir := t.TempDir()
	body := "id: owned-position-template\ninfo:\n  name: Owned position fixture\n  severity: high\nmatchers:\n  - type: regex\n    regex:\n      - TEMPLATE_[A-Za-z0-9]{12}\n"
	if err := os.WriteFile(filepath.Join(dir, "owned.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := rules.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	e := &engine{det: detect.New(tax), eng: eng, maxBytes: defaultMaxScanBytes}
	const count = 2000
	var document strings.Builder
	for i := 0; i < count; i++ {
		fmt.Fprintf(&document, "Ключ😀 CASCADE_G7hJ9kL2mN5p TEMPLATE_R%011d\n", i+10000000000)
	}
	diags := scanDiagnostics(e, "file:///owned/prod.env", document.String())
	if len(diags) != count*2 {
		t.Fatalf("lost diagnostics: got %d, want %d", len(diags), count*2)
	}
	for i, diagnostic := range diags {
		row, start, end := i, 7, 27
		if i >= count {
			row, start, end = i-count, 28, 49
		}
		rangeValue := diagnostic["range"].(map[string]any)
		for side, character := range map[string]int{"start": start, "end": end} {
			position := rangeValue[side].(map[string]any)
			if position["line"] != row || position["character"] != character {
				t.Fatalf("wrong %s position at diagnostic %d: %v", side, i, position)
			}
		}
	}
	raw, err := json.Marshal(diags)
	if err != nil || strings.Contains(string(raw), "G7hJ9kL2mN5p") || strings.Contains(string(raw), "TEMPLATE_R10000000000") {
		t.Fatal("diagnostics exposed fixture values or could not serialize")
	}
}

func FuzzPositionIndexUTF16(f *testing.F) {
	for _, text := range []string{"", "a😀К\r\nb", "\xff\xfeК\n😀", strings.Repeat("К😀x", 100)} {
		f.Add(text, 0)
		f.Add(text, len(text)/2)
	}
	f.Fuzz(func(t *testing.T, text string, off int) {
		if len(text) > 64<<10 {
			return
		}
		index := positionIndex{text: text}
		for _, query := range []int{off, len(text), len(text) / 2, 0, -1} {
			line, character := index.at(query)
			wantLine, wantCharacter := offsetPos(text, query)
			if line != wantLine || character != wantCharacter {
				t.Fatalf("position differs from the linear UTF-16 reference: byte=%d got=(%d,%d) want=(%d,%d)", query, line, character, wantLine, wantCharacter)
			}
		}
	})
}
