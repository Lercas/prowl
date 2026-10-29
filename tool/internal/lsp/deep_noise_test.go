package lsp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/rules"
	bundledrules "github.com/Lercas/prowl/tool/rules"
)

func TestEditorNoiseCorporaAndExactSourceRanges(t *testing.T) {
	e := newTestEngine(t)
	var err error
	e.eng, err = rules.LoadEmbedded(bundledrules.Files)
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []string{"noise-1.4.0.json", "noise-deep-1.4.0.json"} {
		raw, err := os.ReadFile("../scan/testdata/" + fixture)
		if err != nil {
			t.Fatal(err)
		}
		var cases []struct {
			Name, Path, Text, Truth, Value string
			Types                          []string
		}
		if err := json.Unmarshal(raw, &cases); err != nil {
			t.Fatal(err)
		}
		for _, c := range cases {
			t.Run(c.Name, func(t *testing.T) {
				ds := scanDiagnostics(e, "file:///workspace/"+c.Path, c.Text)
				if c.Truth == "negative" {
					if len(ds) != 0 {
						t.Fatalf("non-secret source produced %d diagnostics", len(ds))
					}
					return
				}
				if c.Truth == "ambiguous" {
					return
				}
				start := strings.Index(c.Text, c.Value)
				if start < 0 {
					t.Fatal("fixture lacks a literal source value")
				}
				sl, sc := offsetPos(c.Text, start)
				el, ec := offsetPos(c.Text, start+len(c.Value))
				for _, d := range ds {
					message := d["message"].(string)
					if strings.Contains(message, c.Value) {
						t.Fatal("editor diagnostic discloses a credential")
					}
					rangeValue := d["range"].(map[string]any)
					a := rangeValue["start"].(map[string]any)
					b := rangeValue["end"].(map[string]any)
					for _, typ := range c.Types {
						if strings.Contains(message, "possible secret: "+typ+" (") && a["line"] == sl && a["character"] == sc && b["line"] == el && b["character"] == ec {
							return
						}
					}
				}
				t.Fatalf("credential lacks an exact editor range or type, expected %v", c.Types)
			})
		}
	}
}

func TestEditorSharedPragmasAndRuleDeduplication(t *testing.T) {
	e := newTestEngine(t)
	var err error
	e.eng, err = rules.LoadEmbedded(bundledrules.Files)
	if err != nil {
		t.Fatal(err)
	}
	const line = `AZURE_CLIENT_SECRET="` + "\x4b" + `p9aZ2bYwcX4dWqeV8fUmgThS6iRnjQ7sL"`
	if ds := scanDiagnostics(e, "file:///config.env", line); len(ds) != 1 {
		t.Fatalf("one credential must yield one diagnostic, got %d", len(ds))
	}
	if ds := scanDiagnostics(e, "file:///config.env", line+" # prowl:allow"); len(ds) != 0 {
		t.Fatal("editor ignored a shared allow pragma")
	}
	if ds := scanDiagnostics(e, "file:///config.env", line+"; "+line+"\n"+line); len(ds) != 3 {
		t.Fatalf("distinct occurrences collapsed or duplicated in editor: %d", len(ds))
	}
}

func TestBatchPositionsAreUTF16AndBoundedOnDenseLines(t *testing.T) {
	text := strings.Repeat("🔐Пароль=token0123456789;", 18000)
	offsets := make([]int, 0, 36000)
	for i := 0; i < len(text); i += len("🔐Пароль=token0123456789;") {
		offsets = append(offsets, i+len("🔐Пароль="), i+len("🔐Пароль=token0123456789"))
	}
	start := time.Now()
	positions := offsetPositions(text, offsets)
	if time.Since(start) > 3*time.Second {
		t.Fatal("position conversion repeatedly rescanned a dense document")
	}
	for _, off := range []int{offsets[0], offsets[1], offsets[len(offsets)-1]} {
		line, col := offsetPos(text, off)
		if positions[off] != [2]int{line, col} {
			t.Fatal("batch conversion changed UTF-16 endpoint positions")
		}
	}
	unicodeText := "a🔐б\n\r\n🙂z"
	var unicodeOffsets []int
	for i := -1; i <= len(unicodeText)+1; i++ {
		unicodeOffsets = append(unicodeOffsets, i)
	}
	positions = offsetPositions(unicodeText, unicodeOffsets)
	for _, off := range unicodeOffsets {
		line, col := offsetPos(unicodeText, off)
		if positions[off] != [2]int{line, col} {
			t.Fatalf("UTF-16 position mismatch at offset %d", off)
		}
	}
}

func TestEditorCarriageReturnAndBOMRanges(t *testing.T) {
	e := newTestEngine(t)
	const value = "Winter42!Autumn"
	for _, separator := range []string{"\n", "\r", "\r\n"} {
		text := "\uFEFF{" + separator + `"password":"` + value + `"}`
		ds := scanDiagnostics(e, "file:///production.json", text)
		if len(ds) != 1 {
			t.Fatal("BOM/newline lost editor finding")
		}
		r := ds[0]["range"].(map[string]any)
		start, end := r["start"].(map[string]any), r["end"].(map[string]any)
		if start["line"] != 1 || start["character"] != 12 || end["line"] != 1 || end["character"] != 12+len(value) {
			t.Fatalf("editor newline span is incorrect: %+v", r)
		}
	}
}

func TestActualEditorBuildUsesBundledTemplatesAndRejectsCorruptOverlay(t *testing.T) {
	home := t.TempDir()
	t.Setenv("PROWL_HOME", home)
	t.Chdir(t.TempDir())
	e, err := build()
	if err != nil || e.eng == nil || e.eng.Len() != 175 {
		t.Fatalf("actual editor build omitted bundled rule coverage: %v", err)
	}
	ds := scanDiagnostics(e, "file:///production.json", `{"assemblyai":{"api_key":"`+"\x38"+`3ea947bc2567d10a5f390c2eb468d91"}}`)
	if len(ds) != 1 || !strings.Contains(ds[0]["message"].(string), "assemblyai-api-key") {
		t.Fatal("actual editor build lost typed namespace detection")
	}
	dir := filepath.Join(home, "rules")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.yaml"), []byte("not: [valid"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := build(); err == nil {
		t.Fatal("editor started with a corrupt installed rules overlay")
	}
	if e, err := buildWithBundled(true); err != nil || e.eng.Len() != 175 {
		t.Fatal("bundled editor mode read the installed overlay")
	}
}
