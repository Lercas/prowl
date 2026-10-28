package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/report"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

func TestSARIFUnicodeColumnsFromBothProducers(t *testing.T) {
	const pattern = `OWNED_[A-Za-z0-9]{12}`
	det := detect.New(&taxonomy.Taxonomy{Types: []taxonomy.SecretType{{
		ID: "owned_cascade", Category: "cloud", Detection: taxonomy.Detection{Regex: pattern}, RE: regexp.MustCompile(pattern),
	}}})
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "owned.yaml"), []byte("id: owned_template\ninfo:\n  name: Owned column fixture\n  severity: high\nmatchers:\n  - type: regex\n    regex:\n      - TEMPLATE_[A-Za-z0-9]{12}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := rules.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"", "ASCII ", "Ключ ", "😀🙂 ", "KİȺǰ ", "a\u0301\t "} {
		for _, leading := range []string{"", "first\n", "first\r\n"} {
			text := leading + prefix + "OWNED_G7hJ9kL2mN5p " + prefix + "TEMPLATE_R4tV8w000001"
			const artifactURI = "https://owned.invalid/a%23b?x=%2F#state"
			fs := Findings(context.Background(), det, eng, nil, model.Item{Text: text, Source: "code", Path: "prod.env", ArtifactURI: artifactURI}, nil, nil)
			if len(fs) != 2 {
				t.Fatalf("fixture returned %d findings, want both producers", len(fs))
			}
			for _, f := range fs {
				if f.ArtifactURI != artifactURI || f.Path != "prod.env" {
					t.Fatalf("%s lost URI provenance or changed display identity", f.Type)
				}
			}
			var output bytes.Buffer
			if err := report.Write(&output, fs, "sarif", false); err != nil {
				t.Fatal(err)
			}
			var doc struct {
				Runs []struct {
					ColumnKind string
					Results    []struct {
						RuleID    string
						Locations []struct {
							PhysicalLocation struct {
								Region struct{ StartLine, StartColumn int }
							}
						}
					}
				}
			}
			if err := json.Unmarshal(output.Bytes(), &doc); err != nil {
				t.Fatal(err)
			}
			if doc.Runs[0].ColumnKind != "utf16CodeUnits" {
				t.Errorf("SARIF does not declare UTF-16 columns: %q", doc.Runs[0].ColumnKind)
			}
			for _, result := range doc.Runs[0].Results {
				token := "OWNED_"
				if result.RuleID == "owned_template" {
					token = "TEMPLATE_"
				}
				start := strings.Index(text, token)
				lineStart := strings.LastIndexByte(text[:start], '\n') + 1
				wantLine := strings.Count(text[:start], "\n") + 1
				wantColumn := len(utf16.Encode([]rune(text[lineStart:start]))) + 1
				region := result.Locations[0].PhysicalLocation.Region
				if region.StartLine != wantLine || region.StartColumn != wantColumn {
					t.Errorf("%s prefix=%q: SARIF at %d:%d, want %d:%d", result.RuleID, prefix, region.StartLine, region.StartColumn, wantLine, wantColumn)
				}
				for _, f := range fs {
					if f.Type == result.RuleID && (f.Line != wantLine || f.Col != start-lineStart+1) {
						t.Fatal("byte-based finding coordinates changed")
					}
				}
			}
			if strings.Contains(output.String(), "OWNED_G7hJ9kL2mN5p") || strings.Contains(output.String(), "TEMPLATE_R4tV8w000001") {
				t.Fatal("SARIF exposed a raw fixture value")
			}
		}
	}
}
