package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/targetlist"
)

func TestInvalidInventoryRefusedBeforeDomainOrHermesDiscovery(t *testing.T) {
	for name, command := range map[string]func([]string) int{"domain": cmdDomain, "hermes": cmdHermesAudit} {
		for kind, raw := range map[string]string{
			"invalid-utf8": "127.0.0.1\n\xff",
			"long-line":    "127.0.0.1\n" + strings.Repeat("x", targetlist.MaxLine+1),
			"entry-budget": strings.Repeat("127.0.0.1\n", targetlist.MaxEntries+1),
		} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				dir := t.TempDir()
				path, out := filepath.Join(dir, "inventory"), filepath.Join(dir, "report.json")
				if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(out, []byte("previous owned report"), 0o600); err != nil {
					t.Fatal(err)
				}
				if code := command([]string{"--authorized", "--targets", path, "--output", out}); code != 2 {
					t.Fatalf("invalid inventory returned %d", code)
				}
				after, err := os.ReadFile(out)
				if err != nil || string(after) != "previous owned report" {
					t.Fatal("invalid inventory replaced report")
				}
			})
		}
	}
}
