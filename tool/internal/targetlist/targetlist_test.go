package targetlist

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func inventory(t *testing.T, raw string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadPreservesOrderAndDeduplicates(t *testing.T) {
	got, err := Read(inventory(t, "# owned inventory\r\n\r\n  a.example  \r\nb.example\ra.example\n\ta.example\t\nb.example\n"))
	// An embedded CR is data, not a newline; only conventional LF/CRLF records are split.
	want := []string{"a.example", "b.example\ra.example", "b.example"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("read=%v error=%v", got, err)
	}
}

func TestReadRejectsInvalidSuffixWithoutPartialList(t *testing.T) {
	for name, raw := range map[string]string{
		"invalid-utf8": "a.example\nb.\xffexample",
		"long-target":  "a.example\n" + strings.Repeat("x", MaxLine+1),
		"long-comment": "a.example\n#" + strings.Repeat("x", MaxLine),
		"entry-budget": strings.Repeat("a.example\n", MaxEntries+1),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := Read(inventory(t, raw))
			if err == nil || got != nil {
				t.Fatal("failed suffix returned a usable partial inventory")
			}
		})
	}
}

func TestReadBoundaryBudgets(t *testing.T) {
	for _, ending := range []string{"", "\n", "\r\n"} {
		raw := strings.Repeat("x", MaxLine)
		got, err := Read(inventory(t, raw+ending))
		if err != nil || !reflect.DeepEqual(got, []string{raw}) {
			t.Fatalf("maximum-length line refused: %v", err)
		}
	}
	got, err := Read(inventory(t, strings.Repeat("a.example\n", MaxEntries)))
	if err != nil || !reflect.DeepEqual(got, []string{"a.example"}) {
		t.Fatalf("maximum entry count refused: %v", err)
	}
}

func TestReadRequiresBoundedRegularSelection(t *testing.T) {
	dir := t.TempDir()
	for _, path := range []string{dir, filepath.Join(dir, "missing")} {
		if got, err := Read(path); err == nil || got != nil {
			t.Fatal("selected absent/wrong-type inventory accepted")
		}
	}
	path := filepath.Join(dir, "large")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	a, b := f.Truncate(MaxBytes+1), f.Close()
	if a != nil || b != nil {
		t.Fatalf("fixture: %v %v", a, b)
	}
	if got, err := Read(path); err == nil || got != nil {
		t.Fatal("oversized inventory accepted")
	}
}

func TestReadSupportsRegularFileAliases(t *testing.T) {
	path := inventory(t, "a.example\n")
	alias := filepath.Join(filepath.Dir(path), "alias")
	if err := os.Symlink(path, alias); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	got, err := Read(alias)
	if err != nil || !reflect.DeepEqual(got, []string{"a.example"}) {
		t.Fatalf("valid alias refused: %v", err)
	}
}
