package rules

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// minimalRule returns a valid (error-free) rule template body with the given id.
func minimalRule(id string) string {
	return "id: " + id + "\n" +
		"info:\n" +
		"  name: " + id + "\n" +
		"  severity: high\n" +
		"  tags: test\n" +
		"category: generic\n" +
		"matchers:\n" +
		"  - type: regex\n" +
		"    regex:\n" +
		"      - 'XYZ[0-9A-Z]{16}'\n"
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// managedTree lists, slash-separated and sorted, every managed file (.yaml/.yml/SCHEMA.md, excluding
// the manifest) physically present under dir — i.e. what the tool actually installed on disk.
func managedTree(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !managedFile(path) {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

// TestUpdateMirrorsShrink: updating from a large set to a small one must leave the target holding
// exactly the small set (+ manifest), not the union — orphans must be deleted.
func TestUpdateMirrorsShrink(t *testing.T) {
	target := t.TempDir()

	// First install: several rules across nested categories, plus a SCHEMA.md.
	big := t.TempDir()
	writeFile(t, filepath.Join(big, "cloud", "aws.yaml"), minimalRule("aws"))
	writeFile(t, filepath.Join(big, "cloud", "gcp.yml"), minimalRule("gcp"))
	writeFile(t, filepath.Join(big, "db", "postgres.yaml"), minimalRule("postgres"))
	writeFile(t, filepath.Join(big, "generic", "password.yaml"), minimalRule("password"))
	writeFile(t, filepath.Join(big, "SCHEMA.md"), "# schema\n")

	res, err := Update(UpdateOpts{Source: big, Target: target, Now: "t0"})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if res.Manifest.Count != 4 {
		t.Fatalf("install manifest count = %d, want 4", res.Manifest.Count)
	}
	if got := len(managedTree(t, target)); got != 5 { // 4 yaml + SCHEMA.md
		t.Fatalf("after install: %d managed files on disk, want 5: %v", got, managedTree(t, target))
	}

	// Second install: a single rule in one category. Everything else must be removed.
	small := t.TempDir()
	writeFile(t, filepath.Join(small, "cloud", "aws.yaml"), minimalRule("aws"))

	res, err = Update(UpdateOpts{Source: small, Target: target, Now: "t1"})
	if err != nil {
		t.Fatalf("shrink: %v", err)
	}
	if res.Manifest.Count != 1 {
		t.Fatalf("shrink manifest count = %d, want 1", res.Manifest.Count)
	}
	// The diff should account for the removals (the old SCHEMA.md is not hashed, so Removed tracks the
	// 3 orphaned yaml rules; the point of the test is that the *disk* is mirrored regardless).
	if len(res.Removed) != 3 {
		t.Errorf("Removed = %v, want 3 entries", res.Removed)
	}

	// Disk must now hold exactly the small set + manifest.
	got := managedTree(t, target)
	want := []string{"cloud/aws.yaml"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("after shrink, managed files on disk = %v, want %v", got, want)
	}

	// The manifest file itself must survive the mirror.
	if _, err := os.Stat(filepath.Join(target, ManifestName)); err != nil {
		t.Fatalf("manifest was deleted by mirror: %v", err)
	}

	// Manifest must not lie: its Count and Files match what is on disk.
	m := ReadManifest(target)
	if m.Count != 1 || len(m.Files) != 1 || m.Files["cloud/aws.yaml"] == "" {
		t.Fatalf("manifest disagrees with disk: %+v", m)
	}

	// The now-empty orphaned subdirectories (db/, generic/) should be pruned.
	for _, sub := range []string{"db", "generic"} {
		if _, err := os.Stat(filepath.Join(target, sub)); !os.IsNotExist(err) {
			t.Errorf("empty orphan subdir %q not pruned (err=%v)", sub, err)
		}
	}
}

// TestUpdateMirrorsSwitch covers switching to a disjoint ruleset (no shared files) — the classic
// "can't switch rulesets" symptom.
func TestUpdateMirrorsSwitch(t *testing.T) {
	target := t.TempDir()

	a := t.TempDir()
	writeFile(t, filepath.Join(a, "x.yaml"), minimalRule("x"))
	writeFile(t, filepath.Join(a, "y.yaml"), minimalRule("y"))
	if _, err := Update(UpdateOpts{Source: a, Target: target, Now: "t0"}); err != nil {
		t.Fatal(err)
	}

	b := t.TempDir()
	writeFile(t, filepath.Join(b, "z.yaml"), minimalRule("z"))
	if _, err := Update(UpdateOpts{Source: b, Target: target, Now: "t1"}); err != nil {
		t.Fatal(err)
	}

	got := managedTree(t, target)
	if strings.Join(got, ",") != "z.yaml" {
		t.Fatalf("after switch, disk = %v, want [z.yaml]", got)
	}
}

// TestCheckWritesNothing guards the constraint that --check must not mutate the target at all,
// including the new delete pass.
func TestCheckWritesNothing(t *testing.T) {
	target := t.TempDir()
	cur := t.TempDir()
	writeFile(t, filepath.Join(cur, "keep.yaml"), minimalRule("keep"))
	if _, err := Update(UpdateOpts{Source: cur, Target: target, Now: "t0"}); err != nil {
		t.Fatal(err)
	}
	before := managedTree(t, target)

	// --check against a totally different (empty-of-keep) source must report a removal but touch nothing.
	other := t.TempDir()
	writeFile(t, filepath.Join(other, "new.yaml"), minimalRule("new"))
	res, err := Update(UpdateOpts{Source: other, Target: target, Now: "t1", Check: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Removed) != 1 || res.Removed[0] != "keep.yaml" {
		t.Errorf("check should report keep.yaml removed, got %v", res.Removed)
	}
	if after := managedTree(t, target); strings.Join(after, ",") != strings.Join(before, ",") {
		t.Fatalf("--check mutated the target: before=%v after=%v", before, after)
	}
}

// TestMirrorDeleteLeavesSymlinksAndForeignFiles confirms the mirror never follows a symlink and never
// touches files it does not manage (e.g. a README the user dropped in).
func TestMirrorDeleteLeavesSymlinksAndForeignFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	target := t.TempDir()

	src := t.TempDir()
	writeFile(t, filepath.Join(src, "real.yaml"), minimalRule("real"))
	if _, err := Update(UpdateOpts{Source: src, Target: target, Now: "t0"}); err != nil {
		t.Fatal(err)
	}

	// A foreign (unmanaged) file the tool must leave alone.
	foreign := filepath.Join(target, "notes.txt")
	if err := os.WriteFile(foreign, []byte("user notes"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A symlink whose name *looks* managed, pointing outside the target. The mirror must not follow it
	// (which would delete the external target) — at most it could unlink the link itself, but our
	// policy is to leave symlinks untouched entirely.
	outside := filepath.Join(t.TempDir(), "external.yaml")
	if err := os.WriteFile(outside, []byte("DO NOT DELETE"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(target, "evil.yaml")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}

	// Re-install the same single-file set; mirror runs its delete pass.
	if _, err := Update(UpdateOpts{Source: src, Target: target, Now: "t1"}); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(foreign); err != nil {
		t.Errorf("unmanaged file was deleted: %v", err)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Errorf("mirror followed a symlink and deleted its external target: %v", err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("symlink should be left untouched (err=%v)", err)
	}
}
