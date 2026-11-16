package source

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestWorkingTreeBoundaryRejectsLateStatRebinding(t *testing.T) {
	for _, mutation := range []string{"leaf-symlink", "leaf-file", "parent-symlink", "parent-symlink-same-file", "parent-directory", "marker-create", "marker-remove", "marker-replace"} {
		t.Run(mutation, func(t *testing.T) {
			dir := t.TempDir()
			for _, name := range []string{"config", "foreign"} {
				if err := os.Mkdir(filepath.Join(dir, name), 0700); err != nil {
					t.Fatal(err)
				}
			}
			write(t, filepath.Join(dir, "config/key.json"), `{"account":"owned"}`)
			if mutation == "parent-symlink-same-file" {
				if err := os.Link(filepath.Join(dir, "config/key.json"), filepath.Join(dir, "foreign/key.json")); err != nil {
					t.Skipf("hardlinks unavailable: %v", err)
				}
			} else {
				write(t, filepath.Join(dir, "foreign/key.json"), `{"account":"foreign"}`)
			}
			if mutation == "marker-remove" || mutation == "marker-replace" {
				if err := os.Mkdir(filepath.Join(dir, "config/.git"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			observations := &worktreeObservations{}
			paths := []string{"config", "config/.git", "config/key.json"}
			for _, path := range paths {
				if _, err := observations.observe(root, path); err != nil {
					t.Fatal(err)
				}
			}
			rename := func(old, next string) {
				t.Helper()
				if err := os.Rename(filepath.Join(dir, old), filepath.Join(dir, next)); err != nil {
					t.Fatal(err)
				}
			}
			link := func(target, path string) {
				t.Helper()
				if err := os.Symlink(target, filepath.Join(dir, path)); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			}
			switch mutation {
			case "leaf-symlink":
				rename("config/key.json", "config/saved.json")
				link("../foreign/key.json", "config/key.json")
			case "leaf-file":
				rename("config/key.json", "config/saved.json")
				write(t, filepath.Join(dir, "config/key.json"), `{"account":"replacement"}`)
			case "parent-symlink", "parent-symlink-same-file":
				rename("config", "saved")
				link("foreign", "config")
			case "parent-directory":
				rename("config", "saved")
				rename("foreign", "config")
			case "marker-remove":
				rename("config/.git", "config/saved-git")
			case "marker-replace":
				rename("config/.git", "config/saved-git")
				fallthrough
			case "marker-create":
				if err := os.Mkdir(filepath.Join(dir, "config/.git"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			// Replay the former gate: Stat after the boundary check, then fstat.
			// Both observations see the replacement and falsely accept its identity.
			late, err := root.Stat("config/key.json")
			if err != nil {
				t.Fatal(err)
			}
			file, err := root.Open("config/key.json")
			if err != nil {
				t.Fatal(err)
			}
			actual, err := file.Stat()
			_ = file.Close()
			if err != nil || !os.SameFile(late, actual) {
				t.Fatal("fixture did not reproduce the former late-Stat acceptance")
			}
			file, err = observations.open(root, "config/key.json", late, paths)
			if file != nil {
				_ = file.Close()
			}
			if err == nil {
				t.Fatal("changed path or repository boundary was accepted")
			}
		})
	}
}

func TestWorkingTreeBoundaryRemembersAbsenceAndBoundsMetadata(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	o := &worktreeObservations{}
	if _, err := o.observe(root, "missing"); err != nil {
		t.Fatal(err)
	}
	if err := o.validate(root, []string{"missing"}); err != nil {
		t.Fatal("stable absence changed")
	}
	write(t, filepath.Join(dir, "missing"), "new boundary")
	if _, err := o.observe(root, "missing"); err == nil {
		t.Fatal("a later acquisition item ignored a new boundary")
	}
	o = &worktreeObservations{bytes: maxComponentRepositoryBytes}
	if _, err := o.observe(root, "missing"); err == nil {
		t.Fatal("path metadata escaped its byte budget")
	}
	o = &worktreeObservations{seen: make(map[string]os.FileInfo)}
	for i := range maxComponentWorktreeObservations {
		o.seen["entry-"+strconv.Itoa(i)] = nil
	}
	if _, err := o.observe(root, "missing"); err == nil {
		t.Fatal("observation count escaped its budget")
	}
}
