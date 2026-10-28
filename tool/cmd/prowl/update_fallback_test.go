package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDefaultUpdateOnlyFallsBackWhenRemoteAcquisitionIsUnavailable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell git is POSIX-only")
	}
	for _, kind := range []string{"rules", "verifiers"} {
		for _, mode := range []string{"offline", "invalid-template", "invalid-revision"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				work, home, bin, remote := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
				t.Chdir(work)
				t.Setenv("PROWL_HOME", home)
				bundled := filepath.Join(work, kind)
				if err := os.Mkdir(bundled, 0o700); err != nil {
					t.Fatal(err)
				}
				if kind == "rules" {
					writeTemplate(t, bundled, "bundled-owned")
				} else if err := os.WriteFile(filepath.Join(bundled, "bundled-owned.yaml"), []byte("id: bundled-owned\nmatch: [bundled-owned]\nrequests:\n  - url: https://owned.invalid/identity\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(remote, "invalid.yaml"), []byte("id: [broken\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("PROWL_FETCH_LIBRARY", remote)
				t.Setenv("PROWL_FETCH_MODE", mode)
				script := "#!/bin/sh\nif [ \"$PROWL_FETCH_MODE\" = offline ]; then exit 6; fi\ncase \"$*\" in *rev-parse*) if [ \"$PROWL_FETCH_MODE\" = invalid-revision ]; then exit 3; fi; printf 'abc1234\\n'; exit 0;; esac\nfor dest do :; done\ncp -R \"$PROWL_FETCH_LIBRARY/.\" \"$dest\"\n"
				if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o700); err != nil {
					t.Fatal(err)
				}
				t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
				want := 2
				if mode == "offline" {
					want = 0
				}
				if code := updateInto(kind, "", filepath.Join(home, kind), "owned-test", false, false); code != want {
					t.Fatalf("default update with %s: got %d, want %d", mode, code, want)
				}
				if mode != "offline" {
					if _, err := os.Stat(filepath.Join(home, kind)); !os.IsNotExist(err) {
						t.Fatal("invalid remote source was replaced with a successful bundled install")
					}
				}
			})
		}
	}
}
