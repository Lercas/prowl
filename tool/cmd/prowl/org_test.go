package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/Lercas/prowl/tool/internal/safehttp"
)

func orgAPI(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	old := safehttp.AllowPrivate.Swap(true)
	t.Cleanup(func() { safehttp.AllowPrivate.Store(old) })
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	t.Setenv("GITHUB_API", s.URL)
	t.Setenv("GITHUB_TOKEN", "")
}

func TestOrgPartialListingReportsAndBlocksBaseline(t *testing.T) {
	fakeRepoClone(t)
	t.Chdir(t.TempDir())
	orgAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Link", `<?page=2>; rel="next"`)
		fmt.Fprint(w, `[{"clone_url":"https://owned.invalid/project.git"}]`)
	})
	args := []string{"github:owned", "--format", "json", "--output", "partial.json", "--silence"}
	if code := cmdOrg(args); code != 2 {
		t.Fatalf("partial listing returned %d", code)
	}
	truncated, fs := readBucketReport(t, "partial.json")
	if !truncated || len(fs) != 2 {
		t.Fatalf("lost partial results/diagnostic: %v %+v", truncated, fs)
	}
	if code := cmdOrg(append(args, "--write-baseline", "baseline.json")); code != 2 {
		t.Fatalf("incomplete baseline returned %d", code)
	}
	if _, err := os.Stat("baseline.json"); !os.IsNotExist(err) {
		t.Fatal("incomplete baseline created")
	}
}

func TestOrgFingerprintsStableAndScoped(t *testing.T) {
	fakeRepoClone(t)
	t.Chdir(t.TempDir())
	url := "https://owned.invalid/a.git"
	orgAPI(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, `[{"clone_url":%q}]`, url) })
	var original string
	for _, name := range []string{"first", "repeat", "other"} {
		if name == "other" {
			url = "https://other.invalid/a.git"
		}
		if code := cmdOrg([]string{"github:owned", "--format", "json", "--output", name + ".json", "--silence"}); code != 0 {
			t.Fatalf("org returned %d", code)
		}
		truncated, fs := readBucketReport(t, name+".json")
		if truncated || len(fs) != 1 {
			t.Fatalf("unexpected scan: %v %+v", truncated, fs)
		}
		fp := fs[0].Fingerprint
		if name == "first" {
			original = fp
		} else if (fp == original) != (name == "repeat") {
			t.Fatalf("unstable or unscoped fingerprint: %s %s", original, fp)
		}
	}
}

func TestOrgEmptyInventoryStillReportsAndPreflights(t *testing.T) {
	fakeRepoClone(t)
	t.Chdir(t.TempDir())
	calls := 0
	orgAPI(t, func(w http.ResponseWriter, r *http.Request) { calls++; fmt.Fprint(w, `[]`) })
	if code := cmdOrg([]string{"github:owned", "--format", "json", "--output", "empty.json", "--silence"}); code != 0 {
		t.Fatalf("empty inventory returned %d", code)
	}
	if truncated, fs := readBucketReport(t, "empty.json"); truncated || len(fs) != 0 {
		t.Fatalf("empty report: %v %+v", truncated, fs)
	}
	before := calls
	if code := cmdOrg([]string{"github:owned", "--verified-only", "--verifiers", t.TempDir(), "--silence"}); code != 2 {
		t.Fatal("invalid verifier accepted")
	}
	if calls != before {
		t.Fatal("listing preceded preflight")
	}
}

func TestOrgFailedClonesRemainVisible(t *testing.T) {
	for _, mode := range []string{"all-fail", "mixed"} {
		t.Run(mode, func(t *testing.T) {
			fakeRepoClone(t)
			t.Chdir(t.TempDir())
			orgAPI(t, func(w http.ResponseWriter, r *http.Request) {
				if mode == "mixed" {
					fmt.Fprint(w, `[{"clone_url":"ext::owned-invalid"},{"clone_url":"https://owned.invalid/project.git"}]`)
				} else {
					fmt.Fprint(w, `[{"clone_url":"ext::owned-invalid"}]`)
				}
			})
			if code := cmdOrg([]string{"github:owned", "--format", "json", "--output", "clones.json", "--silence"}); code != 2 {
				t.Fatalf("failed clone gate returned %d", code)
			}
			truncated, fs := readBucketReport(t, "clones.json")
			want := 1
			if mode == "mixed" {
				want = 2
			}
			if !truncated || len(fs) != want {
				t.Fatalf("clone failure lost: %v %+v", truncated, fs)
			}
		})
	}
}

func TestOrgHistoryFingerprintsScopedAcrossRepositories(t *testing.T) {
	fakeRepoClone(t)
	t.Chdir(t.TempDir())
	orgAPI(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"clone_url":"https://owned.invalid/a.git"},{"clone_url":"https://owned.invalid/b.git"}]`)
	})
	if code := cmdOrg([]string{"github:owned", "--history", "--format", "json", "--output", "history.json", "--silence"}); code != 0 {
		t.Fatalf("history returned %d", code)
	}
	truncated, fs := readBucketReport(t, "history.json")
	fingerprints := map[string]bool{}
	for _, f := range fs {
		fingerprints[f.Fingerprint] = true
	}
	if truncated || len(fs) != 4 || len(fingerprints) != 4 {
		t.Fatalf("history identities collided: %v %+v", truncated, fs)
	}
}

func TestOrgRejectsIgnoredModesAndExtraTargetsBeforeListing(t *testing.T) {
	calls := 0
	orgAPI(t, func(w http.ResponseWriter, r *http.Request) { calls++; fmt.Fprint(w, `[]`) })
	for _, flags := range [][]string{{"github:extra"}, {"--staged"}, {"--since", "HEAD"}, {"--branch", "main"}, {"--depth", "2"}} {
		args := append([]string{"github:owned", "--silence"}, flags...)
		if code := cmdOrg(args); code != 2 {
			t.Fatalf("ignored org arguments accepted: %v code=%d", flags, code)
		}
	}
	if calls != 0 {
		t.Fatal("invalid arguments reached API")
	}
}
