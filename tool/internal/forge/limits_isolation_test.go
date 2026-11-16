package forge

import (
	"context"
	"fmt"
	"github.com/Lercas/prowl/tool/internal/model"
	"net/http"
	"reflect"
	"sync"
	"testing"
)

func TestListingRetainsEntryPageLimit(t *testing.T) {
	SetMaxPages(2)
	t.Cleanup(func() { SetMaxPages(200) })
	localAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			fmt.Fprint(w, `[{"clone_url":"https://owned.invalid/b.git"}]`)
			return
		}
		SetMaxPages(1)
		w.Header().Set("Link", `<?per_page=100&page=2>; rel="next"`)
		fmt.Fprint(w, `[{"clone_url":"https://owned.invalid/a.git"}]`)
	})
	urls, err := ListRepos(context.Background(), "github:owned")
	if err != nil || len(urls) != 2 {
		t.Fatalf("later defaults changed in-flight pagination: repos=%d error=%v", len(urls), err)
	}
}

func TestExplicitListingLimitsAndScopeIgnoreLegacySetters(t *testing.T) {
	defer SetMaxPages(DefaultMaxPages)
	localAPI(t, func(w http.ResponseWriter, r *http.Request) {
		SetMaxPages(1)
		if r.URL.Query().Get("page") == "2" {
			fmt.Fprint(w, `[{"clone_url":"https://owned.invalid/b.git"}]`)
			return
		}
		w.Header().Set("Link", `<?per_page=100&page=2>; rel="next"`)
		fmt.Fprint(w, `[{"clone_url":"https://owned.invalid/a.git"}]`)
	})
	collect := func(explicit bool, limit int) model.ScanResult {
		coverage := model.NewCoverage()
		ctx := model.WithCoverage(t.Context(), coverage)
		var urls []string
		var err error
		if explicit {
			urls, err = ListReposWithOptions(ctx, "github:owned", Options{MaxPages: limit})
		} else {
			SetMaxPages(limit)
			urls, err = ListRepos(ctx, "github:owned")
		}
		if limit == 1 {
			if err == nil || len(urls) != 1 {
				t.Fatal("tight cap did not preserve partial inventory")
			}
		} else if err != nil || len(urls) != 2 {
			t.Fatal("selected limit changed during listing", len(urls), err)
		}
		return model.NewResult(nil, coverage)
	}
	legacy := collect(false, 2)
	selected := collect(true, 2)
	if !legacy.Complete || !selected.Complete || !reflect.DeepEqual(legacy.Scope, selected.Scope) {
		t.Fatal("inventory/API scopes did not retain the effective entry limit")
	}
	limited := collect(true, 1)
	if limited.Complete || reflect.DeepEqual(limited.Scope, selected.Scope) {
		t.Fatal("partial listing certified complete or reused another limit scope")
	}
	defaults := collect(true, 0)
	if !defaults.Complete || reflect.DeepEqual(defaults.Scope, limited.Scope) {
		t.Fatal("explicit defaults inherited a legacy cap")
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 1000 {
			SetMaxPages(1)
			SetMaxPages(3)
		}
	})
	collect(true, 2)
	wg.Wait()
}
