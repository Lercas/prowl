package domain

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestBundleMapAndImports(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bundle.js":
			_, _ = io.WriteString(w, "import './chunk.js';\n//# sourceMappingURL=./named.map")
		case "/chunk.js":
			_, _ = io.WriteString(w, "const publicNumber = 42;")
		case "/named.map":
			_, _ = io.WriteString(w, `{"version":3,"sources":["src/config.ts"],"sourcesContent":["const key='`+"\x41"+`KIANAFGYOEYPXU1DSYP';"]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	cov := model.NewCoverage()
	ctx := model.WithCoverage(context.Background(), cov)
	ch := make(chan model.Item, 16)
	walkAssets(ctx, ch, srv.Client(), []string{srv.URL + "/bundle.js"}, "code", newBudget(16), &contentSeen{seen: map[uint64]bool{}})
	close(ch)
	mapFound, chunkFound := false, false
	for it := range ch {
		if strings.Contains(it.Path, "sources/") {
			mapFound = true
			if it.Meta["source_map"] != srv.URL+"/named.map" {
				t.Fatal("lost source-map origin")
			}
		}
		if strings.HasSuffix(it.Path, "chunk.js") {
			chunkFound = true
		}
	}
	if !mapFound || !chunkFound {
		t.Fatal("missed declared map/import")
	}
	if complete, _, ds := cov.Snapshot(); !complete {
		t.Fatalf("optional guessed map made coverage incomplete: %v", ds)
	}
}

func TestDiscoverFollowsDeclaredMapAndModule(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = io.WriteString(w, `<script src="/bundle.js"></script>`)
		case "/bundle.js":
			_, _ = io.WriteString(w, "import './chunk.js';\n//# sourceMappingURL=./named.map")
		case "/chunk.js":
			_, _ = io.WriteString(w, "const publicNumber = 42;")
		case "/named.map":
			_, _ = io.WriteString(w, `{"version":3,"sources":["src/config.ts"],"sourcesContent":["const key='`+"\x41"+`KIANAFGYOEYPXU1DSYP';"]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	items, reached := Discover(context.Background(), srv.URL, Options{Authorized: true, HTTPClient: srv.Client(), MaxAssets: 16})
	mapFound, chunkFound := false, false
	for item := range items {
		mapFound = mapFound || strings.Contains(item.Path, "sources/") && strings.Contains(item.Text, "AKIA")
		chunkFound = chunkFound || strings.HasSuffix(item.Path, "/chunk.js")
	}
	if !reached.Load() || !mapFound || !chunkFound {
		t.Fatalf("discovery lost declared source map or module: reached=%v map=%v module=%v", reached.Load(), mapFound, chunkFound)
	}
}

func TestBareSourceMapReference(t *testing.T) {
	var fetched atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bundle.js":
			_, _ = io.WriteString(w, "//# sourceMappingURL=renamed.js.map")
		case "/renamed.js.map":
			fetched.Store(true)
			_, _ = io.WriteString(w, `{"version":3,"sources":["config.ts"],"sourcesContent":["const key='`+"\x41"+`KIANAFGYOEYPXU1DSYP';"]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	cov := model.NewCoverage()
	ch := make(chan model.Item, 8)
	walkAssets(model.WithCoverage(context.Background(), cov), ch, srv.Client(), []string{srv.URL + "/bundle.js"}, "code", newBudget(8), &contentSeen{seen: map[uint64]bool{}})
	if !fetched.Load() {
		t.Fatal("declared relative map was silently skipped")
	}
}

func TestReferenceLimitIsVisibleInCoverage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bundle.js" {
			_, _ = io.WriteString(w, strings.Repeat("//# sourceMappingURL=empty.map\n", 33))
		} else {
			_, _ = io.WriteString(w, `{"version":3,"sources":[],"sourcesContent":[]}`)
		}
	}))
	defer srv.Close()
	cov := model.NewCoverage()
	ch := make(chan model.Item, 4)
	walkAssets(model.WithCoverage(context.Background(), cov), ch, srv.Client(), []string{srv.URL + "/bundle.js"}, "code", newBudget(128), &contentSeen{seen: map[uint64]bool{}})
	complete, _, diagnostics := cov.Snapshot()
	if complete {
		t.Fatal("reference cap was silently treated as complete")
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == "web_reference_limit" {
			return
		}
	}
	t.Fatal("reference budget has no specific diagnostic")
}

func TestSourceMapSourceURLDoesNotLeakAuthentication(t *testing.T) {
	ch := make(chan model.Item, 2)
	cov := model.NewCoverage()
	ctx := model.WithCoverage(context.Background(), cov)
	emitSourceMap(ctx, ch, "https://example.invalid/app.map?key=map-private", `{"version":3,"sources":["https://user:source-private@example.invalid/config.ts?key=source-query"],"sourcesContent":["const key='`+"\x41"+`KIANAFGYOEYPXU1DSYP';"]}`, newBudget(2))
	close(ch)
	for item := range ch {
		data, err := json.Marshal(item)
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range []string{"map-private", "source-private", "source-query"} {
			if strings.Contains(string(data), raw) {
				t.Fatal("source-map locator carries raw authentication")
			}
		}
	}
}
func TestSourceMapBoundsAndOrigin(t *testing.T) {
	if _, ok := sameOriginRef("https://a.invalid/b.js", "https://b.invalid/a.js"); ok {
		t.Fatal("followed outside origin")
	}
	cov := model.NewCoverage()
	ctx := model.WithCoverage(context.Background(), cov)
	ch := make(chan model.Item, 4)
	emitSourceMap(ctx, ch, "map", `{"version":3,"sources":["x"],"sourcesContent":[null]}`, newBudget(4))
	if complete, _, _ := cov.Snapshot(); complete {
		t.Fatal("missing source content considered complete")
	}
}

func TestGuessedMapSPAFallbackDoesNotInvalidateCoverage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bundle.js" {
			_, _ = io.WriteString(w, "const publicNumber = 42;")
		} else {
			_, _ = io.WriteString(w, "<html>SPA route fallback</html>")
		}
	}))
	defer srv.Close()
	cov := model.NewCoverage()
	ch := make(chan model.Item, 4)
	walkAssets(model.WithCoverage(context.Background(), cov), ch, srv.Client(), []string{srv.URL + "/bundle.js"}, "code", newBudget(8), &contentSeen{seen: map[uint64]bool{}})
	if complete, _, ds := cov.Snapshot(); !complete {
		t.Fatalf("guessed nonexistent map made a complete scan partial: %v", ds)
	}
}

// Focused tests use the same bounded, ordered fetcher as real discovery.
func walkAssets(ctx context.Context, ch chan<- model.Item, c *http.Client, urls []string, source string, b *budget, seen *contentSeen) {
	required := map[string]bool{}
	for _, u := range urls {
		required[u] = true
	}
	newTextFetcher(c).fetchAll(ctx, ch, dedup(withSourceMaps(urls)), source, b, 8, seen, required)
}

func TestDeclaredMapWithoutSuffixAndInvalidMapRemainVisible(t *testing.T) {
	for _, body := range []string{`{"version":2,"sources":[],"sourcesContent":[]}`, `{"version":3,"version":3,"sources":[],"sourcesContent":[]}`, `{"version":3,"sections":[]}`} {
		client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/bundle.js" {
				return ownedResponse(r, 200, "//# sourceMappingURL=/opaque"), nil
			}
			if r.URL.Path == "/opaque" {
				return ownedResponse(r, 200, body), nil
			}
			return ownedResponse(r, 404, ""), nil
		})}
		coverage := model.NewCoverage()
		ctx := model.WithCoverage(context.Background(), coverage)
		ch := make(chan model.Item, 16)
		walkAssets(ctx, ch, client, []string{"https://maps.owned.test/bundle.js"}, "code", newBudget(16), &contentSeen{seen: map[uint64]bool{}})
		if complete, _, _ := coverage.Snapshot(); complete {
			t.Fatal("declared invalid map was treated as complete")
		}
	}
}

func TestMissingGuessedMapCannotHideLaterRequiredReference(t *testing.T) {
	client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/bundle.js" {
			return ownedResponse(r, 200, "//# sourceMappingURL=missing.map"), nil
		}
		return ownedResponse(r, 404, ""), nil
	})}
	coverage := model.NewCoverage()
	ctx := model.WithCoverage(context.Background(), coverage)
	ch := make(chan model.Item, 16)
	newTextFetcher(client).fetchAll(ctx, ch, []string{"https://late.owned.test/missing.map", "https://late.owned.test/bundle.js"}, "code", newBudget(16), 2, &contentSeen{seen: map[uint64]bool{}}, map[string]bool{"https://late.owned.test/bundle.js": true})
	if complete, _, _ := coverage.Snapshot(); complete {
		t.Fatal("an already tried optional URL hid a later mandatory map")
	}
}
