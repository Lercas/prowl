package forge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestInventoryScopeTracksObservedSetAndAPIButNotToken(t *testing.T) {
	body := `[{"clone_url":"https://user:owned-private@owned.invalid/a.git?token=private"}]`
	s := localAPI(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
	collect := func() model.ScanResult {
		coverage := model.NewCoverage()
		if _, err := ListRepos(model.WithCoverage(context.Background(), coverage), "github:owned"); err != nil {
			t.Fatal(err)
		}
		return model.NewResult(nil, coverage)
	}
	t.Setenv("GITHUB_TOKEN", "owned-first-token")
	first := collect()
	t.Setenv("GITHUB_TOKEN", "owned-second-token")
	second := collect()
	raw, _ := json.Marshal(first)
	if !first.Complete || len(first.Scope) != 2 || string(raw) == "" || strings.Contains(string(raw), "private") || strings.Contains(string(raw), "token") {
		t.Fatalf("unsafe inventory: %s", raw)
	}
	if fmt.Sprint(first.Scope) != fmt.Sprint(second.Scope) {
		t.Fatal("credential value entered scope identity")
	}
	body = `[{"clone_url":"https://owned.invalid/b.git"}]`
	changed := collect()
	if first.Scope[1].Policy == changed.Scope[1].Policy {
		t.Fatal("observed inventory set did not change scope")
	}
	t.Setenv("GITHUB_API", s.URL+"/alternate")
	other := collect()
	if first.Scope[0].Target == other.Scope[0].Target {
		t.Fatal("API endpoint was not scoped")
	}
	body = `[]`
	empty := collect()
	if !empty.Complete || len(empty.Scope) != 2 {
		t.Fatal("successful empty inventory lost its scope")
	}
}

func TestInventoryPartialFailureRetainsScopeAndEntries(t *testing.T) {
	localAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			w.WriteHeader(503)
			return
		}
		w.Header().Set("Link", `<?per_page=100&page=2>; rel="next"`)
		fmt.Fprint(w, `[{"clone_url":"https://owned.invalid/a.git"}]`)
	})
	c := model.NewCoverage()
	urls, err := ListRepos(model.WithCoverage(context.Background(), c), "github:owned")
	result := model.NewResult(nil, c)
	if err == nil || len(urls) != 1 || result.Complete || len(result.Scope) != 2 || len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "forge_inventory_incomplete" {
		t.Fatalf("partial inventory: %+v %v", result, err)
	}
}

func TestPaginationPreservesSelectionAndRejectsAmbiguity(t *testing.T) {
	first := "https://owned.invalid/projects?per_page=100&page=1&include_subgroups=true"
	for _, next := range []string{"?page=2", "?per_page=100&page=2&include_subgroups=false", "?per_page=10&page=2&include_subgroups=true", "?per_page=100&page=2&include_subgroups=true&search=hidden", "?per_page=100&page=2&page=3&include_subgroups=true", "https://owned.invalid/%xx?token=owned-private-link"} {
		if _, err := checkedArrayPageURL(first, first, next); err == nil || strings.Contains(err.Error(), "private") {
			t.Fatalf("changed selection accepted or private error reflected")
		}
	}
	valid := "?per_page=100&page=2&include_subgroups=true"
	if _, err := checkedArrayPageURL(first, first, valid); err != nil {
		t.Fatal(err)
	}
	for _, header := range []http.Header{
		{"Link": {`<>; rel="next"`}},
		{"X-Next-Page": {"2", "3"}},
		{"Link": {`<?page=2>; rel="next"`}, "X-Next-Page": {"3"}},
	} {
		if _, err := nextPage(header, first); err == nil {
			t.Fatal("ambiguous pagination headers accepted")
		}
	}
	if _, err := nextPage(http.Header{"Link": {`<?page=2>; rel="next"`}, "X-Next-Page": {"2"}}, first); err != nil {
		t.Fatal(err)
	}
}

func TestListingRejectsAmbiguousJSONAndOversizedRowsBeforeAllocation(t *testing.T) {
	for _, body := range []string{
		`[{"clone_url":"https://owned.invalid/a","clone_url":"https://owned.invalid/b"}]`,
		`[{"clone_url":"https://owned.invalid/\ud800"}]`,
		`[` + strings.Repeat(`{},`, 100) + `{}]`,
	} {
		localAPI(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
		if _, err := ListRepos(context.Background(), "github:owned"); err == nil {
			t.Fatal("ambiguous or oversized page accepted")
		}
	}
	var out struct {
		Values []struct {
			Links struct{ Clone []struct{ Name, Href string } }
		}
	}
	raw := []byte(`{"values":[` + strings.Repeat(`{},`, 100) + `{}]}`)
	if err := boundListingRows(raw, &out); err == nil || out.Values != nil {
		t.Fatal("Bitbucket oversized page allocated")
	}
}

type errorTransport struct {
	cause error
	body  io.ReadCloser
}

func (tr errorTransport) RoundTrip(*http.Request) (*http.Response, error) {
	if tr.cause != nil {
		return nil, tr.cause
	}
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: tr.body}, nil
}

type closeFailure struct{ io.Reader }

func (closeFailure) Close() error { return errors.New("owned-private-close-detail") }

func TestAPITransportAndCloseErrorsArePrivateAndIncomplete(t *testing.T) {
	previous := client
	t.Cleanup(func() { client = previous })
	sentinel := errors.New("owned-private-transport-detail")
	client = &http.Client{Transport: errorTransport{cause: sentinel}}
	var out []map[string]json.RawMessage
	_, _, err := getJSON(context.Background(), "https://owned.invalid/repositories?token=owned-private-query", nil, &out)
	if err == nil || strings.Contains(err.Error(), "private") || !errors.Is(err, sentinel) {
		t.Fatalf("unsafe transport error: %v", err)
	}
	client = &http.Client{Transport: errorTransport{body: closeFailure{strings.NewReader(`[]`)}}}
	if _, _, err := getJSON(context.Background(), "https://owned.invalid/repositories", nil, &out); err == nil || strings.Contains(err.Error(), "private") {
		t.Fatalf("unsafe or missing close failure: %v", err)
	}
}

func TestPageConfigurationHasHardUpperBound(t *testing.T) {
	previous := currentMaxPages()
	t.Cleanup(func() { SetMaxPages(previous) })
	SetMaxPages(hardMaxPages + 100)
	if currentMaxPages() != hardMaxPages {
		t.Fatal("page cap unbounded")
	}
}

func TestBitbucketNextLocationRemainsOpaque(t *testing.T) {
	calls := 0
	s := localAPI(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Query().Get("cursor") == "opaque" {
			fmt.Fprint(w, `{"values":[{"links":{"clone":[{"name":"https","href":"https://owned.invalid/b.git"}]}}]}`)
			return
		}
		fmt.Fprint(w, `{"values":[{"links":{"clone":[{"name":"https","href":"https://owned.invalid/a.git"}]}}],"next":"?cursor=opaque"}`)
	})
	urls, err := bitbucketList(context.Background(), s.URL+"/repositories/owned?pagelen=100", nil)
	if err != nil || len(urls) != 2 || calls != 2 {
		t.Fatalf("opaque continuation broken: %v %v (%d calls)", urls, err, calls)
	}
}

func TestAPIBaseRejectsCredentialAndSelectionURLComponents(t *testing.T) {
	for _, raw := range []string{"https://u:private@owned.invalid", "https://owned.invalid?", "https://owned.invalid?filter=private", "https://owned.invalid#", "https://owned.invalid#private"} {
		if _, err := apiBase(raw); err == nil || strings.Contains(err.Error(), "private") {
			t.Fatal("unsafe API base accepted or reflected")
		}
	}
	if got, err := apiBase("https://owned.invalid/api/v4/"); err != nil || got != "https://owned.invalid/api/v4" {
		t.Fatalf("ordinary API base changed: %s %v", got, err)
	}
}

func TestValidListingEntriesSurviveBodyCloseFailure(t *testing.T) {
	previous := client
	t.Cleanup(func() { client = previous })
	for _, bitbucket := range []bool{false, true} {
		body := `[{"clone_url":"https://owned.invalid/a.git"}]`
		if bitbucket {
			body = `{"values":[{"links":{"clone":[{"name":"https","href":"https://owned.invalid/a.git"}]}}]}`
		}
		client = &http.Client{Transport: errorTransport{body: closeFailure{strings.NewReader(body)}}}
		var urls []string
		var err error
		if bitbucket {
			urls, err = bitbucketList(context.Background(), "https://owned.invalid/repositories", nil)
		} else {
			urls, _, err = listArrays(context.Background(), "https://owned.invalid/repositories", nil, "clone_url")
		}
		if !errors.Is(err, errListingClose) || len(urls) != 1 || urls[0] != "https://owned.invalid/a.git" {
			t.Fatalf("readable listing lost on close failure: %v %v", urls, err)
		}
	}
}
