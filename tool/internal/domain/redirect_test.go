package domain

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestDiscoverResolvesAssetsFromRedirectedDocument(t *testing.T) {
	for _, tc := range []struct{ name, destination, markup, asset string }{
		{"directory", "/release/index.html", `<script src="app.js"></script>`, "/release/app.js"},
		{"trailing-slash", "/release/", `<script src="app.js"></script>`, "/release/app.js"},
		{"parent-link", "/release/pages/index.html", `<script src="../app.js"></script>`, "/release/app.js"},
		{"relative-base", "/release/index.html", `<base href="assets/"><script src="app.js"></script>`, "/release/assets/app.js"},
		{"encoded-directory", "/release%2Fpart/index.html", `<script src="app.js"></script>`, "/release%2Fpart/app.js"},
		{"query", "/release/index.html?build=1", `<script src="app.js"></script>`, "/release/app.js"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var paths []string
			client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
				mu.Lock()
				paths = append(paths, r.URL.RequestURI())
				mu.Unlock()
				switch r.URL.RequestURI() {
				case "", "/":
					resp := ownedResponse(r, 302, "")
					resp.Header.Set("Location", tc.destination)
					return resp, nil
				case tc.destination:
					return ownedResponse(r, 200, tc.markup), nil
				case tc.asset:
					return ownedResponse(r, 200, "redirected asset candidate"), nil
				default:
					return ownedResponse(r, 404, ""), nil
				}
			})}
			ch, reached := Discover(context.Background(), "https://redirect.owned.test/", Options{Authorized: true, HTTPClient: client})
			found, rootAddress, errors := false, false, 0
			for item := range ch {
				if item.Error != nil {
					errors++
				}
				found = found || item.Text == "redirected asset candidate"
				rootAddress = rootAddress || item.Text == tc.markup && item.Path == "https://redirect.owned.test"+tc.destination
				if item.Text == "redirected asset candidate" && item.Path != "https://redirect.owned.test"+tc.asset {
					t.Errorf("asset provenance changed: %s", item.Path)
				}
			}
			if !reached.Load() || !found || !rootAddress || errors != 0 {
				t.Fatalf("redirected document lost its relative asset: reached=%v found=%v errors=%d requests=%v", reached.Load(), found, errors, paths)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(paths) != 4 || !reflect.DeepEqual(paths[:2], []string{"", tc.destination}) && !reflect.DeepEqual(paths[:2], []string{"/", tc.destination}) {
				t.Errorf("unexpected redirect/asset requests: %v", paths)
			}
		})
	}
}

func responseAt(t *testing.T, original *http.Request, status int, text, address string) *http.Response {
	t.Helper()
	request, err := http.NewRequestWithContext(original.Context(), http.MethodGet, address, nil)
	if err != nil {
		t.Fatal(err)
	}
	return ownedResponse(request, status, text)
}

func TestContentAddressStaysPairedWithLastAcceptedBody(t *testing.T) {
	for _, first := range []string{"read", "close"} {
		for _, last := range []string{"404", "410", "network", "500", "recovered", "empty"} {
			t.Run(first+"/"+last, func(t *testing.T) {
				calls := 0
				client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
					calls++
					if calls == 1 {
						resp := responseAt(t, r, 200, "partial content", "https://paired.owned.test/partial/index.html")
						if first == "read" {
							resp.Body = &tailFailure{strings.NewReader("partial content")}
						} else {
							resp.Body = &closeFailure{strings.NewReader("partial content")}
						}
						return resp, nil
					}
					switch last {
					case "network":
						return nil, errors.New("owned connection failure")
					case "404":
						return responseAt(t, r, 404, "", "https://paired.owned.test/absent"), nil
					case "410":
						return responseAt(t, r, 410, "", "https://paired.owned.test/absent"), nil
					case "500":
						return responseAt(t, r, 500, "", "https://paired.owned.test/server-error"), nil
					case "empty":
						return responseAt(t, r, 204, "", "https://paired.owned.test/fresh/index.html"), nil
					default:
						return responseAt(t, r, 200, "fresh content", "https://paired.owned.test/fresh/index.html"), nil
					}
				})}
				content, err := newTextFetcher(client).getDocument(context.Background(), "https://paired.owned.test/")
				wantURL, wantText := "https://paired.owned.test/partial/index.html", "partial content"
				complete := last == "recovered" || last == "empty"
				if complete {
					wantURL, wantText = "https://paired.owned.test/fresh/index.html", "fresh content"
					if last == "empty" {
						wantText = ""
					}
				}
				if !content.present || content.url != wantURL || content.text != wantText || (err == nil) != complete {
					t.Fatalf("content/address pair became stale: content=%+v error=%v", content, err)
				}
			})
		}
	}
}

func TestUnexpectedResponseAddressIsNotAdopted(t *testing.T) {
	const requested = "https://metadata.owned.test/"
	for _, address := range []string{"https://other.owned.test/path", "http://metadata.owned.test/path", "https://metadata.owned.test:8443/path", "https://user:private-input@metadata.owned.test/path"} {
		calls := 0
		client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
			calls++
			return responseAt(t, r, 200, "owned available prefix", address), nil
		})}
		content, err := newTextFetcher(client).getDocument(context.Background(), requested)
		if err == nil || !content.present || content.text != "owned available prefix" || content.url != requested || calls != 1 || strings.Contains(err.Error(), "private-input") || strings.Contains(err.Error(), address) {
			t.Fatalf("invalid response address was adopted or exposed: content=%+v calls=%d err=%v", content, calls, err)
		}
	}
}

func TestMissingResponseAddressFallsBackToRequest(t *testing.T) {
	client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
		resp := ownedResponse(r, 200, "owned content")
		resp.Request = nil
		return resp, nil
	})}
	content, err := newTextFetcher(client).getDocument(context.Background(), "https://metadata.owned.test/path")
	if err != nil || !content.present || content.text != "owned content" || content.url != "https://metadata.owned.test/path" {
		t.Fatalf("missing optional response metadata changed content: %+v err=%v", content, err)
	}
}

func TestRedirectedBundlesDiscoverTheirFinalAdjacentMapOnce(t *testing.T) {
	var mu sync.Mutex
	mapCalls := 0
	client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "", "/":
			return ownedResponse(r, 200, `<script src="/one.js"></script><script src="/two.js"></script>`), nil
		case "/one.js", "/two.js":
			resp := ownedResponse(r, 302, "")
			resp.Header.Set("Location", "/release/app.js")
			return resp, nil
		case "/release/app.js":
			return ownedResponse(r, 200, "owned JavaScript without candidates"), nil
		case "/release/app.js.map":
			mu.Lock()
			mapCalls++
			mu.Unlock()
			return ownedResponse(r, 200, "candidate in redirected bundle's map"), nil
		default:
			return ownedResponse(r, 404, ""), nil
		}
	})}
	ch, reached := Discover(context.Background(), "https://maps.owned.test/", Options{Authorized: true, HTTPClient: client})
	found := false
	for item := range ch {
		if item.Error != nil {
			t.Errorf("complete redirected bundle became incomplete: %v", item.Error)
		}
		found = found || item.Text == "candidate in redirected bundle's map" && item.Path == "https://maps.owned.test/release/app.js.map"
	}
	if !reached.Load() || !found || mapCalls != 1 {
		t.Fatalf("final bundle map was lost or requested repeatedly: reached=%v found=%v mapCalls=%d", reached.Load(), found, mapCalls)
	}
}

func TestRedirectedMapFollowupsRespectDiscoveryBudget(t *testing.T) {
	mapCalls := 0
	client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "", "/":
			return ownedResponse(r, 200, `<script src="/download.js"></script>`), nil
		case "/download.js":
			return responseAt(t, r, 200, "owned JavaScript", "https://budget-map.owned.test/release/app.js"), nil
		case "/release/app.js.map":
			mapCalls++
			return ownedResponse(r, 200, "map candidate"), nil
		default:
			return ownedResponse(r, 404, ""), nil
		}
	})}
	ch, reached := Discover(context.Background(), "https://budget-map.owned.test/", Options{Authorized: true, MaxAssets: 3, HTTPClient: client})
	diagnostics := 0
	for item := range ch {
		if item.Error != nil {
			diagnostics++
		}
	}
	if !reached.Load() || mapCalls != 0 || diagnostics != 1 {
		t.Fatalf("map follow-up exceeded its budget or hid exhaustion: reached=%v requests=%d diagnostics=%d", reached.Load(), mapCalls, diagnostics)
	}
}
