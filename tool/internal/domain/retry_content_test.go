package domain

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

const ownedPartialText = "owned partial content containing a candidate"

type tailFailure struct{ io.Reader }

func (f *tailFailure) Read(p []byte) (int, error) {
	n, err := f.Reader.Read(p)
	if err == io.EOF {
		return n, errors.New("owned transport tail failure")
	}
	return n, err
}

func (*tailFailure) Close() error { return nil }

func TestContentRetryCannotTurnUnreadableBodyIntoAbsence(t *testing.T) {
	for _, first := range []string{"read", "close"} {
		for _, last := range []string{"404", "410", "network", "500", "recovered", "empty"} {
			t.Run(first+"/"+last, func(t *testing.T) {
				calls := 0
				client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
					calls++
					if calls == 1 {
						resp := ownedResponse(r, 200, ownedPartialText)
						if first == "read" {
							resp.Body = &tailFailure{strings.NewReader(ownedPartialText)}
						} else {
							resp.Body = &closeFailure{strings.NewReader(ownedPartialText)}
						}
						return resp, nil
					}
					switch last {
					case "network":
						return nil, errors.New("owned connection failure")
					case "404":
						return ownedResponse(r, 404, ""), nil
					case "410":
						return ownedResponse(r, 410, ""), nil
					case "500":
						return ownedResponse(r, 500, ""), nil
					case "empty":
						return ownedResponse(r, 204, ""), nil
					default:
						return ownedResponse(r, 200, "fresh complete content"), nil
					}
				})}
				body, present, err := newTextFetcher(client).getText(context.Background(), "https://"+first+"-"+last+".owned.test/")
				if !present {
					t.Fatal("a previously reached content response was forgotten")
				}
				if last == "recovered" || last == "empty" {
					want := "fresh complete content"
					if last == "empty" {
						want = ""
					}
					if err != nil || body != want || calls != 2 {
						t.Fatalf("complete retry returned stale content: calls=%d body=%q err=%v", calls, body, err)
					}
				} else if err == nil || body != ownedPartialText {
					t.Fatalf("unreadable response became clean/empty or lost its prefix: body=%q err=%v", body, err)
				}
			})
		}
	}
}

func TestDiscoveryKeepsPartialRootAndMarksIncompleteAfterRetryAbsence(t *testing.T) {
	for _, first := range []string{"read", "close"} {
		t.Run(first, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
				if strings.HasPrefix(r.URL.Hostname(), "www.") {
					return ownedResponse(r, 200, "complete alternate root"), nil
				}
				calls++
				if calls > 1 {
					return ownedResponse(r, 404, ""), nil
				}
				resp := ownedResponse(r, 200, ownedPartialText)
				if first == "read" {
					resp.Body = &tailFailure{strings.NewReader(ownedPartialText)}
				} else {
					resp.Body = &closeFailure{strings.NewReader(ownedPartialText)}
				}
				return resp, nil
			})}
			items, reached := Discover(context.Background(), "retry-root-"+first+".owned.test", Options{Authorized: true, HTTPClient: client})
			partial, complete, diagnostics := false, false, 0
			for it := range items {
				partial = partial || it.Text == ownedPartialText
				complete = complete || it.Text == "complete alternate root"
				if it.Error != nil {
					diagnostics++
				}
			}
			if !partial || !complete || diagnostics != 1 || !reached.Load() {
				t.Fatalf("retry erased root coverage evidence: partial=%v complete=%v errors=%d reached=%v", partial, complete, diagnostics, reached.Load())
			}
		})
	}
}

func TestFetchAllKeepsUnreadableOptionalAssetPrefix(t *testing.T) {
	ctx := context.Background()
	var mu sync.Mutex
	calls := 0
	client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n > 1 {
			return ownedResponse(r, 404, ""), nil
		}
		resp := ownedResponse(r, 200, ownedPartialText)
		resp.Body = &tailFailure{strings.NewReader(ownedPartialText)}
		return resp, nil
	})}
	ch := make(chan model.Item, 4)
	newTextFetcher(client).fetchAll(ctx, ch, []string{"https://optional-retry.owned.test/app.js.map"}, "code", newBudget(10), 1, &contentSeen{seen: map[uint64]bool{}}, nil)
	close(ch)
	partial, diagnostics := false, 0
	for it := range ch {
		partial = partial || it.Text == ownedPartialText
		if it.Error != nil {
			diagnostics++
		}
	}
	if !partial || diagnostics != 1 {
		t.Fatalf("previously served optional asset became a clean miss: partial=%v errors=%d", partial, diagnostics)
	}
}

func TestCompleteAlternateRootDiscoversAssetsFromPreviouslyReadPrefix(t *testing.T) {
	const html = `<script src="/app.js"></script>`
	rootCalls, assetCalls := 0, 0
	client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/app.js" {
			assetCalls++
			return ownedResponse(r, 200, "complete asset content"), nil
		}
		if r.URL.Path == "/app.js.map" {
			return ownedResponse(r, 404, ""), nil
		}
		if strings.HasPrefix(r.URL.Hostname(), "www.") {
			return ownedResponse(r, 200, html), nil
		}
		rootCalls++
		if rootCalls > 1 {
			return ownedResponse(r, 404, ""), nil
		}
		resp := ownedResponse(r, 200, html)
		resp.Body = &closeFailure{strings.NewReader(html)}
		return resp, nil
	})}
	ch, _ := Discover(context.Background(), "recovered-links.owned.test", Options{Authorized: true, HTTPClient: client})
	asset, diagnostics := false, 0
	for it := range ch {
		asset = asset || it.Text == "complete asset content"
		if it.Error != nil {
			diagnostics++
		}
	}
	if !asset || assetCalls != 1 || diagnostics != 1 {
		t.Fatalf("deduped prefix suppressed discovery from a complete root: asset=%v requests=%d errors=%d", asset, assetCalls, diagnostics)
	}
}
