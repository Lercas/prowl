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

type ownedTransport func(*http.Request) (*http.Response, error)

func (f ownedTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func ownedResponse(r *http.Request, status int, text string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(text)), Request: r}
}

func TestHTTPReadMustBeComplete(t *testing.T) {
	for name, raw := range map[string]string{"empty": "", "at-limit": strings.Repeat("x", maxBodyBytes), "above-limit": strings.Repeat("x", maxBodyBytes+1)} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				return ownedResponse(r, 200, raw), nil
			})}
			got, present, err := newTextFetcher(client).getText(context.Background(), "https://"+name+".owned.test/")
			if !present || calls != 1 || (err != nil) != (name == "above-limit") {
				t.Fatalf("present=%v calls=%d error=%v", present, calls, err)
			}
			if err == nil && got != raw {
				t.Fatal("complete body was changed")
			}
		})
	}
}

type closeFailure struct{ io.Reader }

func (*closeFailure) Close() error { return errors.New("owned close failure") }

func TestHTTPBodyCloseFailureIsNotClean(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		resp := ownedResponse(r, 200, "owned text")
		resp.Body = &closeFailure{strings.NewReader("owned text")}
		return resp, nil
	})}
	_, _, err := newTextFetcher(client).getText(context.Background(), "https://close.owned.test/")
	if err == nil || calls != 3 {
		t.Fatalf("failed close was ignored: calls=%d error=%v", calls, err)
	}
}

func TestDiscoveryHonestResultsAndOptionalProbes(t *testing.T) {
	for _, mode := range []string{"unreachable", "empty", "asset-404", "optional-map", "oversize", "budget", "bad-recon", "authorization"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			var mu sync.Mutex
			client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
				mu.Lock()
				calls++
				mu.Unlock()
				if strings.HasPrefix(r.URL.Hostname(), "www.") || mode == "unreachable" {
					return ownedResponse(r, 404, ""), nil
				}
				if r.URL.Hostname() == "crt.sh" || r.URL.Hostname() == "web.archive.org" {
					return ownedResponse(r, 200, "{invalid"), nil
				}
				if r.URL.Path != "" && r.URL.Path != "/" {
					if mode == "optional-map" && r.URL.Path == "/app.js" {
						return ownedResponse(r, 200, "owned JS"), nil
					}
					return ownedResponse(r, 404, ""), nil
				}
				body := "owned root"
				switch mode {
				case "empty":
					body = ""
				case "asset-404", "optional-map":
					body = `<script src="/app.js"></script>`
				case "oversize":
					body = strings.Repeat("x", maxBodyBytes+1)
				case "budget":
					body = `<script id="__NEXT_DATA__" type="application/json">{"x":"owned state"}</script>`
				}
				return ownedResponse(r, 200, body), nil
			})}
			opts := Options{Authorized: mode != "authorization", HTTPClient: client, Recon: mode == "bad-recon"}
			if mode == "budget" {
				opts.MaxAssets = 1
			}
			ch, reached := Discover(context.Background(), mode+".owned.test", opts)
			var items []model.Item
			for item := range ch {
				items = append(items, item)
			}
			incomplete, state := false, false
			for _, item := range items {
				incomplete = incomplete || item.Error != nil
				state = state || strings.HasSuffix(item.Path, "#__NEXT_DATA__")
			}
			wantIncomplete := mode != "empty" && mode != "optional-map"
			if incomplete != wantIncomplete {
				t.Fatalf("unexpected completeness: %v", items)
			}
			if mode == "empty" && !reached.Load() {
				t.Fatal("empty successful page was called unreachable")
			}
			if mode == "authorization" && calls != 0 {
				t.Fatal("unauthorized discovery contacted a transport")
			}
			if mode == "budget" && (!state || calls != 1) {
				t.Fatalf("state was dropped or budget exceeded: state=%v requests=%d", state, calls)
			}
		})
	}
}

func TestReconCatalogRejectsUnsafeNamesAndLostRows(t *testing.T) {
	for name, body := range map[string]string{
		"unsafe-ct":       `[{"name_value":"outside.test/a.owned.test"}]`,
		"invalid-wayback": `[["original","timestamp"],["https://owned.test/a.js","../../outside"]]`,
		"malformed-row":   `[["original","timestamp"],["https://owned.test/a.js"]]`,
	} {
		t.Run(name, func(t *testing.T) {
			client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) { return ownedResponse(r, 200, body), nil })}
			var err error
			if name == "unsafe-ct" {
				_, err = newTextFetcher(client).crtshSubdomains(context.Background(), "owned.test")
			} else {
				_, err = newTextFetcher(client).waybackAssets(context.Background(), "owned.test", 120)
			}
			if err == nil {
				t.Fatal("unsafe or malformed inventory accepted")
			}
		})
	}
}

func TestBudgetConcurrentReservationsNeverExceedLimit(t *testing.T) {
	b := newBudget(8)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); b.take() }()
	}
	wg.Wait()
	if b.used() != 8 {
		t.Fatalf("budget counter exceeded limit: %d", b.used())
	}
}
