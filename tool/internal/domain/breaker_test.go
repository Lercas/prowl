package domain

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestBreakerSeparatesIndependentOrigins(t *testing.T) {
	for _, healthy := range []string{"https://origin.owned.test:8443/", "http://origin.owned.test/"} {
		t.Run(healthy, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.String() == healthy {
					return ownedResponse(r, 200, "healthy independent origin"), nil
				}
				return ownedResponse(r, 403, ""), nil
			})}
			fetcher := newTextFetcher(client)
			for range 3 {
				if _, _, err := fetcher.getText(context.Background(), "https://origin.owned.test/"); err == nil {
					t.Fatal("failed origin became clean")
				}
			}
			body, present, err := fetcher.getText(context.Background(), healthy)
			if err != nil || !present || body != "healthy independent origin" || calls != 4 {
				t.Fatalf("another origin was suppressed: calls=%d present=%v body=%q err=%v", calls, present, body, err)
			}
		})
	}
}

func TestBreakerKeepsFailuresWithinOneCanonicalOrigin(t *testing.T) {
	for _, addresses := range [][]string{
		{"https://ALIASES.owned.test./a", "https://aliases.owned.test:443/b", "https://aliases.owned.test:00443/c", "https://aliases.owned.test/d"},
		{"http://[2001:0db8:0:0:0:0:0:1]/a", "http://[2001:db8::1]:80/b", "http://[2001:db8::1]/c", "http://[2001:db8::1]/d"},
		{"https://пример.рф/a", "https://xn--e1afmkfd.xn--p1ai:443/b", "https://ПРИМЕР.РФ./c", "https://xn--e1afmkfd.xn--p1ai/d"},
	} {
		calls := 0
		client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
			calls++
			return ownedResponse(r, 403, ""), nil
		})}
		fetcher := newTextFetcher(client)
		for i, address := range addresses {
			_, present, err := fetcher.getText(context.Background(), address)
			if err == nil || present || calls != min(i+1, 3) {
				t.Fatalf("canonical origin escaped its breaker: address=%q calls=%d present=%v err=%v", address, calls, present, err)
			}
		}
	}
}

func TestBreakerSuccessResetsConsecutiveFailures(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 3 || calls == 6 {
			return ownedResponse(r, 200, "recovered"), nil
		}
		return ownedResponse(r, 403, ""), nil
	})}
	fetcher := newTextFetcher(client)
	for i := 1; i <= 6; i++ {
		body, present, err := fetcher.getText(context.Background(), "https://reset.owned.test/")
		if calls != i || (err == nil) != (i%3 == 0) || present != (i%3 == 0) || i%3 == 0 && body != "recovered" {
			t.Fatalf("success did not reset failures: step=%d calls=%d present=%v body=%q err=%v", i, calls, present, body, err)
		}
	}
}

func TestFetchAllKeepsHealthyOriginAfterAnotherTrips(t *testing.T) {
	urls := []string{"https://assets.owned.test/a.js", "https://assets.owned.test/b.js", "https://assets.owned.test/c.js", "https://assets.owned.test/d.js", "https://assets.owned.test:8443/healthy.js"}
	calls := 0
	client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Port() == "8443" {
			return ownedResponse(r, 200, "independent asset"), nil
		}
		return ownedResponse(r, 403, ""), nil
	})}
	ch := make(chan model.Item, len(urls))
	newTextFetcher(client).fetchAll(context.Background(), ch, urls, "code", newBudget(10), 1, &contentSeen{seen: map[uint64]bool{}}, nil)
	close(ch)
	failures, found := 0, false
	for item := range ch {
		if item.Error != nil {
			failures++
		}
		found = found || item.Text == "independent asset"
	}
	if failures != 4 || !found || calls != 4 {
		t.Fatalf("asset errors suppressed independent content: failures=%d found=%v calls=%d", failures, found, calls)
	}
}

func TestInvalidOriginDoesNotUseTransportOrExposeInput(t *testing.T) {
	for _, address := range []string{"/relative", "https:///empty", "ftp://owned.test/", "https://owned.test:/", "https://owned.test:0/", "https://owned.test:65536/", "https://owned.test:bad/", "https://user:private-input@owned.test/", "https://owned.test/%zz", "https://[not-an-ip]/", "http://[fe80::1%25en0]/"} {
		client := &http.Client{Transport: ownedTransport(func(*http.Request) (*http.Response, error) {
			t.Fatal("invalid origin reached the transport")
			return nil, nil
		})}
		body, present, err := newTextFetcher(client).getText(context.Background(), address)
		if err == nil || present || body != "" || strings.Contains(err.Error(), address) || strings.Contains(err.Error(), "private-input") {
			t.Fatalf("invalid origin was accepted or exposed: present=%v err=%v", present, err)
		}
	}
}

func TestDiscoverBreakerDoesNotPersistAcrossScans(t *testing.T) {
	var mu sync.Mutex
	phase, calls := 0, 0
	client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if phase == 1 {
			return ownedResponse(r, 200, "recovered root"), nil
		}
		if r.URL.Path == "" || r.URL.Path == "/" {
			return ownedResponse(r, 200, `<script src="/a.js"></script><script src="/b.js"></script><script src="/c.js"></script>`), nil
		}
		return ownedResponse(r, 403, ""), nil
	})}
	ch, reached := Discover(context.Background(), "https://lifetime.owned.test/", Options{Authorized: true, HTTPClient: client})
	failures := 0
	for item := range ch {
		if item.Error != nil {
			failures++
		}
	}
	if !reached.Load() || failures < 3 {
		t.Fatalf("fixture did not reach the root and trip the breaker: reached=%v failures=%d", reached.Load(), failures)
	}
	mu.Lock()
	phase, calls = 1, 0
	mu.Unlock()
	ch, reached = Discover(context.Background(), "https://lifetime.owned.test/", Options{Authorized: true, HTTPClient: client})
	found := false
	for item := range ch {
		if item.Error != nil {
			t.Errorf("previous scan poisoned recovery: %v", item.Error)
		}
		found = found || item.Text == "recovered root"
	}
	mu.Lock()
	defer mu.Unlock()
	if !reached.Load() || !found || calls != 1 {
		t.Fatalf("new scan skipped its healthy root: reached=%v found=%v calls=%d", reached.Load(), found, calls)
	}
}
