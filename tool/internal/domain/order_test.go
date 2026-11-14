package domain

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/model"
)

type afterRead struct {
	io.Reader
	ready <-chan struct{}
	ctx   context.Context
}

func (r *afterRead) Read(p []byte) (int, error) {
	select {
	case <-r.ready:
		return r.Reader.Read(p)
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	}
}

func (*afterRead) Close() error { return nil }

type signalClose struct {
	io.Reader
	ready chan struct{}
}

func (r *signalClose) Close() error { close(r.ready); return nil }

func TestFetchAllDuplicateBodyKeepsInputOrder(t *testing.T) {
	for range 20 {
		ready := make(chan struct{})
		client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
			resp := ownedResponse(r, 200, "same owned candidate content")
			if r.URL.Path == "/first.json" {
				resp.Body = &afterRead{strings.NewReader("same owned candidate content"), ready, r.Context()}
			} else {
				resp.Body = &signalClose{strings.NewReader("same owned candidate content"), ready}
			}
			return resp, nil
		})}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ch := make(chan model.Item, 2)
		newTextFetcher(client).fetchAll(ctx, ch, []string{"https://order.owned.test/first.json", "https://order.owned.test/second.json"}, "code", newBudget(10), 2, &contentSeen{seen: map[uint64]bool{}}, nil)
		cancel()
		if len(ch) != 1 {
			t.Fatalf("duplicate body was lost or scanned repeatedly: items=%d", len(ch))
		}
		if item := <-ch; item.Path != "https://order.owned.test/first.json" || item.Error != nil {
			t.Fatalf("response completion order changed the finding source: %+v", item)
		}
	}
}

func TestFetchAllOutputOrderAndParallelAdmission(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var mu sync.Mutex
	started := map[string]bool{}
	allStarted := make(chan struct{})
	client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		started[r.URL.Path] = true
		if len(started) == 3 {
			close(allStarted)
		}
		mu.Unlock()
		select {
		case <-allStarted:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		return ownedResponse(r, 200, r.URL.Path), nil
	})}
	urls := []string{"https://parallel.owned.test/a.json", "https://parallel.owned.test/b.json", "https://parallel.owned.test/c.json"}
	ch := make(chan model.Item, 3)
	newTextFetcher(client).fetchAll(ctx, ch, urls, "code", newBudget(10), 3, &contentSeen{seen: map[uint64]bool{}}, nil)
	if len(ch) != 3 {
		t.Fatalf("parallel workers failed to reach their causal barrier: items=%d ctx=%v", len(ch), ctx.Err())
	}
	for _, want := range urls {
		if item := <-ch; item.Path != want || item.Error != nil {
			t.Fatalf("parallel output did not preserve admission order: got=%+v want=%s", item, want)
		}
	}
}

func TestFetchAllBudgetAdmitsOnlyTheInputPrefix(t *testing.T) {
	var mu sync.Mutex
	requests := map[string]int{}
	client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		requests[r.URL.String()]++
		mu.Unlock()
		return ownedResponse(r, 200, r.URL.Path), nil
	})}
	urls := []string{"https://budget-order.owned.test/a.json", "https://budget-order.owned.test/b.json", "https://budget-order.owned.test/c.json", "https://budget-order.owned.test/d.json"}
	ch := make(chan model.Item, 5)
	b := newBudget(2)
	newTextFetcher(client).fetchAll(context.Background(), ch, urls, "code", b, 8, &contentSeen{seen: map[uint64]bool{}}, nil)
	close(ch)
	var paths []string
	diagnostics := 0
	for item := range ch {
		if item.Error != nil {
			diagnostics++
			if item.Path != urls[2] {
				t.Errorf("budget did not stop at the first unadmitted URL: %s", item.Path)
			}
		} else {
			paths = append(paths, item.Path)
		}
	}
	if diagnostics != 1 || b.used() != 2 || len(paths) != 2 || paths[0] != urls[0] || paths[1] != urls[1] || len(requests) != 2 || requests[urls[0]] != 1 || requests[urls[1]] != 1 {
		t.Fatalf("budget admission changed with worker scheduling: errors=%d used=%d paths=%v requests=%v", diagnostics, b.used(), paths, requests)
	}
}

type cancelClose struct {
	io.Reader
	cancel context.CancelFunc
}

func (r *cancelClose) Close() error { r.cancel(); return nil }

func TestFetchAllCancellationStopsThePendingWindow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	requests := map[string]int{}
	never := make(chan struct{})
	client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		requests[r.URL.Path]++
		mu.Unlock()
		resp := ownedResponse(r, 200, "owned content")
		if r.URL.Path == "/first.json" {
			resp.Body = &afterRead{strings.NewReader("owned content"), never, r.Context()}
		} else {
			resp.Body = &cancelClose{strings.NewReader("owned content"), cancel}
		}
		return resp, nil
	})}
	ch := make(chan model.Item, 4)
	done := make(chan struct{})
	b := newBudget(10)
	go func() {
		newTextFetcher(client).fetchAll(ctx, ch, []string{"https://cancel-order.owned.test/first.json", "https://cancel-order.owned.test/second.json", "https://cancel-order.owned.test/third.json"}, "code", b, 2, &contentSeen{seen: map[uint64]bool{}}, nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation stranded a pending response or worker")
	}
	mu.Lock()
	defer mu.Unlock()
	if ctx.Err() == nil || b.used() != 2 || requests["/third.json"] != 0 {
		t.Fatalf("cancellation admitted more work: ctx=%v used=%d requests=%v", ctx.Err(), b.used(), requests)
	}
}
