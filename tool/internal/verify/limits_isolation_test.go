package verify

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestVerifierConstructorsRetainIndependentConcurrency(t *testing.T) {
	defer SetConcurrency(DefaultConcurrency)
	SetConcurrency(1)
	legacy := New(time.Second)
	SetConcurrency(3)
	explicit := NewWithOptions(time.Second, Options{Concurrency: 2})
	defaults := NewWithOptions(time.Second, Options{})
	path := writeVerifier(t, "https://owned.invalid")
	disk, err := LoadWithOptions(time.Second, Options{Concurrency: 4}, path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	embedded, err := LoadEmbeddedWithOptions(time.Second, ownedEmbeddedVerifier(string(raw)), Options{Concurrency: 5})
	if err != nil {
		t.Fatal(err)
	}
	SetConcurrency(7)
	for set, want := range map[*Set]int{legacy: 1, explicit: 2, defaults: 8, disk: 4, embedded: 5} {
		if set.Concurrency() != want {
			t.Fatalf("constructor inherited later defaults: got %d want %d", set.Concurrency(), want)
		}
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 1000 {
			SetConcurrency(1)
			SetConcurrency(3)
		}
	})
	wg.Go(func() {
		for range 100 {
			if NewWithOptions(time.Second, Options{}).Concurrency() != 8 {
				t.Error("explicit default changed")
			}
			_ = New(time.Second)
		}
	})
	wg.Wait()
}

func TestSelectedConcurrencyBoundsActualProviderCalls(t *testing.T) {
	defer SetConcurrency(DefaultConcurrency)
	var active, peak atomic.Int32
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := active.Add(1)
		defer active.Add(-1)
		for {
			old := peak.Load()
			if old >= n || peak.CompareAndSwap(old, n) {
				break
			}
		}
		entered <- struct{}{}
		<-release
		w.WriteHeader(200)
	}))
	defer server.Close()
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	set, err := LoadWithOptions(2*time.Second, Options{Concurrency: 2}, writeVerifier(t, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	SetConcurrency(1)
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Go(func() {
			r := set.Verify(t.Context(), "mocktoken", fmt.Sprintf("owned-value-%d", i), "", false)
			if r.Status != Verified {
				t.Errorf("provider verification failed: %s", r.Status)
			}
		})
	}
	for range 2 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("selected concurrency did not allow two calls")
		}
	}
	if peak.Load() != 2 {
		t.Fatal("selected concurrency did not bound calls", peak.Load())
	}
	unblock()
	wg.Wait()
	if peak.Load() != 2 {
		t.Fatal("provider limit changed while running", peak.Load())
	}
}
