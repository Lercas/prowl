package atlassian

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func jiraMockWithBulkGate(n int, lat time.Duration, gate func(context.Context)) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/rest/api/2/serverInfo", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"deploymentType":"Cloud"}`))
	})
	mux.HandleFunc("/rest/api/3/project/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"isLast":true,"values":[{"key":"P"}]}`))
	})
	mux.HandleFunc("/rest/api/3/search/jql", func(w http.ResponseWriter, r *http.Request) {
		var b strings.Builder
		b.WriteString(`{"isLast":true,"issues":[`)
		for i := 1; i <= n; i++ {
			if i > 1 {
				b.WriteByte(',')
			}
			b.WriteString(`{"id":"` + strconv.Itoa(i) + `","key":"P-` + strconv.Itoa(i) + `","fields":{"summary":"x"}}`)
		}
		b.WriteString(`]}`)
		w.Write([]byte(b.String()))
	})
	mux.HandleFunc("/rest/api/3/changelog/bulkfetch", func(w http.ResponseWriter, r *http.Request) {
		if gate != nil {
			gate(r.Context())
		}
		time.Sleep(lat) // ONE latency-bound round-trip per batch of issues — the win over per-issue
		var body struct {
			IssueIdsOrKeys []string `json:"issueIdsOrKeys"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		var b strings.Builder
		b.WriteString(`{"issueChangeLogs":[`)
		for i, id := range body.IssueIdsOrKeys {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(`{"issueId":"` + id + `","changeHistories":[{"created":"2020","items":[{"field":"description","fromString":"x"}]}]}`)
		}
		b.WriteString(`]}`)
		w.Write([]byte(b.String()))
	})
	return httptest.NewServer(mux)
}

// BenchmarkParallelSpeedup is informational: `go test -run=^$ -bench=ParallelSpeedup -benchtime=1x`.

func TestParallelBulkRequestsConcurrent(t *testing.T) {
	const n = 400
	entered := make(chan struct{}, 8)
	unblock := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(unblock) }) }
	srv := jiraMockWithBulkGate(n, 0, func(ctx context.Context) {
		entered <- struct{}{}
		select {
		case <-unblock:
		case <-ctx.Done():
		}
	})
	defer srv.Close()
	defer release()
	done := make(chan int, 1)
	go func() { done <- drainCollect(srv.URL, Options{Workers: 8}) }()
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()
	for i := 0; i < 8; i++ {
		select {
		case <-entered:
		case <-timeout.C:
			t.Fatalf("only %d/8 bulk requests entered while responses were blocked", i)
		}
	}
	release()

	select {
	case count := <-done:
		if count != 2*n {
			t.Fatalf("parallel collection lost current/history items: got %d want %d", count, 2*n)
		}
	case <-timeout.C:
		t.Fatal("parallel collection did not finish after releasing responses")
	}
}
