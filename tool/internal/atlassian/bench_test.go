package atlassian

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func drainCollect(base string, opts Options) int {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ch, _, err := Collect(ctx, base, "jira", Auth{Email: "e", Token: "t"}, opts)
	if err != nil {
		return -1
	}
	n := 0
	for range ch {
		n++
	}
	return n
}

func timeCollect(base string, opts Options) time.Duration {
	start := time.Now()
	drainCollect(base, opts)
	return time.Since(start)
}

// latencyJiraMock returns a Cloud Jira mock that sleeps `lat` on every detail round-trip, so wall time
// is dominated by latency (the real-world bottleneck the worker pool targets). It serves `n` issues
// and implements the BULK changelog endpoint, so history costs one round-trip per jiraBatchSize issues.
func latencyJiraMock(n int, lat time.Duration) *httptest.Server {
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
func BenchmarkParallelSpeedup(b *testing.B) {
	const n = 400 // 8 batches at jiraBatchSize=50, so the pool has work to parallelize
	lat := 15 * time.Millisecond
	srv := latencyJiraMock(n, lat)
	defer srv.Close()
	for _, w := range []int{1, 4, 8, 16} {
		b.Run("workers="+strconv.Itoa(w), func(b *testing.B) {
			d := timeCollect(srv.URL, Options{Workers: w})
			b.ReportMetric(float64(d.Milliseconds()), "ms/scan")
		})
	}
}

// TestParallelSpeedupReal asserts the worker pool delivers a real wall-time speedup: with 8 batches of
// latency-bound bulk-history fetches, 8 workers must be markedly faster than 1. A loose 2x bound
// (theoretical ~8x) keeps it robust against CI scheduling jitter.
func TestParallelSpeedupReal(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	const n = 400
	lat := 10 * time.Millisecond
	srv := latencyJiraMock(n, lat)
	defer srv.Close()

	seq := timeCollect(srv.URL, Options{Workers: 1})
	par := timeCollect(srv.URL, Options{Workers: 8})
	t.Logf("sequential(1 worker)=%v  parallel(8 workers)=%v  speedup=%.1fx", seq, par, float64(seq)/float64(par))
	if par >= seq/2 {
		t.Fatalf("worker pool gave no real speedup: 1-worker=%v 8-worker=%v (want 8-worker < 1-worker/2)", seq, par)
	}
}
