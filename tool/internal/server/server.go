// Package server exposes the detector as a stateless HTTP scan worker with bounded concurrency,
// /healthz, and /metrics.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/scan"
)

const (
	maxReqBytes      = 16 << 20 // 16MB per payload
	maxBatchReqBytes = 8 << 20  // 8MB for /scan/batch: tighter, since one item fans out to many findings
	maxBatchItems    = 10000    // cap items per batch to bound output/memory amplification
	// maxItemBytes bounds a SINGLE item's content, which the body/batch caps don't: one ~16MB string
	// is one uninterruptible scan with unbounded fan-out. Capping per item bounds CPU/output.
	maxItemBytes = 4 << 20 // 4MB max scanned content per item
	// maxRespFindings caps the findings in ONE response. The input caps don't bound this: one
	// allowed-size item of dense cue lines fans out to thousands of findings, and N concurrent
	// responses can sum to GBs and OOM the worker. A truncation note is appended when this trips. The
	// detector's maxScanMatches (50000) is the upstream backstop; this is the tighter HTTP bound.
	maxRespFindings = 5000
)

// capFindings bounds a response to maxRespFindings, dropping the overflow and appending an info-level
// note (in the last kept slot) so the client sees the result was capped. The bool reports truncation;
// a response at/under the cap is returned unchanged.
func capFindings(fs []model.Finding) ([]model.Finding, bool) {
	if len(fs) <= maxRespFindings {
		return fs, false
	}
	dropped := len(fs) - (maxRespFindings - 1)
	out := fs[: maxRespFindings-1 : maxRespFindings-1] // 3-index slice: the append can't alias dropped findings
	out = append(out, model.Finding{
		Detector: "server",
		Type:     "response_truncated",
		Severity: "info",
		Stage:    "intake",
		Rationale: fmt.Sprintf("response exceeded the per-request findings cap (%d); %d findings were "+
			"dropped to bound response size and memory", maxRespFindings, dropped),
	})
	return out, true
}

type metrics struct {
	scanned, findings, errors, rejected, inflight, truncated int64
}

// Server is a stateless scan worker. Safe for concurrent use.
type Server struct {
	det   *detect.Detector
	eng   *rules.Engine // installed rule templates (datadog, dropbox, …); nil = taxonomy detectors only
	allow func(value, path string) bool
	sem   chan struct{} // bounded concurrency -> backpressure
	m     metrics
}

// New builds a scan worker. eng carries the loaded rule templates (the set `scan`/`lsp` load) so the
// server matches the CLI's coverage; pass nil for taxonomy detectors only. eng is read-only after
// construction and safe to share across the request handlers.
func New(det *detect.Detector, eng *rules.Engine, allow func(value, path string) bool, maxConcurrent int) *Server {
	if maxConcurrent <= 0 {
		maxConcurrent = 2 * runtime.NumCPU()
	}
	return &Server{det: det, eng: eng, allow: allow, sem: make(chan struct{}, maxConcurrent)}
}

type scanItem struct {
	Content string `json:"content"`
	Source  string `json:"source"`
	Path    string `json:"path"`
}

func (i scanItem) toModel() model.Item {
	src := i.Source
	if src == "" {
		src = "code"
	}
	return model.Item{Text: i.Content, Source: src, Path: i.Path}
}

type scanResult struct {
	Count    int             `json:"count"`
	Findings []model.Finding `json:"findings"`
}

// Handler returns the HTTP routes. Mountable into any server (tests, custom middleware).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("GET /limits", s.handleLimits)
	mux.HandleFunc("POST /scan", s.handleScan)
	mux.HandleFunc("POST /scan/batch", s.handleBatch)
	return recoverMW(jsonErrorMW(mux))
}

// jsonErrorMW converts the ServeMux's own 404/405 (which net/http emits as text/plain, not our
// handlers) into the uniform JSON error body. Our handlers set application/json first, so they pass
// through unchanged. See muxErrorWriter.
func jsonErrorMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&muxErrorWriter{ResponseWriter: w}, r)
	})
}

// muxErrorWriter rewrites a ServeMux-generated 404/405 into the uniform JSON error body. It detects
// one by status 404/405 with a non-JSON Content-Type (our handlers always set application/json first),
// then fixes the header, emits {"error":...}, and discards the mux's plain-text body.
type muxErrorWriter struct {
	http.ResponseWriter
	wroteHeader bool
	rewrite     bool // true once we decide to swallow the body and emit JSON instead
}

func (w *muxErrorWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	// A non-JSON content-type on a 404/405 means net/http produced it, not our handlers.
	if (status == http.StatusNotFound || status == http.StatusMethodNotAllowed) &&
		!strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		w.rewrite = true
		w.Header().Set("Content-Type", "application/json") // overwrite the mux's text/plain
	}
	w.ResponseWriter.WriteHeader(status)
	if w.rewrite {
		// Emit the JSON envelope now; the mux's own plain-text Write is swallowed below.
		_ = json.NewEncoder(w.ResponseWriter).Encode(map[string]string{"error": http.StatusText(status)})
	}
}

func (w *muxErrorWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.rewrite {
		return len(b), nil // discard the mux's plain-text line; JSON already written
	}
	return w.ResponseWriter.Write(b)
}

// recoverMW is defense-in-depth for handler glue (scan.Findings already self-guards). It logs without
// exposing the stack and returns a generic 500 instead of letting net/http abort the connection.
// http.ErrAbortHandler is re-panicked so net/http's abort contract still holds.
func recoverMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			if rec == http.ErrAbortHandler {
				panic(rec) // honor net/http's abort contract; the deferred release() already ran
			}
			logx.Error("panic in handler", "method", r.Method, "path", r.URL.Path)
			writeJSONError(w, http.StatusInternalServerError, "internal server error")
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) acquire() bool {
	select {
	case s.sem <- struct{}{}:
		atomic.AddInt64(&s.m.inflight, 1)
		return true
	default:
		atomic.AddInt64(&s.m.rejected, 1)
		return false
	}
}

func (s *Server) release() {
	<-s.sem
	atomic.AddInt64(&s.m.inflight, -1)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]int64{
		"scanned":   atomic.LoadInt64(&s.m.scanned),
		"findings":  atomic.LoadInt64(&s.m.findings),
		"errors":    atomic.LoadInt64(&s.m.errors),
		"rejected":  atomic.LoadInt64(&s.m.rejected),
		"inflight":  atomic.LoadInt64(&s.m.inflight),
		"truncated": atomic.LoadInt64(&s.m.truncated),
		"capacity":  int64(cap(s.sem)),
	})
}

// handleLimits advertises the request-size and count caps so an integrator can size requests up front
// instead of discovering them via a 413. The values mirror the constants the intake paths enforce.
func (s *Server) handleLimits(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]int64{
		"max_request_bytes": maxReqBytes,
		"max_batch_bytes":   maxBatchReqBytes,
		"max_batch_items":   maxBatchItems,
		"max_item_bytes":    maxItemBytes,
	})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if !s.acquire() {
		w.Header().Set("Retry-After", "1")
		writeJSONError(w, http.StatusServiceUnavailable, "overloaded")
		return
	}
	defer s.release()
	var in scanItem
	if err := decode(w, r, &in, maxReqBytes); err != nil {
		atomic.AddInt64(&s.m.errors, 1)
		writeDecodeError(w, err)
		return
	}
	// Bound a single item's content (the body cap alone doesn't stop one huge uninterruptible scan).
	if len(in.Content) > maxItemBytes {
		atomic.AddInt64(&s.m.errors, 1)
		writeJSONError(w, http.StatusRequestEntityTooLarge, "item content too large")
		return
	}
	fs := scan.Findings(r.Context(), s.det, s.eng, nil, in.toModel(), s.allow, nil)
	atomic.AddInt64(&s.m.scanned, 1)
	atomic.AddInt64(&s.m.findings, int64(len(fs)))
	// Bound the per-request output: even an allowed-size item can fan out to thousands of findings.
	if capped, truncated := capFindings(fs); truncated {
		atomic.AddInt64(&s.m.truncated, 1)
		fs = capped
	}
	writeJSON(w, http.StatusOK, scanResult{Count: len(fs), Findings: fs})
}

func (s *Server) handleBatch(w http.ResponseWriter, r *http.Request) {
	// Reject an obviously oversized body before taking a concurrency slot (cheap, best-effort).
	if r.ContentLength > maxBatchReqBytes {
		w.Header().Set("Connection", "close")
		writeJSONError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	if !s.acquire() {
		w.Header().Set("Retry-After", "1")
		writeJSONError(w, http.StatusServiceUnavailable, "overloaded")
		return
	}
	defer s.release()
	var in []scanItem
	if err := decode(w, r, &in, maxBatchReqBytes); err != nil {
		atomic.AddInt64(&s.m.errors, 1)
		writeDecodeError(w, err)
		return
	}
	// Cap items to bound the output/memory amplification (one input item can fan out to many
	// findings, and the whole response is buffered before being written).
	if len(in) > maxBatchItems {
		atomic.AddInt64(&s.m.errors, 1)
		writeJSONError(w, http.StatusRequestEntityTooLarge, "too many items")
		return
	}
	ctx := r.Context()
	// Initialize as empty (not nil) so a zero-hit batch serializes "findings": [] not null.
	all := []model.Finding{}
	batchTruncated := false
	for _, it := range in {
		// Stop once the aggregate output reaches the cap; remaining items are left unscanned and a
		// truncation note is added below.
		if len(all) >= maxRespFindings {
			batchTruncated = true
			break
		}
		// Stop promptly if the client disconnected, freeing the slot.
		if err := ctx.Err(); err != nil {
			atomic.AddInt64(&s.m.errors, 1)
			return
		}
		// Skip+annotate an oversized item rather than scanning it (it would dominate the batch as one
		// uninterruptible, high-fan-out scan).
		if len(it.Content) > maxItemBytes {
			atomic.AddInt64(&s.m.errors, 1)
			all = append(all, model.Finding{
				Detector:  "server",
				Type:      "item_too_large",
				Severity:  "info",
				Source:    it.toModel().Source,
				Path:      it.Path,
				Stage:     "intake",
				Rationale: "item content exceeded the per-item byte cap and was not scanned",
			})
			continue
		}
		all = append(all, scan.Findings(ctx, s.det, s.eng, nil, it.toModel(), s.allow, nil)...)
	}
	atomic.AddInt64(&s.m.scanned, int64(len(in)))
	atomic.AddInt64(&s.m.findings, int64(len(all)))
	// Final bound: the last item can push the aggregate just past the cap (capFindings trims), while
	// batchTruncated covers stopping at exactly the cap with items left unscanned. Both add a note.
	if capped, truncated := capFindings(all); truncated {
		atomic.AddInt64(&s.m.truncated, 1)
		all = capped
	} else if batchTruncated {
		atomic.AddInt64(&s.m.truncated, 1)
		all = append(all, model.Finding{
			Detector:  "server",
			Type:      "response_truncated",
			Severity:  "info",
			Stage:     "intake",
			Rationale: fmt.Sprintf("batch hit the per-request findings cap (%d); remaining items were not scanned", maxRespFindings),
		})
	}
	writeJSON(w, http.StatusOK, scanResult{Count: len(all), Findings: all})
}

func decode(w http.ResponseWriter, r *http.Request, v any, maxBytes int64) error {
	return json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBytes)).Decode(v)
}

// writeDecodeError maps a decode failure to its status: 413 when the body exceeded the MaxBytesReader
// cap, else 400. No internal detail is sent to the client.
func writeDecodeError(w http.ResponseWriter, err error) {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		writeJSONError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeJSONError emits a uniform application/json error body (replacing http.Error's text/plain).
// The message is JSON-encoded, so it is escaped rather than interpolated raw.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// Serve runs the worker until ctx is cancelled, then drains in-flight requests within a 10s deadline.
func Serve(ctx context.Context, addr string, s *Server) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second, // whole request (incl. body) must arrive in time -> slowloris
		// WriteTimeout covers decode+scan+encode+write. Work is bounded (<=maxBatchItems of
		// <=maxItemBytes each), so 120s covers the worst case plus draining over a slow link.
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second, // close idle keep-alive conns so they don't pin resources
	}
	go func() {
		<-ctx.Done()
		logx.Info("shutting down, draining in-flight requests")
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	logx.Info("scan worker listening", "addr", addr, "capacity", cap(s.sem))
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
