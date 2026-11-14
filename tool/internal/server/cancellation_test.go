package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestCancelledScanCannotReturnCompleteEnvelope(t *testing.T) {
	s := newSrv(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest("POST", "/scan", strings.NewReader(`{"content":"AWS_KEY=`+"\x41"+`KIANAFGYOEYPXU1DSYP"}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	var report model.ScanResult
	if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Complete || report.CompletionReason != "incomplete" {
		t.Fatal("cancelled request certified as complete")
	}
}

func TestCancelledEmptyBatchCannotReturnCompleteEnvelope(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	r := httptest.NewRequest("POST", "/scan/batch", strings.NewReader(`[]`)).WithContext(ctx)
	w := httptest.NewRecorder()
	newSrv(t).Handler().ServeHTTP(w, r)
	var result model.ScanResult
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.Complete || result.CompletionReason != "incomplete" || len(result.Diagnostics) == 0 {
		t.Fatal("cancelled empty batch certified as complete")
	}
}
