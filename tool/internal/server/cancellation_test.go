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
