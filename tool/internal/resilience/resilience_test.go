package resilience

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRetrySucceedsAfterTransientFailures(t *testing.T) {
	calls := 0
	err := Retry(context.Background(), 5, time.Millisecond, 5*time.Millisecond, func() error {
		calls++
		if calls < 3 {
			return errors.New("transient")
		}
		return nil
	})
	if err != nil || calls != 3 {
		t.Errorf("expected success on 3rd try, err=%v calls=%d", err, calls)
	}
}

func TestRetryExhausts(t *testing.T) {
	calls := 0
	err := Retry(context.Background(), 3, time.Millisecond, 2*time.Millisecond, func() error {
		calls++
		return errors.New("always")
	})
	if err == nil || calls != 3 {
		t.Errorf("expected exhaustion after 3 calls, err=%v calls=%d", err, calls)
	}
}

func TestRetryRespectsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	err := Retry(ctx, 5, time.Millisecond, time.Millisecond, func() error { calls++; return errors.New("x") })
	if err == nil || calls != 0 {
		t.Errorf("cancelled ctx should not call fn, err=%v calls=%d", err, calls)
	}
}

func TestBreakerOpensAndRecovers(t *testing.T) {
	now := time.Unix(1000, 0)
	b := NewBreaker(2, 30*time.Second)
	b.now = func() time.Time { return now }

	if !b.Allow("h") {
		t.Fatal("breaker should start closed")
	}
	b.Record("h", false)
	if !b.Allow("h") {
		t.Fatal("one failure should not open (threshold 2)")
	}
	b.Record("h", false) // 2nd consecutive failure -> open
	if b.Allow("h") {
		t.Fatal("breaker should be open after threshold")
	}
	now = now.Add(31 * time.Second) // cooldown elapsed
	if !b.Allow("h") {
		t.Fatal("breaker should half-open after cooldown")
	}
	b.Record("h", true) // success closes it
	b.Record("h", false)
	if !b.Allow("h") {
		t.Fatal("success should have reset the failure count")
	}
	// unrelated key is independent
	if !b.Allow("other") {
		t.Fatal("breaker should be per-key")
	}
}

func TestGuardRecoversPanic(t *testing.T) {
	var got any
	Guard(func() { panic("boom") }, func(r any) { got = r })
	if got != "boom" {
		t.Errorf("panic not recovered, got %v", got)
	}
	// no panic -> recovered not called, no crash
	called := false
	Guard(func() {}, func(any) { called = true })
	if called {
		t.Error("recovered called without a panic")
	}
}
