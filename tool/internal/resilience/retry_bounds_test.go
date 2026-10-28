package resilience

import (
	"context"
	"errors"
	"math"
	"math/big"
	"testing"
	"time"
)

func TestRetryDurationBoundsDoNotPanicAfterCancellation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		base, max time.Duration
	}{
		{"maximum", time.Duration(math.MaxInt64), time.Duration(math.MaxInt64)},
		{"negative-cap", time.Second, -1},
		{"minimum-cap", time.Second, time.Duration(math.MinInt64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("retry delay panicked instead of honoring cancellation: %v", r)
				}
			}()
			err := Retry(ctx, 2, tc.base, tc.max, func() error {
				calls++
				cancel() // No long timer can keep this regression test waiting.
				return errors.New("owned transient failure")
			})
			if calls != 1 || !errors.Is(err, context.Canceled) {
				t.Errorf("cancelled retry ran again or lost context: calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestRetryBackoffSaturatesWithoutOverflow(t *testing.T) {
	values := []time.Duration{-1, 0, 1, 300 * time.Millisecond, time.Duration(1<<62 + 1), time.Duration(math.MaxInt64)}
	for _, base := range values {
		for _, cap := range values {
			for _, attempt := range []int{0, 1, 2, 31, 62, 63, 64, 1000} {
				want := time.Duration(0)
				if base > 0 && cap > 0 {
					exact := new(big.Int).Lsh(big.NewInt(int64(base)), uint(attempt))
					if exact.Cmp(big.NewInt(int64(cap))) > 0 {
						want = cap
					} else {
						want = time.Duration(exact.Int64())
					}
				}
				if got := retryBackoff(base, cap, attempt); got != want {
					t.Fatalf("overflow changed delay: base=%d cap=%d attempt=%d got=%d want=%d", base, cap, attempt, got, want)
				}
			}
		}
	}
	for _, limit := range values {
		for i := 0; i < 1000; i++ {
			if got := retryJitter(limit); got < 0 || (limit <= 0 && got != 0) || (limit > 0 && got > limit) {
				t.Fatalf("jitter escaped its interval: limit=%d got=%d", limit, got)
			}
		}
	}
}

func TestRetryWithoutDelayKeepsAttemptsAndLastCause(t *testing.T) {
	cause := errors.New("owned failure")
	for _, base := range []time.Duration{0, -1, time.Second} {
		for _, cap := range []time.Duration{0, -1} {
			calls := 0
			err := Retry(context.Background(), 3, base, cap, func() error { calls++; return cause })
			if calls != 3 || !errors.Is(err, cause) {
				t.Fatal("disabled waiting changed attempts or discarded the last failure")
			}
		}
	}
}
