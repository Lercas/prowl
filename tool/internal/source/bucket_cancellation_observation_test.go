package source

import (
	"context"
	"errors"
	"testing"
	"time"
)

type bucketCancellationObservation struct {
	err      error
	finished time.Time
}

func (o bucketCancellationObservation) metDeadline(deadline time.Time) bool {
	return errors.Is(o.err, context.Canceled) && !o.finished.After(deadline)
}

// When both branches are ready, recover an already recorded completion even if
// select chose the timer. Its timestamp still has to satisfy the original budget.
func awaitBucketCancellation(done <-chan bucketCancellationObservation, expired <-chan time.Time) (bucketCancellationObservation, bool) {
	select {
	case observation := <-done:
		return observation, true
	case <-expired:
		select {
		case observation := <-done:
			return observation, true
		default:
			return bucketCancellationObservation{}, false
		}
	}
}

func TestBucketCancellationReadyResultRetainsExactDeadline(t *testing.T) {
	deadline := time.Now()
	for _, test := range []struct {
		name        string
		observation bucketCancellationObservation
		want        bool
	}{
		{"early", bucketCancellationObservation{context.Canceled, deadline.Add(-time.Millisecond)}, true},
		{"at-boundary", bucketCancellationObservation{context.Canceled, deadline}, true},
		{"late", bucketCancellationObservation{context.Canceled, deadline.Add(time.Nanosecond)}, false},
		{"success-is-not-cancellation", bucketCancellationObservation{nil, deadline.Add(-time.Millisecond)}, false},
		{"unrelated-error", bucketCancellationObservation{context.DeadlineExceeded, deadline.Add(-time.Millisecond)}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			for range 1000 {
				done := make(chan bucketCancellationObservation, 1)
				done <- test.observation
				expired := make(chan time.Time, 1)
				expired <- deadline
				got, received := awaitBucketCancellation(done, expired)
				if !received || got.metDeadline(deadline) != test.want {
					t.Fatal("ready branch selection changed the actual cancellation deadline", received, got)
				}
			}
		})
	}
}

func TestBucketCancellationWithoutResultRemainsTimeout(t *testing.T) {
	done := make(chan bucketCancellationObservation)
	expired := make(chan time.Time, 1)
	expired <- time.Now()
	if _, received := awaitBucketCancellation(done, expired); received {
		t.Fatal("timer fabricated a cancellation result")
	}
}
