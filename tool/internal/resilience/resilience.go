// Package resilience provides fault-tolerance primitives: bounded retries with exponential
// backoff + jitter, a per-key circuit breaker, and a panic guard.
package resilience

import (
	"context"
	"math/rand"
	"sync"
	"time"
)

// Retry runs fn until it returns nil, attempts are exhausted, or ctx is cancelled. Backoff grows
// exponentially from base (capped at maxDelay) with full jitter to avoid thundering herds.
func Retry(ctx context.Context, attempts int, base, maxDelay time.Duration, fn func() error) error {
	if attempts < 1 {
		attempts = 1
	}
	var err error
	for i := 0; i < attempts; i++ {
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = fn(); err == nil {
			return nil
		}
		if i == attempts-1 {
			break
		}
		delay := base << i
		if delay > maxDelay || delay <= 0 {
			delay = maxDelay
		}
		jittered := time.Duration(rand.Int63n(int64(delay) + 1)) // full jitter
		select {
		case <-time.After(jittered):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}

// Breaker is a per-key circuit breaker: after `threshold` consecutive failures for a key it opens
// for `cooldown`, during which Allow returns false (skip the doomed call). One success closes it.
type Breaker struct {
	threshold int
	cooldown  time.Duration
	mu        sync.Mutex
	state     map[string]*breakerState
	now       func() time.Time // injectable clock for tests
}

type breakerState struct {
	fails   int
	openTil time.Time
}

func NewBreaker(threshold int, cooldown time.Duration) *Breaker {
	if threshold < 1 {
		threshold = 1
	}
	return &Breaker{threshold: threshold, cooldown: cooldown, state: map[string]*breakerState{}, now: time.Now}
}

// Allow reports whether a call for key should proceed (false while the breaker is open).
func (b *Breaker) Allow(key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.state[key]
	if s == nil {
		return true
	}
	return !b.now().Before(s.openTil)
}

// Record updates the breaker after a call (ok=true success, ok=false failure).
func (b *Breaker) Record(key string, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.state[key]
	if s == nil {
		s = &breakerState{}
		b.state[key] = s
	}
	if ok {
		s.fails = 0
		s.openTil = time.Time{}
		return
	}
	s.fails++
	if s.fails >= b.threshold {
		s.openTil = b.now().Add(b.cooldown)
	}
}

// Guard runs fn and converts a panic into a recovered() callback instead of crashing the process.
func Guard(fn func(), recovered func(any)) {
	defer func() {
		if r := recover(); r != nil && recovered != nil {
			recovered(r)
		}
	}()
	fn()
}
