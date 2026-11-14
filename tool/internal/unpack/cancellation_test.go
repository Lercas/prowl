package unpack

import (
	"context"
	"errors"
	"testing"
)

func TestWalkContextStopsAfterCancellation(t *testing.T) {
	data := makeZIP(t, map[string][]byte{"one.txt": []byte("one"), "two.txt": []byte("two")})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	_, recognized, err := WalkContext(ctx, "input.zip", data, Limits{}, func(Entry) error { calls++; cancel(); return nil })
	if !recognized || !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal("archive walk did not respect cancellation")
	}
}

func TestCancelledReaderDoesNotTouchUnderlyingInput(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := readBounded(contextReader{ctx, panicReader{}}, 1024)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation not propagated")
	}
}

type panicReader struct{}

func (panicReader) Read([]byte) (int, error) { panic("cancelled read touched its input") }
