package atlassian

import (
	"context"
	"sync"
)

// defaultWorkers is the per-scan concurrency for the per-item detail work (per-issue changelog/comment
// fetches, per-page version-body fetches). The walk is network-bound, so overlapping round-trips is
// the dominant speedup; 8 keeps well under typical Atlassian rate limits (the client also backs off on
// 429). Tunable via Options.Workers / the CLI --workers flag.
const defaultWorkers = 8

func workerCount(opts Options) int {
	if opts.Workers > 0 {
		return opts.Workers
	}
	return defaultWorkers
}

// runPool runs `process` over the items `produce` pushes, across `workers` goroutines. The cursor/
// offset PAGINATION inside produce stays sequential (a cursor can't be parallelized — API_REFERENCE
// T9/T26), but the expensive per-item detail fetches run concurrently. produce runs on the calling
// goroutine and feeds items via push (non-blocking on ctx cancellation); runPool returns once produce
// has finished and every queued item has been processed.
func runPool[T any](ctx context.Context, workers int, produce func(push func(T)), process func(T)) {
	if workers < 1 {
		workers = 1
	}
	jobs := make(chan T, workers*4)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range jobs {
				process(it)
			}
		}()
	}
	produce(func(it T) {
		select {
		case jobs <- it:
		case <-ctx.Done():
		}
	})
	close(jobs)
	wg.Wait()
}
