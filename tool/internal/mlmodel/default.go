package mlmodel

import "sync"

var (
	defaultOnce  sync.Once
	defaultModel *Model
	defaultErr   error
)

// Default returns a process-wide Model parsed lazily from the embedded JSON,
// caching the instance (or load error) so the model is parsed only once.
func Default() (*Model, error) {
	defaultOnce.Do(func() {
		defaultModel, defaultErr = Load()
	})
	return defaultModel, defaultErr
}
