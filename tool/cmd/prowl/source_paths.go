package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"

	"github.com/Lercas/prowl/tool/internal/model"
)

func relativeSourcePath(root, p string) (string, error) {
	rel, err := filepath.Rel(root, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("source item has no scoped path")
	}
	return filepath.ToSlash(rel), nil
}

// mapSourcePaths rewrites locators before detection/fingerprinting and emits acquisition errors
// ahead of partial content, so report filters and baseline writes see source incompleteness.
func mapSourcePaths(ctx context.Context, items <-chan model.Item, path func(string) (string, error), initial ...model.Item) <-chan model.Item {
	ch := make(chan model.Item, 128)
	go func() {
		defer close(ch)
		for _, it := range initial {
			select {
			case ch <- it:
			case <-ctx.Done():
				return
			}
		}
		if items == nil {
			return
		}
		for it := range items {
			if path != nil {
				p, err := path(it.Path)

				if record, ok := it.Meta["git_history"].(*model.GitRecord); ok {
					display := record.DisplayPath
					if display == "" {
						display = record.Object.Path
					}
					mapped, mapErr := path(display)
					if mapErr != nil {
						err = errors.Join(err, mapErr)
					}
					copyRecord := *record
					copyRecord.DisplayPath = mapped
					meta := make(map[string]any, len(it.Meta))
					for key, value := range it.Meta {
						meta[key] = value
					}
					meta["git_history"] = &copyRecord
					it.Meta = meta
				}
				it.Path = p
				if err != nil {
					it.Error = err
				}
			}
			select {
			case ch <- it:
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch
}
