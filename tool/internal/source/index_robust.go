package source

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/Lercas/prowl/tool/internal/config"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/resilience"
)

// gitWorktreeRoot resolves the repository independently of the caller's current subdirectory.
func gitWorktreeRoot(ctx context.Context, dir string) (string, error) {
	out, err := gitCmd(ctx, dir, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", fmt.Errorf("resolve git worktree: %w", err)
	}
	return strings.TrimSuffix(string(out), "\n"), nil
}

func excludedGitPath(ctx context.Context, path string, exclude []string) bool {
	if skipByExtension(ctx, path) {
		return true
	}
	for _, pattern := range exclude {
		if config.PathMatch(pattern, path) {
			return true
		}
	}
	return false
}

// GitWorktreeFiles reads root-relative diff paths while preserving their repository-relative locators.
func GitWorktreeFiles(ctx context.Context, paths, exclude []string, maxBytes int64) <-chan model.Item {
	return GitWorktreeFilesIn(ctx, "", paths, exclude, maxBytes)
}

// GitWorktreeFilesIn scans diff paths in an explicitly selected repository.
func GitWorktreeFilesIn(ctx context.Context, dir string, paths, exclude []string, maxBytes int64) <-chan model.Item {
	ch := make(chan model.Item, 64)
	go func() {
		defer close(ch)
		root, err := gitWorktreeRoot(ctx, dir)
		if err != nil {
			send(ctx, ch, model.Item{Source: "code", Error: err})
			return
		}
		for _, path := range paths {
			if !emitListedTarget(ctx, ch, filepath.Join(root, path), path, maxBytes, exclude) {
				return
			}
		}
	}()
	return ch
}

// GitIndexFilesIn scans staged objects in an explicitly selected repository.
func GitIndexFilesIn(ctx context.Context, dir string, paths, exclude []string, maxBytes int64) <-chan model.Item {
	model.CoverageFrom(ctx).RegisterScope("git-index", dir, struct {
		Paths, Exclude []string
		MaxBytes       int64
	}{paths, exclude, maxBytes})
	ch := make(chan model.Item, 64)
	go func() {
		defer close(ch)
		resilience.Guard(func() {
			selected := make(map[string]bool, len(paths))
			for _, path := range paths {
				if !excludedGitPath(ctx, path, exclude) {
					selected[path] = true
				}
			}
			if len(selected) == 0 {
				return
			}
			root, err := gitWorktreeRoot(ctx, dir)
			if err != nil {
				send(ctx, ch, model.Item{Source: "code", Error: err})
				return
			}
			if path, err := readIndexFiles(ctx, ch, root, selected, maxBytes, exclude); err != nil {
				model.Note(ctx, "git_index_read_failed", path, true)
				send(ctx, ch, model.Item{Source: "code", Path: path, Error: err})
			}
		}, func(any) {
			model.Note(ctx, "git_index_read_failed", dir, true)
			send(ctx, ch, model.Item{Source: "code", Error: fmt.Errorf("git index reader failed")})
		})
	}()
	return ch
}

func readIndexFiles(ctx context.Context, ch chan<- model.Item, root string, selected map[string]bool, maxBytes int64, exclude []string) (errPath string, err error) {
	listing, err := gitCmd(ctx, root, "ls-files", "--stage", "-z").Output()
	if err != nil {
		return "", fmt.Errorf("list git index: %w", err)
	}
	processCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cat := gitCmd(processCtx, root, "cat-file", "--batch")
	in, err := cat.StdinPipe()
	if err != nil {
		return "", err
	}
	out, err := cat.StdoutPipe()
	if err != nil {
		_ = in.Close()
		return "", err
	}
	if err = cat.Start(); err != nil {
		_ = in.Close()
		_ = out.Close()
		return "", err
	}
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("git index reader failed")
		}
		_ = in.Close()
		if err != nil {
			cancel() // a malformed/incomplete frame may leave cat-file blocked writing a body
		}
		if waitErr := cat.Wait(); err == nil && waitErr != nil {
			err = fmt.Errorf("git index object reader: %w", waitErr)
		}
	}()
	br := bufio.NewReader(out)
	found := make(map[string]bool, len(selected))
	for _, entry := range strings.Split(string(listing), "\x00") {
		head, path, ok := strings.Cut(entry, "\t")
		if !ok || !selected[path] || found[path] {
			continue
		}
		found[path] = true
		fields := strings.Fields(head)
		if len(fields) != 3 || fields[2] != "0" {
			model.Note(ctx, "git_index_unmerged", path, true)
			if !send(ctx, ch, model.Item{Source: "code", Path: path, Error: fmt.Errorf("git index entry is unresolved")}) {
				return path, ctx.Err()
			}
			continue
		}
		if fields[0] == "160000" {
			model.Note(ctx, "git_submodule", path, false)
			continue // submodule commit, not file content
		}
		if _, err := io.WriteString(in, fields[1]+"\n"); err != nil {
			return path, err
		}
		header, err := br.ReadString('\n')
		if err != nil {
			return path, err
		}
		typ, size, ok := parseCatFileHeader(header)
		if !ok || typ != "blob" || !strings.HasPrefix(header, fields[1]+" ") {
			return path, fmt.Errorf("git index blob is unavailable")
		}
		data, err := consumeBlob(br, size, maxBytes)
		if err != nil {
			return path, err
		}
		if size > maxBytes {
			model.Note(ctx, "max_size", path, true)
			if !send(ctx, ch, model.Item{Source: "code", Path: path, Error: fmt.Errorf("staged file exceeds max-size")}) {
				return path, ctx.Err()
			}
			continue
		}
		if !emitPayload(ctx, ch, path, data, maxBytes, exclude, map[string]any{"blob": fields[1], "git_index": true}) {
			return path, ctx.Err()
		}
	}
	for path := range selected {
		if !found[path] {
			model.Note(ctx, "git_index_entry_missing", path, true)
			if !send(ctx, ch, model.Item{Source: "code", Path: path, Error: fmt.Errorf("selected file is missing from git index")}) {
				return path, ctx.Err()
			}
		}
	}
	return "", nil
}
