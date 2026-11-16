package source

import (
	"bufio"
	"context"
	"errors"
	"io"
	pathpkg "path"
	"strings"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/resilience"
)

const maxComponentRepositoryItems = 10000
const maxComponentRepositoryBytes = 32 << 20

// RepositoryCredentialFiles reads immutable blobs from the already pinned checkout commit.
// No working-tree content or other repository acquisition can provide companions.
func RepositoryCredentialFiles(ctx context.Context, dir string, exclude []string, maxBytes int64) <-chan model.Item {
	ch := make(chan model.Item, 64)
	go func() {
		defer close(ch)
		resilience.Guard(func() {
			origin, ok := ctx.Value(repositoryOriginKey{}).(repositoryOrigin)
			if !ok || !origin.pinned || !origin.empty && !model.ValidImmutableMetadata("commit", origin.revision) {
				model.Note(ctx, "cross_file_repository_revision_unavailable", dir, true)
				send(ctx, ch, model.Item{Source: "code", Error: errors.New("cross-file repository commit is unavailable")})
				return
			}
			model.CoverageFrom(ctx).RegisterScope("components-repository-snapshot", origin.url, struct {
				Commit string
				Empty  bool
			}{origin.revision, origin.empty})
			if origin.empty {
				return
			}
			ctx = credentialRootContext(WithCredentialScopes(ctx))
			if err := readRepositoryCredentialFiles(ctx, ch, dir, origin.revision, exclude, maxBytes, &repositoryComponentBudget{}); err != nil {
				model.Note(ctx, "cross_file_repository_read_failed", origin.url, true)
				send(ctx, ch, model.Item{Source: "code", Path: origin.url, Error: errors.New("cross-file repository object read failed")})
			}
		}, func(any) {
			model.Note(ctx, "cross_file_repository_read_failed", dir, true)
			send(ctx, ch, model.Item{Source: "code", Error: errors.New("cross-file repository reader failed")})
		})
	}()
	return ch
}

type repositoryComponentBudget struct {
	count int
	bytes int64
}

func readRepositoryCredentialFiles(ctx context.Context, ch chan<- model.Item, dir, commit string, exclude []string, maxBytes int64, budget *repositoryComponentBudget) (err error) {
	listing, err := timelineOutput(ctx, dir, "ls-tree", "-r", "-z", commit, "--")
	if err != nil {
		return err
	}
	if len(listing) > 0 && listing[len(listing)-1] != 0 {
		return errors.New("unterminated repository tree listing")
	}
	processCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cat := gitCmd(processCtx, dir, "cat-file", "--batch")
	in, err := cat.StdinPipe()
	if err != nil {
		return err
	}
	out, err := cat.StdoutPipe()
	if err != nil {
		_ = in.Close()
		return err
	}
	if err = cat.Start(); err != nil {
		_ = in.Close()
		_ = out.Close()
		return err
	}
	defer func() {
		if recover() != nil {
			err = errors.New("repository object reader failed")
		}
		_ = in.Close()
		if err != nil {
			cancel()
		}
		_ = out.Close()
		if waitErr := cat.Wait(); err == nil && waitErr != nil {
			err = waitErr
		}
	}()
	br := bufio.NewReader(out)
	seen := make(map[string]bool)
	for _, entry := range strings.Split(string(listing), "\x00") {
		if entry == "" {
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		head, path, ok := strings.Cut(entry, "\t")
		fields := strings.Fields(head)
		if !ok || path == "" || path == "." || path == ".." || pathpkg.IsAbs(path) || pathpkg.Clean(path) != path || strings.HasPrefix(path, "../") || len(fields) != 3 || !model.ValidImmutableMetadata("blob", fields[2]) {
			return errors.New("invalid repository tree entry")
		}
		if fields[0] == "160000" && fields[1] == "commit" {
			model.Note(ctx, "git_submodule", path, false)
			continue
		}
		if fields[1] != "blob" || fields[0] != "100644" && fields[0] != "100755" && fields[0] != "120000" {
			return errors.New("unsupported repository tree entry")
		}
		if excludedGitPath(ctx, path, exclude) {
			continue
		}
		if seen[path] {
			return errors.New("duplicate repository tree path")
		}
		seen[path] = true
		budget.count++
		if budget.count > maxComponentRepositoryItems {
			return errors.New("repository component item limit reached")
		}
		if _, err := io.WriteString(in, fields[2]+"\n"); err != nil {
			return err
		}
		header, err := br.ReadString('\n')
		if err != nil {
			return err
		}
		typ, size, ok := parseCatFileHeader(header)
		if !ok || typ != "blob" || !strings.HasPrefix(header, fields[2]+" ") {
			return errors.New("repository blob is unavailable")
		}
		if size > int64(maxComponentRepositoryBytes)-budget.bytes {
			return errors.New("repository component byte limit reached")
		}
		budget.bytes += size
		data, err := consumeBlob(br, size, maxBytes)
		if err != nil {
			return err
		}
		if size > maxBytes {
			model.Note(ctx, "max_size", path, true)
			if !send(ctx, ch, model.Item{Source: "code", Path: path, Error: errors.New("repository file exceeds max-size")}) {
				return ctx.Err()
			}
			continue
		}
		emitCtx := ctx
		if fields[0] == "120000" {
			emitCtx = withoutCredentialScope(ctx)
		}
		meta := map[string]any{"blob": fields[2], "commit": commit}
		if graph, _ := ctx.Value(credentialHistoryGraphKey{}).(*model.GitHistoryGraph); graph != nil {
			meta["git_history"] = &model.GitRecord{Graph: graph, Object: model.GitObject{Path: path, Blob: fields[2]}}
		}
		if !emitPayload(emitCtx, ch, path, data, maxBytes, exclude, meta) {
			return ctx.Err()
		}
	}
	return nil
}
