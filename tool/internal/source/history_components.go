package source

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/resilience"
)

type credentialHistoryCommitKey struct{}
type credentialHistoryGraphKey struct{}

// GitCredentialHistory reads complete immutable trees with an independent scope
// for every commit. It never joins parts across revisions or the working tree.
func GitCredentialHistory(ctx context.Context, dir string, exclude []string, maxBytes int64) <-chan model.Item {
	return gitCredentialHistory(ctx, dir, exclude, maxBytes, false)
}

// GitCredentialTimeline preserves per-commit credentials while collecting one lifecycle graph.
func GitCredentialTimeline(ctx context.Context, dir string, exclude []string, maxBytes int64) <-chan model.Item {
	return gitCredentialHistory(ctx, dir, exclude, maxBytes, true)
}

func gitCredentialHistory(ctx context.Context, dir string, exclude []string, maxBytes int64, timeline bool) <-chan model.Item {
	ctx = WithCredentialScopes(ctx)
	registerGitScope(ctx, "git-component-history", dir, nil, exclude, maxBytes)
	ch := make(chan model.Item, 64)
	go func() {
		defer close(ch)
		fail := func() {
			model.Note(ctx, "cross_file_history_read_failed", "", true)
			send(ctx, ch, model.Item{Source: "code", Error: errors.New("cross-file history intake failed")})
		}
		resilience.Guard(func() {
			var commits []string
			var digest string
			var graph *model.GitHistoryGraph
			var err error
			if timeline {
				commits, digest, graph, err = credentialTimelineCommits(ctx, dir)
				ctx = context.WithValue(ctx, credentialHistoryGraphKey{}, graph)
			} else {
				commits, digest, err = credentialHistoryCommits(ctx, dir)
			}
			if err != nil {
				fail()
				return
			}
			target := dir
			if origin, ok := ctx.Value(repositoryOriginKey{}).(repositoryOrigin); ok {
				target = origin.url
			}
			model.CoverageFrom(ctx).RegisterScope("components-history-snapshot", target, struct {
				Revision, CommitsSHA256                 string
				Timeline                                bool
				Commits, MaxCommits, MaxItems, MaxBytes int
			}{"complete-commit-trees-v2-timeline", digest, timeline, len(commits), maxTimelineCommits, maxComponentRepositoryItems, maxComponentRepositoryBytes})
			budget := &repositoryComponentBudget{}
			for _, commit := range commits {
				itemCtx := credentialRootContext(WithCredentialScopes(model.WithProvenance(ctx, map[string]any{"commit": commit})))
				itemCtx = context.WithValue(itemCtx, credentialHistoryCommitKey{}, commit)
				if err := readRepositoryCredentialFiles(itemCtx, ch, dir, commit, exclude, maxBytes, budget); err != nil {
					fail()
					return
				}
			}
		}, func(any) { fail() })
	}()
	return ch
}

func credentialHistoryCommits(ctx context.Context, dir string) ([]string, string, error) {
	ctx = WithCredentialScopes(ctx)
	shallow, err := timelineOutput(ctx, dir, "rev-parse", "--is-shallow-repository")
	if err != nil || strings.TrimSpace(string(shallow)) != "false" {
		return nil, "", errors.New("complete cross-file history is unavailable")
	}
	head, err := timelineOutput(ctx, dir, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		refs, refsErr := timelineOutput(ctx, dir, "for-each-ref", "--format=%(objectname)")
		symbolic, symErr := timelineOutput(ctx, dir, "symbolic-ref", "--quiet", "HEAD")
		if refsErr == nil && len(refs) == 0 && symErr == nil && strings.HasPrefix(strings.TrimSpace(string(symbolic)), "refs/heads/") {
			digest := sha256.Sum256(nil)
			return nil, hex.EncodeToString(digest[:]), nil
		}
		return nil, "", errors.New("history HEAD is unavailable")
	}
	headID := strings.TrimSpace(string(head))
	if !model.ValidImmutableMetadata("commit", headID) {
		return nil, "", errors.New("invalid history HEAD")
	}
	raw, err := timelineOutput(ctx, dir, "rev-list", "--all", headID, "--topo-order", "--reverse", "--")
	if err != nil {
		return nil, "", err
	}
	return parseCredentialHistoryCommits(raw, headID)
}

func parseCredentialHistoryCommits(raw []byte, headID string) ([]string, string, error) {
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		return nil, "", errors.New("history commit listing is unavailable")
	}
	if bytes.Count(raw, []byte("\n")) > maxTimelineCommits {
		return nil, "", errors.New("history commit limit reached")
	}
	commits := strings.Split(string(raw[:len(raw)-1]), "\n")
	seen := make(map[string]bool, len(commits))
	for _, commit := range commits {
		if !model.ValidImmutableMetadata("commit", commit) || seen[commit] {
			return nil, "", errors.New("invalid history commit listing")
		}
		seen[commit] = true
	}
	if !seen[headID] {
		return nil, "", errors.New("history HEAD is absent from commit listing")
	}
	digest := sha256.Sum256(raw)
	return commits, hex.EncodeToString(digest[:]), nil
}
