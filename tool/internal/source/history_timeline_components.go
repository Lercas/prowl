package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/Lercas/prowl/tool/internal/model"
)

func credentialTimelineCommits(ctx context.Context, dir string) ([]string, string, *model.GitHistoryGraph, error) {
	ctx = WithCredentialScopes(ctx)
	graph, _, err := readTimelineGraph(ctx, dir)
	if err != nil {
		// Unborn history is the only graph failure that can prove an empty selection.
		if empty, digest, emptyErr := credentialHistoryCommits(ctx, dir); emptyErr == nil && len(empty) == 0 {
			return nil, digest, nil, nil
		}
		return nil, "", nil, err
	}
	if !graph.Complete {
		return nil, "", nil, errors.New("complete component timeline is unavailable")
	}
	var listing strings.Builder
	commits := make([]string, 0, len(graph.Commits))
	for _, commit := range graph.Commits {
		commits = append(commits, commit.Hash)
		listing.WriteString(commit.Hash + "\n")
	}
	digest := sha256.Sum256([]byte(listing.String()))
	return commits, hex.EncodeToString(digest[:]), graph, nil
}
