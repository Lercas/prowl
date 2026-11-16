package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/source"
)

// cmdRepo clones a remote git repository (any git URL) into a temp dir and scans it. --history scans
// every blob; otherwise the default-branch working tree. Auth via your existing git credentials.
func cmdRepo(args []string) int {
	c, rest, err := parseCommand("repo", args)
	if err != nil {
		return commandParseError(err)
	}
	branch, depth := c.cmd.branch, c.cmd.depth
	if code := checkSourceModes(c, nil); code != 0 {
		return code
	}
	setupLogging(c)
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "usage: prowl repo <git-url> [--branch B] [--history] [--depth N] [scan flags]")
		return 2
	}
	if len(rest) > 1 {
		logx.Error("scan one repository at a time (for many, use 'prowl org')", "given", len(rest))
		return 2
	}
	ctx, stop := rootContext(c)
	defer stop()
	return scanCheckout(ctx, c, source.CloneOpts{URL: rest[0], Branch: branch, Full: c.history, Depth: depth})
}

// scanCheckout scans a cloned repository without changing the caller's directory. The checkout's
// source paths remain repository-relative, and acquisition failures enter the incomplete report.
func scanCheckout(ctx context.Context, c commonFlags, o source.CloneOpts) int {
	cleanup := func() {}
	defer func() { cleanup() }()
	c.noAutoConfig = true // ignore the cloned repo's own .prowl.yaml (only an explicit --config is trusted)
	return scanItemStream(ctx, c, func(ctx context.Context, c commonFlags) (<-chan model.Item, error) {
		logx.Info("cloning repository", "url", source.RepositoryLocator(o.URL), "history", o.Full)
		if o.Timeout == 0 {
			o.Timeout = c.timeout
		}
		cloned := startStage(c, "cloning repository")
		dir, release, err := source.CloneRepo(ctx, o)
		cloned()
		cleanup = release
		if err != nil {
			logx.Error("clone failed", "url", source.RepositoryLocator(o.URL), "err", err)
			return mapSourcePaths(ctx, nil, nil, model.Item{Source: "code", Path: source.RepositoryLocator(o.URL), Error: err}), nil
		}
		ctx, revisionErr := source.RepositoryContext(ctx, dir, o)
		var items <-chan model.Item
		if c.crossFile {
			if c.gitTimeline {
				items = source.GitCredentialTimeline(ctx, dir, c.exclude, c.maxSize)
			} else if c.history {
				items = source.GitCredentialHistory(ctx, dir, c.exclude, c.maxSize)
			} else {
				items = source.RepositoryCredentialFiles(ctx, dir, c.exclude, c.maxSize)
			}
		} else {
			items, err = scanInputAt(ctx, c, []string{dir}, dir)
		}
		if err != nil {
			return mapSourcePaths(ctx, nil, nil, model.Item{Source: "code", Path: source.RepositoryLocator(o.URL), Error: err}), nil
		}
		var initial []model.Item
		if revisionErr != nil {
			initial = append(initial, model.Item{Source: "code", Path: source.RepositoryLocator(o.URL), Error: revisionErr})
		}
		return mapSourcePaths(ctx, items, func(p string) (string, error) {
			if c.crossFile || c.history || c.staged || c.since != "" {
				return p, nil // Git sources already carry repository-relative locators
			}
			return relativeSourcePath(dir, p)
		}, initial...), nil
	})
}
