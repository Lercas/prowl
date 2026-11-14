package main

import (
	"context"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/source"
)

func cmdAgents(args []string) int {
	c, projects, err := parseCommand("agents", args)
	if err != nil {
		return commandParseError(err)
	}
	c.noAutoPolicy = true
	c.noAutoConfig = true // A transcript/config being audited cannot suppress itself.
	ctx, stop := rootContext(c)
	defer stop()
	return scanItemStream(ctx, c, func(ctx context.Context, c commonFlags) (<-chan model.Item, error) {
		return source.AgentSurface(ctx, source.AgentOptions{Projects: projects, Home: c.cmd.agentHome, ShellHistory: c.cmd.shellHistory, MaxBytes: c.maxSize, Exclude: c.exclude}), nil
	})
}
