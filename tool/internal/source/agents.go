package source

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/resilience"
)

const maxAgentFiles = 10000

type AgentOptions struct {
	Projects     []string
	Home         string // Explicit operator-selected home; never inferred from environment.
	ShellHistory bool
	MaxBytes     int64
	Exclude      []string
}

type agentTarget struct{ path, product string }

var projectAgentTargets = []agentTarget{{".mcp.json", "mcp"}, {"mcp.json", "mcp"}, {".cursor", "cursor"}, {".claude", "claude"}, {".codex", "codex"}, {".agents", "agents"}, {"AGENTS.md", "instructions"}, {"CLAUDE.md", "instructions"}, {".cursorrules", "cursor"}}
var homeAgentTargets = []agentTarget{{".claude", "claude"}, {".cursor", "cursor"}, {".codex", "codex"}, {".config/Claude", "claude"}, {".config/Cursor/User", "cursor"}, {"Library/Application Support/Claude/claude_desktop_config.json", "mcp"}, {"Library/Application Support/Cursor/User", "cursor"}, {"AppData/Roaming/Claude/claude_desktop_config.json", "mcp"}, {"AppData/Roaming/Cursor/User", "cursor"}}

// AgentSurface selects known agent paths and text exports, not the entire home
// directory. Missing optional targets are normal; an unreadable requested root
// or selected file remains an incomplete-source diagnostic.
func AgentSurface(ctx context.Context, o AgentOptions) <-chan model.Item {
	projects := o.Projects
	if len(projects) == 0 && o.Home == "" {
		projects = []string{"."}
	}
	for _, project := range projects {
		registerLocalScope(ctx, "agent-project", project, o)
	}
	if o.Home != "" {
		registerLocalScope(ctx, "agent-home", o.Home, o)
	}
	ch := make(chan model.Item, 64)
	go func() {
		defer close(ch)
		resilience.Guard(func() {
			if o.MaxBytes <= 0 {
				send(ctx, ch, model.Item{Source: "code", Error: errors.New("agent input size must be positive")})
				return
			}
			projects := o.Projects
			if len(projects) == 0 && o.Home == "" {
				projects = []string{"."}
			}
			budget := maxAgentFiles
			seen := make(map[string]bool)
			for _, root := range projects {
				if !walkAgentRoot(ctx, ch, root, projectAgentTargets, o, &budget, seen) {
					return
				}
			}
			if o.Home != "" {
				info, err := os.Lstat(o.Home)
				if err != nil {
					emitSourceError(ctx, ch, o.Home, err)
					return
				}
				if !info.IsDir() {
					emitSourceError(ctx, ch, o.Home, errors.New("agent home must be a directory"))
					return
				}
				targets := append([]agentTarget(nil), homeAgentTargets...)
				if o.ShellHistory {
					targets = append(targets, agentTarget{".zsh_history", "shell"}, agentTarget{".bash_history", "shell"}, agentTarget{".config/fish/fish_history", "shell"})
				}
				walkAgentRoot(ctx, ch, o.Home, targets, o, &budget, seen)
			}
		}, func(any) { send(ctx, ch, model.Item{Source: "code", Error: errors.New("agent surface reader failed")}) })
	}()
	return ch
}

func walkAgentRoot(ctx context.Context, ch chan<- model.Item, rootPath string, targets []agentTarget, o AgentOptions, budget *int, seen map[string]bool) bool {
	if hasParentSegment(rootPath) {
		resolved, err := filepath.EvalSymlinks(rootPath)
		if err != nil {
			return emitSourceError(ctx, ch, rootPath, err)
		}
		rootPath = resolved
	}
	absolute, err := filepath.Abs(rootPath)
	if err != nil {
		return emitSourceError(ctx, ch, rootPath, err)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return emitSourceError(ctx, ch, absolute, err)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return emitSourceError(ctx, ch, absolute, errors.New("agent root must not be a symlink"))
	}
	if !info.IsDir() {
		if !info.Mode().IsRegular() {
			return emitSourceError(ctx, ch, absolute, errors.New("agent input must be a regular file"))
		}
		targets = []agentTarget{{filepath.Base(absolute), "custom"}}
		absolute = filepath.Dir(absolute)
	}
	root, err := os.OpenRoot(absolute)
	if err != nil {
		return emitSourceError(ctx, ch, absolute, err)
	}
	defer root.Close()
	for _, target := range targets {
		name := filepath.ToSlash(target.path)
		optionalMissing := false
		invalid := false
		segments := strings.Split(name, "/")
		for i := range segments {
			relative := strings.Join(segments[:i+1], "/")
			info, err := root.Lstat(relative)
			if errors.Is(err, os.ErrNotExist) {
				optionalMissing = true
				break
			}
			if err != nil {
				if !emitSourceError(ctx, ch, filepath.Join(absolute, target.path), err) {
					return false
				}
				invalid = true
				break
			}
			if info.Mode()&fs.ModeSymlink != 0 {
				if !emitSourceError(ctx, ch, filepath.Join(absolute, target.path), errors.New("agent surface symlink was not followed")) {
					return false
				}
				invalid = true
				break
			}
		}
		if optionalMissing || invalid {
			continue
		}
		stop := false
		err := fs.WalkDir(root.FS(), name, func(relative string, entry fs.DirEntry, walkErr error) error {
			if ctx.Err() != nil {
				stop = true
				return fs.SkipAll
			}
			display := filepath.Join(absolute, filepath.FromSlash(relative))
			if excludedSourcePath(display, o.Exclude) || stateDirectoryExcluded(ctx, display) {
				if entry != nil && entry.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if walkErr != nil {
				if !emitSourceError(ctx, ch, display, walkErr) {
					stop = true
					return fs.SkipAll
				}
				return nil
			}
			if entry.Type()&fs.ModeSymlink != 0 {
				if !emitSourceError(ctx, ch, display, errors.New("agent surface symlink was not followed")) {
					stop = true
					return fs.SkipAll
				}
				return nil
			}
			if entry.IsDir() {
				if defaultSkipDirs[entry.Name()] {
					return fs.SkipDir
				}
				return nil
			}
			if relative != name && !agentTextFile(relative, target.product) {
				return nil
			}
			if seen[display] {
				return nil
			}
			seen[display] = true
			if *budget <= 0 {
				emitSourceError(ctx, ch, display, errors.New("agent surface file limit reached"))
				stop = true
				return fs.SkipAll
			}
			*budget -= 1
			data, readErr := readSourceFile(func() (*os.File, error) {
				before, err := root.Lstat(relative)
				if err != nil {
					return nil, err
				}
				if !before.Mode().IsRegular() {
					return nil, errors.New("agent input must remain a regular file")
				}
				file, err := root.OpenFile(relative, os.O_RDONLY|sourceOpenFlags, 0)
				if err != nil {
					return nil, err
				}
				opened, statErr := file.Stat()
				after, pathErr := root.Lstat(relative)
				if statErr != nil || pathErr != nil || !os.SameFile(before, opened) || !after.Mode().IsRegular() || !os.SameFile(before, after) {
					_ = file.Close()
					return nil, errors.New("agent input identity changed while opening")
				}
				return file, nil
			}, o.MaxBytes)
			if readErr != nil {
				if !emitSourceError(ctx, ch, display, readErr) {
					stop = true
					return fs.SkipAll
				}
				return nil
			}
			text, ok := scannableText(data)
			if !ok {
				if !emitSourceError(ctx, ch, display, errors.New("selected agent text file contains binary data")) {
					stop = true
					return fs.SkipAll
				}
				return nil
			}
			kind := agentKind(relative, target.product)
			source := "code"
			if kind == "history" || kind == "transcript" {
				source = "log"
			}
			if !send(ctx, ch, model.Item{Source: source, Path: display, Text: string(text), Agent: &model.AgentProvenance{Product: target.product, Kind: kind}}) {
				stop = true
				return fs.SkipAll
			}
			return nil
		})
		if stop {
			return false
		}
		if err != nil && !emitSourceError(ctx, ch, filepath.Join(absolute, target.path), err) {
			return false
		}
	}
	return true
}

func agentTextFile(path, product string) bool {
	if product == "shell" {
		return true
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json", ".jsonl", ".ndjson", ".toml", ".yaml", ".yml", ".md", ".mdc", ".txt", ".log", ".conf", ".ini", ".env", ".cfg", ".xml":
		return true
	}
	name := strings.ToLower(filepath.Base(path))
	return name == ".cursorrules" || name == "config" || name == "settings" || strings.HasPrefix(name, ".env.")
}

func agentKind(path, product string) string {
	if product == "shell" {
		return "history"
	}
	lower := strings.ToLower(filepath.ToSlash(path))
	if strings.HasSuffix(lower, ".jsonl") || strings.HasSuffix(lower, ".ndjson") || strings.HasSuffix(lower, ".log") || strings.Contains(lower, "transcript") || strings.Contains(lower, "/sessions/") {
		return "transcript"
	}
	if product == "instructions" || strings.HasSuffix(lower, ".md") || strings.HasSuffix(lower, ".mdc") || strings.HasSuffix(lower, ".cursorrules") {
		return "instructions"
	}
	return "config"
}
