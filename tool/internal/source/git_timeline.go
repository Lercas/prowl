package source

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Lercas/prowl/tool/internal/config"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/resilience"
)

const maxTimelineCommits = 10000
const maxTimelineChanges = 1000000
const maxTimelineOutput = 64 << 20

// timelineOutput is bounded before materialization. Unlike Command.Output,
// hostile commit metadata and raw path lists cannot allocate unbounded buffers.
func timelineOutput(ctx context.Context, dir string, args ...string) ([]byte, error) {
	processCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := gitCmd(processCtx, dir, args...)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(pipe, maxTimelineOutput+1))
	if readErr != nil || len(data) > maxTimelineOutput {
		cancel()
	}
	_ = pipe.Close()
	waitErr := cmd.Wait()
	if len(data) > maxTimelineOutput {
		return nil, errors.New("git timeline output limit reached")
	}
	return data, errors.Join(readErr, waitErr)
}

func readTimelineGraph(ctx context.Context, dir string) (*model.GitHistoryGraph, []model.GitObject, error) {
	head, err := timelineOutput(ctx, dir, "rev-parse", "--verify", "HEAD")
	if err != nil {
		return nil, nil, err
	}
	if !timelineObjectID(strings.TrimSpace(string(head))) {
		return nil, nil, errors.New("invalid git timeline HEAD")
	}
	shallow, err := timelineOutput(ctx, dir, "rev-parse", "--is-shallow-repository")
	if err != nil {
		return nil, nil, err
	}
	raw, err := timelineOutput(ctx, dir, "log", "--no-show-signature", "--no-notes", "--all", strings.TrimSpace(string(head)), "--topo-order", "--reverse", "--format=%H%x00%P%x00%an%x00%aI%x00%cI%x00")
	if err != nil {
		return nil, nil, err
	}
	graph := &model.GitHistoryGraph{Head: strings.TrimSpace(string(head)), Complete: strings.TrimSpace(string(shallow)) == "false", Changes: make(map[string]map[string]string)}
	fields := strings.Split(string(raw), "\x00")
	if len(fields)%5 != 1 || strings.TrimSpace(fields[len(fields)-1]) != "" {
		return nil, nil, errors.New("invalid git timeline log framing")
	}
	objects := make(map[model.GitObject]bool)
	var ordered []model.GitObject
	changes := 0
	totalBytes := len(raw)
	for i := 0; i+4 < len(fields); i += 5 {
		hash := strings.TrimPrefix(fields[i], "\n")
		if hash == "" {
			return nil, nil, errors.New("empty git timeline commit")
		}
		if len(graph.Commits) >= maxTimelineCommits {
			return nil, nil, errors.New("git timeline commit limit reached")
		}
		authorDate, e1 := time.Parse(time.RFC3339, fields[i+3])
		commitDate, e2 := time.Parse(time.RFC3339, fields[i+4])
		if e1 != nil || e2 != nil {
			return nil, nil, errors.New("invalid git timeline commit date")
		}
		commit := model.GitCommit{Hash: hash, Parents: strings.Fields(fields[i+1]), Author: fields[i+2], AuthoredAt: authorDate, CommittedAt: commitDate}
		if !timelineObjectID(hash) {
			return nil, nil, errors.New("invalid git timeline commit")
		}
		for _, parent := range commit.Parents {
			if !timelineObjectID(parent) {
				return nil, nil, errors.New("invalid git timeline parent")
			}
		}
		graph.Commits = append(graph.Commits, commit)
		args := []string{"diff-tree", "--no-color", "--no-ext-diff", "--no-textconv", "--no-commit-id", "--raw", "--no-renames", "--no-abbrev", "-r", "-z"}
		if len(commit.Parents) == 0 {
			args = append(args, "--root", hash)
		} else {
			args = append(args, commit.Parents[0], hash)
		}
		args = append(args, "--")
		diff, err := timelineOutput(ctx, dir, args...)
		if err != nil {
			return nil, nil, err
		}
		totalBytes += len(diff)
		if totalBytes > maxTimelineOutput {
			return nil, nil, errors.New("git timeline graph size limit reached")
		}
		entries, err := parseTimelineChanges(diff)
		if err != nil {
			return nil, nil, err
		}
		changes += len(entries)
		if changes > maxTimelineChanges {
			return nil, nil, errors.New("git timeline change limit reached")
		}
		graph.Changes[hash] = entries
		for path, blob := range entries {
			if blob == "" {
				continue
			}
			object := model.GitObject{Path: path, Blob: blob}
			if !objects[object] {
				objects[object] = true
				ordered = append(ordered, object)
			}
		}
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Path != ordered[j].Path {
			return ordered[i].Path < ordered[j].Path
		}
		return ordered[i].Blob < ordered[j].Blob
	})
	return graph, ordered, nil
}

func parseTimelineChanges(raw []byte) (map[string]string, error) {
	fields := strings.Split(string(raw), "\x00")
	changes := make(map[string]string)
	if len(fields)%2 != 1 || fields[len(fields)-1] != "" {
		return nil, errors.New("unterminated git timeline raw diff")
	}
	for i := 0; i+1 < len(fields); i += 2 {
		if fields[i] == "" {
			return nil, errors.New("empty git timeline diff record")
		}
		header := strings.Fields(fields[i])
		if fields[i+1] == "" || len(header) != 5 || !strings.HasPrefix(header[0], ":") || !timelineObjectID(header[2]) || !timelineObjectID(header[3]) {
			return nil, errors.New("invalid git timeline raw diff")
		}
		blob := header[3]
		// Submodules are not blobs; a type change to one removes this tracked file.
		if header[1] == "160000" || strings.Trim(blob, "0") == "" {
			blob = ""
		}
		changes[fields[i+1]] = blob
	}
	return changes, nil
}

// GitTimelineBlobs scans each (path,blob) pair once. Unlike rev-list --objects,
// it preserves aliases and a graph of every reachable commit's first-parent diff.
func GitTimelineBlobs(ctx context.Context, dir string, exclude []string, maxBytes int64) <-chan model.Item {
	registerGitScope(ctx, "git-timeline", dir, nil, exclude, maxBytes)
	ch := make(chan model.Item, 64)
	go func() {
		defer close(ch)
		resilience.Guard(func() {
			if err := streamTimeline(ctx, ch, dir, exclude, maxBytes); err != nil {
				send(ctx, ch, model.Item{Source: "code", Error: err})
			}
		}, func(any) { send(ctx, ch, model.Item{Source: "code", Error: errors.New("git timeline reader failed")}) })
	}()
	return ch
}

func streamTimeline(ctx context.Context, ch chan<- model.Item, dir string, exclude []string, maxBytes int64) (err error) {
	graph, objects, err := readTimelineGraph(ctx, dir)
	if err != nil {
		return fmt.Errorf("git timeline acquisition: %w", err)
	}
	processCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cat := gitCmd(processCtx, dir, "cat-file", "--batch")
	input, err := cat.StdinPipe()
	if err != nil {
		return err
	}
	output, err := cat.StdoutPipe()
	if err != nil {
		_ = input.Close()
		return err
	}
	if err = cat.Start(); err != nil {
		_ = input.Close()
		_ = output.Close()
		return err
	}
	defer func() {
		_ = input.Close()
		if err != nil {
			cancel()
		}
		waitErr := cat.Wait()
		_ = output.Close()
		if err == nil && waitErr != nil {
			err = fmt.Errorf("git timeline cat-file: %w", waitErr)
		}
	}()
	reader := bufio.NewReader(output)
	for _, object := range objects {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if skipByExtension(ctx, object.Path) {
			continue
		}
		skip := false
		for _, pattern := range exclude {
			if config.PathMatch(pattern, object.Path) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		if _, err = io.WriteString(input, object.Blob+"\n"); err != nil {
			return err
		}
		header, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		if !strings.HasPrefix(header, object.Blob+" ") {
			return errors.New("git timeline object identity mismatch")
		}
		kind, size, ok := parseCatFileHeader(header)
		if !ok || kind != "blob" {
			return errors.New("invalid git timeline blob header")
		}
		body, err := consumeBlob(reader, size, maxBytes)
		if err != nil {
			return err
		}
		if size > maxBytes {
			if !send(ctx, ch, model.Item{Source: "code", Path: object.Path, Error: errors.New("git timeline blob exceeds max-size")}) {
				return ctx.Err()
			}
			continue
		}
		record := &model.GitRecord{Graph: graph, Object: object}
		if !emitPayload(ctx, ch, object.Path, body, maxBytes, exclude, map[string]any{"blob": object.Blob, "git_history": record}) {
			return ctx.Err()
		}
	}
	if !graph.Complete {
		return errors.New("shallow git history cannot establish a complete timeline")
	}
	return nil
}

func timelineObjectID(id string) bool {
	return (len(id) == 40 || len(id) == 64) && strings.Trim(id, "0123456789abcdef") == ""
}
