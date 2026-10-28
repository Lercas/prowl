package cicd

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/Lercas/prowl/tool/internal/model"
)

type githubRuns struct {
	Runs []struct {
		ID         int64  `json:"id"`
		Name       string `json:"name"`
		HTMLURL    string `json:"html_url"`
		HeadBranch string `json:"head_branch"`
		HeadSHA    string `json:"head_sha"`
	} `json:"workflow_runs"`
}

type githubArtifacts struct {
	Artifacts []struct {
		ID      int64  `json:"id"`
		Name    string `json:"name"`
		Expired bool   `json:"expired"`
	} `json:"artifacts"`
}

func (c *collector) collectGitHub(ctx context.Context, out chan<- model.Item, result *Result) {
	repo := c.target.repo
	basePath := "/repos/" + escapedPath(repo)
	for page := 1; result.Runs < c.opts.MaxRuns; page++ {
		q := url.Values{
			"per_page": {"100"},
			"page":     {strconv.Itoa(page)},
			"status":   {"completed"},
		}
		if c.opts.Branch != "" {
			q.Set("branch", c.opts.Branch)
		}
		var payload githubRuns
		if err := c.getJSON(ctx, apiURL(c.opts.BaseURL, basePath+"/actions/runs", q), &payload); err != nil {
			c.fail(result, err)
			return
		}
		if len(payload.Runs) == 0 {
			return
		}
		for _, run := range payload.Runs {
			if result.Runs >= c.opts.MaxRuns || ctx.Err() != nil {
				return
			}
			result.Runs++
			runCtx := model.WithProvenance(ctx, map[string]any{"run_id": strconv.FormatInt(run.ID, 10), "commit": run.HeadSHA})
			label := runLabel(run.Name, run.ID)
			prefix := "github:" + repo + "/actions/" + label
			if c.opts.IncludeLogs {
				rawURL := apiURL(c.opts.BaseURL, basePath+"/actions/runs/"+strconv.FormatInt(run.ID, 10)+"/logs", nil)
				raw, err := c.download(ctx, rawURL)
				if err != nil {
					c.fail(result, fmt.Errorf("run %d logs: %w", run.ID, err))
				} else if err := c.emitPayload(runCtx, out, prefix+"/logs", run.HTMLURL, raw, result); err != nil {
					c.fail(result, fmt.Errorf("run %d logs: %w", run.ID, err))
				}
			}
			if c.opts.IncludeArtifacts && result.Artifacts < c.opts.MaxArtifacts {
				c.collectGitHubArtifacts(runCtx, out, result, basePath, prefix, run.ID, run.HTMLURL)
			}
		}
		if len(payload.Runs) < 100 {
			return
		}
	}
}

func (c *collector) collectGitHubArtifacts(ctx context.Context, out chan<- model.Item, result *Result, basePath, prefix string, runID int64, runURL string) {
	for page := 1; result.Artifacts < c.opts.MaxArtifacts; page++ {
		q := url.Values{"per_page": {"100"}, "page": {strconv.Itoa(page)}}
		var payload githubArtifacts
		listURL := apiURL(c.opts.BaseURL, basePath+"/actions/runs/"+strconv.FormatInt(runID, 10)+"/artifacts", q)
		if err := c.getJSON(ctx, listURL, &payload); err != nil {
			c.fail(result, fmt.Errorf("run %d artifacts: %w", runID, err))
			return
		}
		if len(payload.Artifacts) == 0 {
			return
		}
		for _, artifact := range payload.Artifacts {
			if result.Artifacts >= c.opts.MaxArtifacts || ctx.Err() != nil {
				return
			}
			if artifact.Expired {
				result.Skipped++
				continue
			}
			result.Artifacts++
			downloadURL := apiURL(c.opts.BaseURL, basePath+"/actions/artifacts/"+strconv.FormatInt(artifact.ID, 10)+"/zip", nil)
			raw, err := c.download(ctx, downloadURL)
			if err != nil {
				c.fail(result, fmt.Errorf("artifact %d: %w", artifact.ID, err))
				continue
			}
			artifactPath := prefix + "/artifacts/" + runLabel(artifact.Name, artifact.ID)
			artifactCtx := model.WithProvenance(ctx, map[string]any{"artifact_id": strconv.FormatInt(artifact.ID, 10)})
			if err := c.emitPayload(artifactCtx, out, artifactPath, runURL, raw, result); err != nil {
				c.fail(result, fmt.Errorf("artifact %d: %w", artifact.ID, err))
			}
		}
		if len(payload.Artifacts) < 100 {
			return
		}
	}
}

func escapedPath(repo string) string {
	parts := strings.Split(repo, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}
