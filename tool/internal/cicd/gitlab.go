package cicd

import (
	"context"
	"fmt"
	"net/url"
	"strconv"

	"github.com/Lercas/prowl/tool/internal/model"
)

type gitlabPipeline struct {
	ID     int64  `json:"id"`
	Ref    string `json:"ref"`
	SHA    string `json:"sha"`
	WebURL string `json:"web_url"`
}

type gitlabJob struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	WebURL        string `json:"web_url"`
	ArtifactsFile struct {
		Filename string `json:"filename"`
		Size     int64  `json:"size"`
	} `json:"artifacts_file"`
}

func (c *collector) collectGitLab(ctx context.Context, out chan<- model.Item, result *Result) {
	project := url.PathEscape(c.target.repo)
	basePath := "/projects/" + project
	for page := 1; result.Runs < c.opts.MaxRuns; page++ {
		q := url.Values{
			"per_page": {"100"},
			"page":     {strconv.Itoa(page)},
		}
		if c.opts.Branch != "" {
			q.Set("ref", c.opts.Branch)
		}
		var pipelines []gitlabPipeline
		if err := c.getJSON(ctx, apiURL(c.opts.BaseURL, basePath+"/pipelines", q), &pipelines); err != nil {
			c.fail(result, err)
			return
		}
		if len(pipelines) == 0 {
			return
		}
		for _, pipeline := range pipelines {
			if result.Runs >= c.opts.MaxRuns || ctx.Err() != nil {
				return
			}
			result.Runs++
			prefix := "gitlab:" + c.target.repo + "/pipelines/" + runLabel(pipeline.Ref, pipeline.ID)
			c.collectGitLabJobs(model.WithProvenance(ctx, map[string]any{"commit": pipeline.SHA, "run_id": strconv.FormatInt(pipeline.ID, 10)}), out, result, basePath, prefix, pipeline)
		}
		if len(pipelines) < 100 {
			return
		}
	}
}

func (c *collector) collectGitLabJobs(ctx context.Context, out chan<- model.Item, result *Result, basePath, prefix string, pipeline gitlabPipeline) {
	for page := 1; ; page++ {
		q := url.Values{
			"per_page":        {"100"},
			"page":            {strconv.Itoa(page)},
			"include_retried": {"true"},
		}
		var jobs []gitlabJob
		listURL := apiURL(c.opts.BaseURL, basePath+"/pipelines/"+strconv.FormatInt(pipeline.ID, 10)+"/jobs", q)
		if err := c.getJSON(ctx, listURL, &jobs); err != nil {
			c.fail(result, fmt.Errorf("pipeline %d jobs: %w", pipeline.ID, err))
			return
		}
		if len(jobs) == 0 {
			return
		}
		for _, job := range jobs {
			if ctx.Err() != nil {
				return
			}
			jobPath := prefix + "/jobs/" + runLabel(job.Name, job.ID)
			if c.opts.IncludeLogs {
				traceURL := apiURL(c.opts.BaseURL, basePath+"/jobs/"+strconv.FormatInt(job.ID, 10)+"/trace", nil)
				raw, err := c.download(ctx, traceURL)
				if err != nil {
					c.fail(result, fmt.Errorf("job %d trace: %w", job.ID, err))
				} else if err := c.emitPayload(ctx, out, jobPath+"/trace.log", job.WebURL, raw, result); err != nil {
					c.fail(result, fmt.Errorf("job %d trace: %w", job.ID, err))
				}
			}
			if c.opts.IncludeArtifacts && job.ArtifactsFile.Filename != "" {
				if result.Artifacts >= c.opts.MaxArtifacts {
					continue
				}
				result.Artifacts++
				artifactURL := apiURL(c.opts.BaseURL, basePath+"/jobs/"+strconv.FormatInt(job.ID, 10)+"/artifacts", nil)
				raw, err := c.download(ctx, artifactURL)
				if err != nil {
					c.fail(result, fmt.Errorf("job %d artifact: %w", job.ID, err))
					continue
				}
				if err := c.emitPayload(ctx, out, jobPath+"/artifacts", job.WebURL, raw, result); err != nil {
					c.fail(result, fmt.Errorf("job %d artifact: %w", job.ID, err))
				}
			}
		}
		if len(jobs) < 100 {
			return
		}
	}
}
