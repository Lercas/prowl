package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/Lercas/prowl/tool/internal/cicd"
	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/scan"
)

// cmdCICD scans recent CI logs and downloadable artifacts from one GitHub or GitLab repository.
// Authentication is environment-only so a forge token never lands in argv, shell history, or help.
func cmdCICD(args []string) int {
	c, rest, err := parseCommand("cicd", args)
	if err != nil {
		return commandParseError(err)
	}
	maxRuns, maxArtifacts, maxDownload := c.cmd.maxRuns, c.cmd.maxArtifacts, c.cmd.maxDownload
	logsOnly, artifactsOnly, branch := c.cmd.logsOnly, c.cmd.artifactsOnly, c.cmd.branch
	if code := rejectUnsupportedOCR(c, "cicd"); code != 0 {
		return code
	}
	setupLogging(c)
	targets := rest
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "usage: prowl cicd <github:owner/repo|gitlab:group/project> [--max-runs N] [--branch REF] [scan flags]")
		fmt.Fprintln(os.Stderr, "  auth: GITHUB_TOKEN or GITLAB_TOKEN; API overrides: GITHUB_API / GITLAB_API")
		return 2
	}
	if len(targets) != 1 {
		fmt.Fprintf(os.Stderr, "prowl cicd scans one repository at a time, got %d targets\n", len(targets))
		return 2
	}
	target := targets[0]
	if code := c.mlPreflight(); code != 0 {
		return code
	}

	platform, _, _ := strings.Cut(target, ":")
	var token, baseURL string
	switch platform {
	case "github":
		token = os.Getenv("GITHUB_TOKEN")
		baseURL = firstEnv("GITHUB_API")
	case "gitlab":
		token = os.Getenv("GITLAB_TOKEN")
		baseURL = firstEnv("GITLAB_API")
	default:
		fmt.Fprintf(os.Stderr, "unsupported CI platform %q (use github or gitlab)\n", platform)
		return 2
	}
	if token == "" {
		fmt.Fprintf(os.Stderr, "refusing: %s requires %s_TOKEN for read-only CI API access\n", target, strings.ToUpper(platform))
		return 2
	}

	// Remote CI content cannot provide a trusted .prowl.yaml. Only an explicitly selected --config
	// may affect this scan.
	c.noAutoConfig = true
	cfg, err := loadConfig(&c)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		return 2
	}
	det, _, err := loadDetector(c, cfg)
	if err != nil {
		logx.Error("failed to load detector", "err", err)
		return 2
	}

	eng, err := loadEngine(c)
	if err != nil {
		logx.Error("rule setup failed", "err", err)
		return 2
	}
	vset, verr := loadVerifySet(c)
	if verr != nil {
		logx.Error("verify setup failed", "err", verr)
		return 2
	}

	ctx, stop := rootContext(c)
	defer stop()
	items, done, err := cicd.Collect(ctx, target, cicd.Options{
		BaseURL:          baseURL,
		Token:            token,
		Branch:           branch,
		MaxRuns:          maxRuns,
		MaxArtifacts:     maxArtifacts,
		MaxDownload:      maxDownload,
		MaxItem:          c.maxSize,
		IncludeLogs:      !artifactsOnly,
		IncludeArtifacts: !logsOnly,
	})
	if err != nil {
		logx.Error("cannot start CI collection", "err", err)
		return 2
	}

	code := prepareScan(c, scan.Options{Detector: det, Rules: eng, Verifiers: vset, Allow: cfg.Allowed}).Run(ctx, items)
	result := <-done
	logx.Info("CI collection complete", "target", target, "runs", result.Runs, "artifacts",
		result.Artifacts, "items", result.Items, "skipped", result.Skipped, "failures", result.Failures)
	if result.Items == 0 && ctx.Err() == nil {
		logx.Error("scanned 0 CI items — check repository access, selected branch, and Actions/pipeline retention",
			"target", target)
		return 2
	}
	if result.Failures > 0 {
		logx.Error("CI collection was incomplete — failing closed; partial findings were still reported",
			"failures", result.Failures, "last_error", result.LastError)
		return 2
	}
	return code
}
