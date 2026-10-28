package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/Lercas/prowl/tool/internal/cicd"
	"github.com/Lercas/prowl/tool/internal/logx"
)

// cmdCICD scans recent CI logs and downloadable artifacts from one GitHub or GitLab repository.
// Authentication is environment-only so a forge token never lands in argv, shell history, or help.
func cmdCICD(args []string) int {
	maxRuns := 20
	if v := flagVal(args, "--max-runs"); v != "" {
		maxRuns = mustInt("--max-runs", v, 1)
	}
	maxArtifacts := 100
	if v := flagVal(args, "--max-artifacts"); v != "" {
		maxArtifacts = mustInt("--max-artifacts", v, 1)
	}
	maxDownload := int64(100 << 20)
	if v := flagVal(args, "--max-download"); v != "" {
		n, err := parseByteSize(v)
		if err != nil || n <= 0 {
			fmt.Fprintf(os.Stderr, "--max-download needs a positive size like 100MB, got %q\n", v)
			return 2
		}
		maxDownload = n
	}
	logsOnly := hasFlag(args, "--logs-only")
	artifactsOnly := hasFlag(args, "--artifacts-only")
	if logsOnly && artifactsOnly {
		fmt.Fprintln(os.Stderr, "--logs-only and --artifacts-only are mutually exclusive")
		return 2
	}

	branch := flagVal(args, "--branch")
	cleanArgs := stripValueFlags(args, "--max-runs", "--max-artifacts", "--max-download", "--branch")
	c, rest := parseCommon(cleanArgs)
	if code := rejectUnsupportedOCR(c, "cicd"); code != 0 {
		return code
	}
	setupLogging(c)
	var targets []string
	for _, arg := range rest {
		if !strings.HasPrefix(arg, "-") {
			targets = append(targets, arg)
		}
	}
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

	code := runPreparedScan(ctx, c, cfg, det, eng, vset, items, c.dedupe)
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
