// Package doctor self-diagnoses a Prowl install: taxonomy, checksum validators, detection,
// example filtering, config, and git availability. Exits non-zero if any critical check fails.
package doctor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Lercas/prowl/tool/internal/config"
	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

type Status int

const (
	StatusOK Status = iota
	StatusWarn
	StatusFail
)

// Check is one diagnostic result.
type Check struct {
	Name   string
	Status Status
	Detail string
}

// validGithubToken is a synthetic token whose trailing CRC32 is valid under the standard
// (digits-first) base62 alphabet, used to exercise the checksum path end-to-end.
const validGithubToken = "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"

var detectionCases = []struct{ name, payload, want string }{
	{"aws access key", `AWS = "AKIANAFGYOEYPXU1DSYP"`, "aws_access_key_id"},
	{"db connection string", `url = "postgres://svc:Pr0dPass99@10.0.0.4:5432/app"`, "db_connection_string"},
	{"private key (PEM)", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA1cd\n-----END RSA PRIVATE KEY-----", "private_key_pem"},
	{"jwt", `tok = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV9adQssw5c"`, "jwt"},
	{"github pat (checksum)", `t = "` + validGithubToken + `"`, "github_pat_classic"},
}

// Run executes all checks and returns them in display order.
func Run(det *detect.Detector, tax *taxonomy.Taxonomy, cfg *config.Config) []Check {
	var c []Check

	if len(tax.Types) == 0 {
		c = append(c, Check{"taxonomy", StatusFail, "no detectors compiled"})
	} else {
		c = append(c, Check{"taxonomy", StatusOK, fmt.Sprintf("%d detectors loaded", len(tax.Types))})
	}

	if len(tax.Skipped) > 0 {
		c = append(c, Check{"regex RE2 compatibility", StatusWarn,
			fmt.Sprintf("%d regex(es) not RE2-compatible (skipped)", len(tax.Skipped))})
	} else {
		c = append(c, Check{"regex RE2 compatibility", StatusOK, "all detector regexes compile"})
	}

	c = append(c, checksumCheck(), detectionCheck(det), exampleCheck(det))
	c = append(c, configChecks(cfg)...)
	c = append(c, gitCheck())
	// Optional source tooling/auth. These never FAIL: each tool is needed only for one source mode
	// (bucket/image/org), so a warn is a "configure this before using that source" hint, not a defect.
	c = append(c, awsCheck(), gcloudCheck(), dockerConfigCheck(), forgeTokenCheck())
	c = append(c, Check{"runtime", StatusOK,
		fmt.Sprintf("%s, %d CPU (default --workers)", runtime.Version(), runtime.NumCPU())})
	return c
}

// Healthy reports whether no check failed (warnings are tolerated).
func Healthy(checks []Check) bool {
	for _, c := range checks {
		if c.Status == StatusFail {
			return false
		}
	}
	return true
}

func checksumCheck() Check {
	switch {
	case !detect.GithubChecksumOK(validGithubToken):
		return Check{"checksum validators", StatusFail, "github CRC rejected a known-valid token"}
	case detect.GithubChecksumOK("ghp_" + strings.Repeat("a", 36)):
		return Check{"checksum validators", StatusFail, "github CRC accepted a bad token"}
	case !detect.JWTStructuralOK("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"):
		return Check{"checksum validators", StatusFail, "jwt structural check rejected a valid token"}
	default:
		return Check{"checksum validators", StatusOK, "github CRC + jwt structural pass"}
	}
}

func detectionCheck(det *detect.Detector) Check {
	var missing []string
	for _, tc := range detectionCases {
		found := false
		for _, m := range det.Scan(tc.payload) {
			if m.Type == tc.want {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, tc.name)
		}
	}
	if len(missing) > 0 {
		return Check{"detection self-test", StatusFail, "did not detect: " + strings.Join(missing, ", ")}
	}
	return Check{"detection self-test", StatusOK,
		fmt.Sprintf("%d/%d representative secrets detected", len(detectionCases), len(detectionCases))}
}

func exampleCheck(det *detect.Detector) Check {
	if len(det.Scan(`k = "AKIAIOSFODNN7EXAMPLE"`)) != 0 {
		return Check{"example/placeholder filter", StatusFail, "documentation example key was not filtered"}
	}
	return Check{"example/placeholder filter", StatusOK, "known example/placeholder values ignored"}
}

func configChecks(cfg *config.Config) []Check {
	if cfg == nil {
		return nil
	}
	if issues := cfg.Issues(); len(issues) > 0 {
		return []Check{{"config", StatusFail, strings.Join(issues, "; ")}}
	}
	n := len(cfg.Detectors.Custom)
	if n > 0 {
		return []Check{{"config", StatusOK, fmt.Sprintf("valid (%d custom rule(s) compile)", n)}}
	}
	return []Check{{"config", StatusOK, "valid (or none — using defaults)"}}
}

func gitCheck() Check {
	if _, err := exec.LookPath("git"); err != nil {
		return Check{"git", StatusWarn, "not found — --staged/--since/--history unavailable"}
	}
	return Check{"git", StatusOK, "available (git source modes enabled)"}
}

func awsCheck() Check {
	if _, err := exec.LookPath("aws"); err != nil {
		return Check{"aws CLI", StatusWarn, "not found — 'prowl bucket s3://…' unavailable (install & configure credentials)"}
	}
	return Check{"aws CLI", StatusOK, "on PATH ('prowl bucket s3://…' enabled — auth via your AWS config)"}
}

func gcloudCheck() Check {
	if _, err := exec.LookPath("gcloud"); err != nil {
		return Check{"gcloud CLI", StatusWarn, "not found — 'prowl bucket gs://…' unavailable (install & authenticate)"}
	}
	return Check{"gcloud CLI", StatusOK, "on PATH ('prowl bucket gs://…' enabled — auth via your gcloud config)"}
}

// dockerConfigCheck reports whether ~/.docker/config.json exists. It is needed only to pull from
// PRIVATE registries with 'prowl image'; public images work without it, so a missing file is a warn.
func dockerConfigCheck() Check {
	home, err := os.UserHomeDir()
	if err != nil {
		return Check{"docker config", StatusWarn, "cannot resolve home dir — private 'prowl image' registries may need ~/.docker/config.json"}
	}
	path := filepath.Join(home, ".docker", "config.json")
	if _, err := os.Stat(path); err != nil {
		return Check{"docker config", StatusWarn, "no ~/.docker/config.json — 'prowl image' can pull public images, but private registries need 'docker login'"}
	}
	return Check{"docker config", StatusOK, "~/.docker/config.json present ('prowl image' can reach your private registries)"}
}

// forgeTokenCheck reports which forge tokens are set among GITHUB_TOKEN/GITLAB_TOKEN/BITBUCKET_TOKEN.
// These let 'prowl org' enumerate private repos / lift rate limits; none being set is a warn, not a
// failure, since public orgs scan unauthenticated.
func forgeTokenCheck() Check {
	var set []string
	for _, name := range []string{"GITHUB_TOKEN", "GITLAB_TOKEN", "BITBUCKET_TOKEN"} {
		if os.Getenv(name) != "" {
			set = append(set, name)
		}
	}
	if len(set) == 0 {
		return Check{"forge tokens", StatusWarn,
			"none set — 'prowl org' scans public repos only (set GITHUB_TOKEN/GITLAB_TOKEN/BITBUCKET_TOKEN for private repos & rate limits)"}
	}
	return Check{"forge tokens", StatusOK, "set: " + strings.Join(set, ", ") + " ('prowl org' can reach matching private repos)"}
}
