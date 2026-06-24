package main

import (
	"fmt"
	"os"
	"strings"
)

type cmdInfo struct {
	name, summary, detail string
}

var commands = []cmdInfo{
	{"scan", "scan files, dirs, git, or stdin for secrets", scanHelp},
	{"repo", "clone & scan a remote git repository", repoHelp},
	{"org", "clone & scan every repo in an org/group/workspace", orgHelp},
	{"image", "pull & scan a container image", imageHelp},
	{"bucket", "download & scan a cloud storage prefix", bucketHelp},
	{"domain", "scan a live site (HTML + state blobs + JS)", domainHelp},
	{"jira", "scan Jira across every issue version (Cloud/Server/DC)", ""},
	{"confluence", "scan Confluence across every page version", ""},
	{"serve", "run as a stateless HTTP scan worker", serveHelp},
	{"lsp", "run as a Language Server (in-editor highlighting)", ""},
	{"doctor", "self-diagnose the install", ""},
	{"detectors", "list built-in detector types", ""},
	{"rules", "manage detection rule templates", rulesHelp},
	{"verifiers", "manage live-credential verifiers", verifiersHelp},
	{"config", "validate a .prowl.yaml", configHelp},
	{"version", "print the version", ""},
	{"help", "show help for a command", ""},
}

const scanHelp = `prowl scan [path...] — scan files/dirs for secrets (default: .)

  --rules-dir DIR              run nuclei-style rule templates from DIR
  --tags / --exclude-tags / --rule-severity   filter which templates run
  --verify                    confirm findings are LIVE via the provider
  --verified-only             report ONLY provider-confirmed-live secrets
  --fail-on LEVEL             exit 1 if any finding >= info|low|medium|high|critical
  --fail-on-verified          exit 1 ONLY on a provider-confirmed-LIVE secret (needs --verify; a
                              near-zero-FP CI gate); also bumps live findings to critical
  --format pretty|json|sarif  -o/--output FILE   write the report to a file
  --staged | --since <rev> | --history           scan git instead of the filesystem
  --baseline FILE | --write-baseline FILE         ignore already-known findings
  --exclude SUBSTR  --workers N  --max-size BYTES  --timeout DUR  --config FILE
  --min-confidence F | --min-severity LEVEL | --disable T1,T2 | --no-dedupe   cut noise
  --max-per-file N            cap generic findings per file (data-file guard; default 30, 0=off)
  --ml                        score candidates with the in-process ML model (no sidecar) and drop
                              ones it judges not-a-secret; --ml-threshold F (default 0.3) is the cutoff.
                              Needs a cgo build (default for go install/make build); a static release
                              binary refuses --ml — use --ml-url, or build from source.
  --ml-model FILE             load that model file instead of the embedded one (implies --ml); else
                              $PROWL_HOME/model_binary.json is auto-used, else the embedded model
  --ml-url URL                same, but via an external sidecar (src/serve.py) instead of the embed
  -                           scan stdin (also auto-read when input is piped and no path is given)

Examples:
  prowl scan .
  prowl scan src --rules-dir rules/ --tags aws,stripe
  prowl scan . --verify --verified-only --format sarif -o report.sarif
  prowl scan --staged --fail-on high            # pre-commit / CI gate
  kubectl get secret x -o yaml | prowl scan -   # scan piped input (stdin)

Run 'prowl help' for the full flag list.`

const repoHelp = `prowl repo <git-url> — clone a remote repository and scan it

  --history          scan EVERY blob in the repo's history (default: the working tree only)
  --branch NAME      clone a specific branch or tag (default: the remote's default branch)
  --depth N          shallow-clone depth (default 1; ignored with --history, which is a full clone)
  + all scan flags   --verify, --fail-on, --format, --rules-dir, --tags, --baseline, …

Works with any git URL — GitHub, GitLab, Bitbucket, or self-hosted. The checkout is made in a temp
dir and removed afterwards. Private repos use your existing git credentials (ssh keys / credential
helper) or a token embedded in the URL (https://<token>@host/org/repo.git). The ext:/file: transport
helpers are disabled, so a malicious URL cannot execute commands.

Examples:
  prowl repo https://github.com/org/repo
  prowl repo git@gitlab.com:group/repo.git --history --fail-on high
  prowl repo https://bitbucket.org/team/repo --branch release --verify`

const orgHelp = `prowl org <platform>:<name> — clone & scan every repo in an org/group/workspace

  github:<org-or-user>      every repo in a GitHub org or user account
  gitlab:<group>            every project in a GitLab group (subgroups included)
  bitbucket:<workspace>     every repo in a Bitbucket workspace
  --history          scan each repo's full blob history (default: the working tree)
  --concurrency N    repos scanned in parallel (default: min(4, number of repos))
  --exclude-repo S,… skip repos whose clone URL contains any of these substrings (e.g. a vendored fork)
  + all scan flags   --verify, --fail-on, --format, --rules-dir, --tags, …

Repos are listed via the platform API, then cloned and scanned in parallel (each temp checkout is
removed as it finishes; a slow or unreachable repo is logged and skipped, the sweep continues). Set a
token for private repos and higher rate limits:
  GITHUB_TOKEN / GITLAB_TOKEN / BITBUCKET_TOKEN   (GITHUB_API / GITLAB_API override the API host)
A scanned repo's own .prowl.yaml is ignored, so a repo cannot suppress its own findings. Findings from
all repos are merged into ONE report (each path prefixed "<owner>/<repo>: ", so json/sarif is a single
valid document); the exit code reflects --fail-on over all of them.

Examples:
  GITHUB_TOKEN=ghp_… prowl org github:Lercas --fail-on high
  prowl org gitlab:mygroup --history --format json
  prowl org bitbucket:myteam --verify --verified-only`

const imageHelp = `prowl image <ref> — pull a container image and scan it for secrets

  <ref>              any OCI/Docker reference: alpine:latest, ghcr.io/org/app:1.2, repo@sha256:…
  + all scan flags   --verify, --fail-on, --format, --rules-dir, --tags, --baseline, --max-size, …

Scans EVERY layer's files, not just the flattened final filesystem — so a secret that was COPYed in
one layer and deleted (RM) in a later one is still caught from the earlier layer where it persists.
The image config is scanned too: env vars, labels, and build-history RUN commands are prime secret
locations. The same file across layers is reported once (deduped by content fingerprint).

Public images need no credentials; private registries authenticate via your Docker login
(~/.docker/config.json / the default keychain). Nothing is written to disk — layers stream in memory.

Examples:
  prowl image alpine:latest
  prowl image ghcr.io/org/app:1.4 --fail-on high
  prowl image myregistry.io/team/api@sha256:abc… --verify --format json`

const bucketHelp = `prowl bucket <s3://bucket/prefix | gs://bucket/prefix> — scan a cloud storage prefix

  s3://bucket/prefix    an Amazon S3 bucket/prefix (downloaded with the AWS CLI)
  gs://bucket/prefix     a Google Cloud Storage bucket/prefix (downloaded with the gcloud CLI)
  + all scan flags       --verify, --fail-on, --format, --rules-dir, --tags, --max-size, …

The prefix is downloaded into a temp dir with the platform's own CLI (so your existing cloud
credentials, regions, and roles are reused — exactly as 'repo' reuses your git credentials), scanned,
and removed. The 'aws' or 'gcloud' CLI must be installed and authenticated. The bucket's own
.prowl.yaml is ignored, so its contents cannot suppress findings.

Examples:
  prowl bucket s3://my-logs/2026/ --fail-on high
  prowl bucket gs://my-backups/db/ --format json -o findings.json`

const domainHelp = `prowl domain <host> --authorized — scan a live site

  --authorized     REQUIRED: confirm you are authorized to scan this host
  --recon          deep sweep: subdomains (crt.sh) + wayback history
  --max-assets N   cap fetched assets (default 300)

Scans the host's HTML, inline state blobs (__NEXT_DATA__, __NUXT__, window.env, …),
and the JavaScript bundles + source-maps it references. No subdomain enumeration unless --recon.

Examples:
  prowl domain example.com --authorized
  prowl domain example.com --authorized --recon --format json`

const serveHelp = `prowl serve [--addr :8080] — run as a stateless HTTP scan worker

POST /scan and /scan/batch, GET /healthz and /metrics. One horizontal scaling unit (N replicas
behind a load balancer / k8s HPA).

Example:
  prowl serve --addr :8080`

const rulesHelp = `prowl rules <cmd> — manage detection rule templates (they live outside the binary)

  list     [DIR]                      rules grouped by category, with severity and tags
  show     <rule-id>                  one rule's detail: matchers, regex, severity, reference (built-in or template)
  test     <text|@file>               which rules fire on a sample (built-ins + templates; near-miss hints)
  search   <term>                     find rules by id / tag / description (built-ins + templates)
  validate [DIR]                      lint templates (parse / RE2 / fields); exit 1 on error
  stats    [DIR]                      counts by category / severity, and the top tags
  update   [--source SRC] [--check]   install/refresh from the templates repo (or a dir / git URL)
  export   -o FILE                    write the built-in taxonomy to an editable file

DIR defaults to ./rules. Imports are backward-compatible with gitleaks (.toml) & trufflehog (.yaml).

Examples:
  prowl rules list --tags ai
  prowl rules show stripe-secret-key
  prowl rules test 'key = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"'
  prowl rules update --check`

const configHelp = `prowl config validate [FILE] — lint a .prowl.yaml (default: ./.prowl.yaml)

Reports problems a plain load would silently swallow: unknown/typo'd keys (e.g. allowlsit:),
empty or match-everything custom-detector regexes, and unrecognized custom-rule categories.
Exit 0 = clean, 1 = problems found.

Example:
  prowl config validate
  prowl config validate ci/.prowl.yaml`

const verifiersHelp = `prowl verifiers <cmd> — manage live-credential verifiers (appsec-authored YAML)

  list     [DIR]   which providers, type ids, and endpoints are loaded
  validate [DIR]   parse + regex-compile check; exit 1 on error

DIR defaults to ./verifiers. Use them in a scan with --verify (or --verified-only).

Examples:
  prowl verifiers list
  prowl scan . --verify --verifiers ./verifiers`

// helpFor prints a command's detailed help, or the full top-level usage when name is empty/unknown.
func helpFor(name string) {
	for _, c := range commands {
		if c.name == name && c.detail != "" {
			fmt.Println(c.detail)
			return
		}
	}
	fmt.Print(usage)
}

// hasHelpFlag reports whether -h/--help appears in args.
func hasHelpFlag(args []string) bool {
	for _, a := range args {
		if a == "-h" || a == "--help" {
			return true
		}
	}
	return false
}

func commandNames() []string {
	out := make([]string, len(commands))
	for i, c := range commands {
		out[i] = c.name
	}
	return out
}

// dieUnknownCommand prints a "did you mean" suggestion and exits.
func dieUnknownCommand(cmd string) {
	fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
	if s := closest(cmd, commandNames()); s != "" {
		fmt.Fprintf(os.Stderr, "did you mean 'prowl %s'?\n", s)
	}
	fmt.Fprintln(os.Stderr, "run 'prowl help' for the list of commands")
	os.Exit(2)
}

// knownFlags is every flag the CLI accepts (common + command-specific), used to catch typos.
var knownFlags = map[string]bool{
	"--format": true, "--fail-on": true, "--fail-on-verified": true, "--exclude": true, "--taxonomy": true, "--rules": true,
	"--rules-only": true, "--rules-dir": true, "--tags": true, "--exclude-tags": true,
	"--rule-severity": true, "--verify": true, "--verified-only": true, "--verifiers": true,
	"--config": true, "--output": true, "-o": true, "--staged": true, "--history": true,
	"--since": true, "--baseline": true, "--write-baseline": true, "--max-size": true,
	"--workers": true, "--timeout": true, "--silence": true, "--silent": true, "-s": true,
	"--quiet": true, "-q": true, "--verbose": true, "-v": true, "--no-color": true,
	"--log-format": true, "--log-level": true, "--help": true, "-h": true,
	"--authorized": true, "--recon": true, "--max-assets": true, "--addr": true,
	"--max-concurrent": true, "--source": true, "--check": true, "--allow-unsigned": true,
	"--dedupe": true, "--no-dedupe": true,
	"--min-confidence": true, "--min-severity": true, "--disable": true, "--exclude-repo": true,
	"--branch": true, "--depth": true, "--concurrency": true, "--max-per-file": true,
	"--ml": true, "--ml-model": true, "--ml-url": true, "--ml-threshold": true,
	"--base-url": true, "--current-only": true, "--max-items": true, "--project": true, "--space": true, "--field": true,
}

func allFlagNames() []string {
	out := make([]string, 0, len(knownFlags))
	for f := range knownFlags {
		out = append(out, f)
	}
	return out
}

// dieUnknownFlag prints a suggestion for a mistyped flag and exits.
func dieUnknownFlag(flag string) {
	fmt.Fprintf(os.Stderr, "unknown flag %q\n", flag)
	if s := closest(flag, allFlagNames()); s != "" {
		fmt.Fprintf(os.Stderr, "did you mean '%s'?\n", s)
	}
	os.Exit(2)
}

// closest returns the nearest candidate within an edit-distance budget, or "".
func closest(in string, candidates []string) string {
	best, bestD := "", 1<<30
	for _, c := range candidates {
		if d := levenshtein(in, c); d < bestD {
			best, bestD = c, d
		}
	}
	if bestD <= 3 && bestD < len(in) { // close enough to be a typo, not a different word
		return best
	}
	return ""
}

func levenshtein(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min3(cur[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}

func min3(a, b, c int) int {
	if b < a {
		a = b
	}
	if c < a {
		a = c
	}
	return a
}

// checkUnknownFlags dies with a suggestion on any --flag / -x not in knownFlags (--flag=value ok).
func checkUnknownFlags(args []string) {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") || a == "-" {
			continue
		}
		if len(a) > 1 && a[1] >= '0' && a[1] <= '9' { // a negative-number value, not a flag (e.g. --workers -1)
			continue
		}
		name := a
		if i := strings.IndexByte(a, '='); i >= 0 {
			name = a[:i]
		}
		if !knownFlags[name] {
			dieUnknownFlag(name)
		}
	}
}
