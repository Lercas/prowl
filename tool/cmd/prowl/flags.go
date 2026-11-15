package main

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/publicaudit"
	"github.com/Lercas/prowl/tool/internal/semantic"
)

type commandOptions struct {
	selftestProfile                                                                                                        string
	guardProtocol, agentHome                                                                                               string
	shellHistory                                                                                                           bool
	sub, branch, targetsFile, addr, baseURL, source                                                                        string
	depth, concurrency, maxAssets, maxConcurrent, maxItems, maxRuns, maxArtifacts, minRun, maxRetries                      int
	maxDownload                                                                                                            int64
	excludeRepos, projects, spaces, fields, targets, providers                                                             []string
	gists, authorized, recon, currentOnly, logsOnly, artifactsOnly, noStrings, check, allowUnsigned, active, passive, help bool
}

type flagSpec struct {
	names, commands    []string
	value, description string
	apply              func(*commonFlags, string) error
	commandValues      map[string][]string
}

func (f flagSpec) forCommand(command string) flagSpec {
	if values := f.commandValues[command]; values != nil {
		f.value = strings.Join(values, "|")
		apply := f.apply
		f.apply = func(c *commonFlags, value string) error {
			for _, allowed := range values {
				if value == allowed {
					return apply(c, value)
				}
			}
			return fmt.Errorf("must be one of %s", strings.Join(values, "|"))
		}
	}
	return f
}

func reportFormatFlag() flagSpec {
	f := enumFlag("--format", scanCommands+" index diff", "report format (compare/index/diff: pretty or json)", []string{"pretty", "json", "sarif", "defectdojo", "dojo"}, func(c *commonFlags) *string { return &c.format })
	f.commandValues = map[string][]string{"compare": {"pretty", "json"}, "index": {"pretty", "json"}, "diff": {"pretty", "json"}}
	return f
}

func (f flagSpec) applies(command string) bool {
	for _, name := range f.commands {
		if name == "*" || name == command {
			return true
		}
	}
	return false
}

func valueFlag(names, commands, value, description string, apply func(*commonFlags, string) error) flagSpec {
	return flagSpec{names: strings.Fields(names), commands: strings.Fields(commands), value: value, description: description, apply: apply}
}

func stringFlag(names, commands, value, description string, field func(*commonFlags) *string) flagSpec {
	return valueFlag(names, commands, value, description, func(c *commonFlags, value string) error {
		*field(c) = value
		return nil
	})
}

func boolFlag(names, commands, description string, field func(*commonFlags) *bool) flagSpec {
	return valueFlag(names, commands, "", description, func(c *commonFlags, value string) error {
		b, err := booleanValue(value)
		if err == nil {
			*field(c) = b
		}
		return err
	})
}

func listFlag(names, commands, description string, csv bool, field func(*commonFlags) *[]string) flagSpec {
	return valueFlag(names, commands, "VALUE", description+" (repeatable)", func(c *commonFlags, value string) error {
		values := []string{value}
		if csv {
			values = splitCSV(value)
		}
		*field(c) = append(*field(c), values...)
		return nil
	})
}

func intFlag(name, commands, description string, minimum int, field func(*commonFlags) *int) flagSpec {
	return valueFlag(name, commands, "N", description, func(c *commonFlags, value string) error {
		n, err := integerValue(value, minimum)
		if err == nil {
			*field(c) = n
		}
		return err
	})
}

func floatFlag(name, commands, description string, field func(*commonFlags) *float64) flagSpec {
	return valueFlag(name, commands, "F", description, func(c *commonFlags, value string) error {
		n, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 || n > 1 {
			return errors.New("expects a number in 0..1")
		}
		*field(c) = n
		if name == "--ml-threshold" {
			c.mlThresholdSet = true
		}
		return nil
	})
}

func durationFlag(name, commands, description string, field func(*commonFlags) *time.Duration) flagSpec {
	return valueFlag(name, commands, "DUR", description, func(c *commonFlags, value string) error {
		n, err := time.ParseDuration(value)
		if err != nil || n <= 0 {
			return errors.New("expects a positive Go duration (e.g. 30s, 5m)")
		}
		*field(c) = n
		return nil
	})
}

func sizeFlag(name, commands, description string, field func(*commonFlags) *int64) flagSpec {
	return valueFlag(name, commands, "BYTES", description, func(c *commonFlags, value string) error {
		n, err := parseByteSize(value)
		if err != nil || n <= 0 {
			return errors.New("expects a positive size (e.g. 10485760, 10MB, 4M)")
		}
		*field(c) = n
		return nil
	})
}

func enumFlag(name, commands, description string, allowed []string, field func(*commonFlags) *string) flagSpec {
	return valueFlag(name, commands, strings.Join(allowed, "|"), description, func(c *commonFlags, value string) error {
		for _, option := range allowed {
			if value == option {
				*field(c) = value
				return nil
			}
		}
		return fmt.Errorf("must be one of %s", strings.Join(allowed, "|"))
	})
}

const scanCommands = "scan compare repo org cicd image mobile bucket domain jira confluence agents"
const indexedCommands = "scan repo org cicd image mobile bucket domain jira confluence agents"

const detectorCommands = scanCommands + " serve doctor"

const ocrCommands = "scan repo org"

var commandSubcommands = map[string][]string{
	"rules":     {"list", "show", "test", "search", "validate", "stats", "update", "manifest", "export"},
	"verifiers": {"list", "validate", "update", "manifest"},
	"config":    {"validate"},
	"identity":  {"init"},
}

var cliFlags = []flagSpec{
	enumFlag("--profile", "selftest", "offline self-test profile (default all)", []string{"all", "web", "mobile", "enterprise"}, func(c *commonFlags) *string { return &c.cmd.selftestProfile }),
	boolFlag("--bundled", detectorCommands+" lsp version", "use the release's bundled rules/verifiers, keeping the configuration and identity key", func(c *commonFlags) *bool { return &c.bundled }),
	enumFlag("--protocol", "guard", "hook protocol (default raw)", []string{"raw", "claude", "cursor-prompt", "cursor-tool"}, func(c *commonFlags) *string { return &c.cmd.guardProtocol }),
	stringFlag("--agent-home", "agents", "DIR", "explicitly scan user-level agent configs and transcripts", func(c *commonFlags) *string { return &c.cmd.agentHome }),
	boolFlag("--shell-history", "agents", "include shell history from the explicit --agent-home", func(c *commonFlags) *bool { return &c.cmd.shellHistory }),
	boolFlag("--help -h", "*", "show this command's flags and examples", func(c *commonFlags) *bool { return &c.cmd.help }),
	stringFlag("--index", indexedCommands+" index diff", "DIR", "local private secret index (opt-in)", func(c *commonFlags) *string { return &c.indexDir }),
	stringFlag("--scope", indexedCommands+" index diff", "NAME", "stable scan scope name for the index", func(c *commonFlags) *string { return &c.indexScope }),
	reportFormatFlag(),
	enumFlag("--fail-on", indexedCommands, "exit 1 at this severity or above", []string{"info", "low", "medium", "high", "critical"}, func(c *commonFlags) *string { return &c.failOn }),
	// In 1.5 every incomplete scan fails closed; retain the released flag without allowing opt-out.
	valueFlag("--strict", scanCommands, "", "1.4 compatibility: an incomplete scan always exits 2, including --strict=false", func(_ *commonFlags, value string) error {
		_, err := booleanValue(value)
		return err
	}),
	boolFlag("--ci", indexedCommands, "CI gate: exit 1 on high/critical; an explicit --fail-on wins; an incomplete scan exits 2", func(c *commonFlags) *bool { return &c.ci }),
	boolFlag("--fail-on-verified", indexedCommands, "gate only on provider-confirmed live findings; requires --verify", func(c *commonFlags) *bool { return &c.failOnVerified }),
	listFlag("--exclude", scanCommands, "skip paths containing the substring", false, func(c *commonFlags) *[]string { return &c.exclude }),
	stringFlag("--taxonomy", detectorCommands, "FILE", "override the embedded taxonomy", func(c *commonFlags) *string { return &c.taxonomy }),
	listFlag("--rules", detectorCommands+" rules.list rules.show rules.test rules.search rules.validate rules.stats", "import external rules", false, func(c *commonFlags) *[]string { return &c.rules }),
	boolFlag("--rules-only", detectorCommands, "use only explicit external rules", func(c *commonFlags) *bool { return &c.rulesOnly }),
	listFlag("--rules-dir", detectorCommands, "load template rules from a directory", false, func(c *commonFlags) *[]string { return &c.rulesDir }),
	stringFlag("--tags", detectorCommands+" rules.list", "CSV", "include templates with these tags", func(c *commonFlags) *string { return &c.tags }),
	stringFlag("--exclude-tags", detectorCommands, "CSV", "exclude templates with these tags", func(c *commonFlags) *string { return &c.excludeTags }),
	valueFlag("--rule-severity", detectorCommands+" rules.list", "CSV", "include template severities", func(c *commonFlags, v string) error {
		for _, s := range splitCSV(v) {
			if _, ok := model.SeverityOrder[s]; !ok {
				return errors.New("entries must be info|low|medium|high|critical")
			}
		}
		c.ruleSeverity = v
		return nil
	}),
	boolFlag("--verify", indexedCommands, "validate supported credentials against the provider", func(c *commonFlags) *bool { return &c.verify }),
	boolFlag("--verify-all", indexedCommands, "verify every accepted L1 candidate before ML (implies --verify)", func(c *commonFlags) *bool { return &c.verifyAll }),
	boolFlag("--verified-only", indexedCommands, "report only provider-confirmed live findings (implies --verify)", func(c *commonFlags) *bool { return &c.verifiedOnly }),
	boolFlag("--show-secrets", scanCommands, "emit full values for authorized triage; default masked", func(c *commonFlags) *bool { return &c.showSecrets }),
	listFlag("--verifiers", indexedCommands+" doctor", "load provider verifiers from a directory", false, func(c *commonFlags) *[]string { return &c.verifiers }),
	stringFlag("--config", detectorCommands, "FILE", "load trusted scanner configuration", func(c *commonFlags) *string { return &c.config }),
	stringFlag("--output -o", scanCommands+" rules.export hermes-audit index diff identity.init", "FILE", "write the report to this file", func(c *commonFlags) *string { return &c.output }),
	stringFlag("--identity-key-file", scanCommands, "FILE", "HMAC key for secret and location identities in the report", func(c *commonFlags) *string { return &c.identityKeyFile }),
	stringFlag("--stdin-name", "scan", "NAME", "logical name for stdin, used to pick the format; the file is not opened", func(c *commonFlags) *string { return &c.stdinName }),
	boolFlag("--staged", "scan compare repo", "scan the Git index", func(c *commonFlags) *bool { return &c.staged }),
	boolFlag("--git-timeline", "scan repo org", "build a Git observation timeline (implies --history)", func(c *commonFlags) *bool { return &c.gitTimeline }),
	boolFlag("--history", "scan compare repo org", "scan Git blob history", func(c *commonFlags) *bool { return &c.history }),
	stringFlag("--since", "scan compare repo", "REV", "scan Git changes since this revision", func(c *commonFlags) *string { return &c.since }),
	stringFlag("--baseline", indexedCommands, "FILE", "suppress findings recorded in this baseline", func(c *commonFlags) *string { return &c.baseline }),
	stringFlag("--write-baseline", indexedCommands, "FILE", "write a baseline from complete scan results", func(c *commonFlags) *string { return &c.writeBaseline }),
	sizeFlag("--max-size", scanCommands+" guard", "maximum input/member size (scan: 10MB; guard: 1MiB, max 8MiB)", func(c *commonFlags) *int64 { return &c.maxSize }),
	intFlag("--workers", scanCommands, "scan concurrency; 0 selects the runtime default", 0, func(c *commonFlags) *int { return &c.workers }),
	durationFlag("--timeout", scanCommands+" serve hermes-audit guard", "total scan/request timeout (guard: default 3s, max 30s)", func(c *commonFlags) *time.Duration { return &c.timeout }),
	boolFlag("--silence --silent -s", detectorCommands, "suppress human output and logging", func(c *commonFlags) *bool { return &c.silence }),
	boolFlag("--quiet -q", detectorCommands, "log errors only", func(c *commonFlags) *bool { return &c.quiet }),
	boolFlag("--verbose -v", detectorCommands, "enable debug logging", func(c *commonFlags) *bool { return &c.verbose }),
	boolFlag("--no-color", detectorCommands, "disable terminal colors", func(c *commonFlags) *bool { return &c.noColor }),
	enumFlag("--log-format", detectorCommands, "logging format", []string{"console", "json"}, func(c *commonFlags) *string { return &c.logFormat }),
	valueFlag("--log-level", detectorCommands, "LEVEL", "debug|info|warn|error (case-insensitive)", func(c *commonFlags, v string) error {
		var level slog.Level
		if err := level.UnmarshalText([]byte(v)); err != nil {
			return errors.New("must be debug|info|warn|error")
		}
		c.logLevel = v
		return nil
	}),
	boolFlag("--dedupe", scanCommands, "collapse repeated findings (default true)", func(c *commonFlags) *bool { return &c.dedupe }),
	valueFlag("--no-dedupe", scanCommands, "", "retain repeated findings", func(c *commonFlags, v string) error {
		b, err := booleanValue(v)
		if err == nil {
			c.dedupe = !b
		}
		return err
	}),
	floatFlag("--min-confidence", scanCommands, "minimum reported confidence", func(c *commonFlags) *float64 { return &c.minConfidence }),
	enumFlag("--min-severity", scanCommands, "minimum reported severity", []string{"info", "low", "medium", "high", "critical"}, func(c *commonFlags) *string { return &c.minSeverity }),
	stringFlag("--disable", scanCommands, "CSV", "disable listed detector types", func(c *commonFlags) *string { return &c.disable }),
	intFlag("--max-per-file", indexedCommands, "generic findings per file; 0 disables the cap (default 30)", 0, func(c *commonFlags) *int { return &c.maxPerFile }),
	boolFlag("--ml", scanCommands+" selftest", "run the portable in-process L2 model", func(c *commonFlags) *bool { return &c.mlEmbed }),
	boolFlag("--semantic", indexedCommands+" compare", "find source-backed candidates with an opt-in model (loopback by default)", func(c *commonFlags) *bool { return &c.semantic }),
	stringFlag("--semantic-url", indexedCommands+" compare", "URL", "model endpoint (implies semantic)", func(c *commonFlags) *string { return &c.semanticURL }),
	stringFlag("--semantic-model", indexedCommands+" compare", "MODEL", "model name (implies semantic)", func(c *commonFlags) *string { return &c.semanticModel }),
	boolFlag("--semantic-allow-remote", indexedCommands+" compare", "allow source text to be sent to the model over HTTPS", func(c *commonFlags) *bool { return &c.semanticAllowRemote }),
	boolFlag("--reconstruct", scanCommands, "reconstruct bounded static JS/TS strings without executing code", func(c *commonFlags) *bool { return &c.reconstruct }),
	stringFlag("--ml-model", scanCommands, "FILE", "load a compatible external model (implies ML)", func(c *commonFlags) *string { return &c.mlModel }),
	stringFlag("--ml-url", indexedCommands, "URL", "score candidates through an external sidecar", func(c *commonFlags) *string { return &c.mlURL }),
	floatFlag("--ml-threshold", scanCommands, "L2 suppression threshold (default 0.3)", func(c *commonFlags) *float64 { return &c.mlThreshold }),
	boolFlag("--ocr", ocrCommands, "OCR local images and image-only PDF pages", func(c *commonFlags) *bool { return &c.ocrEnabled }),
	stringFlag("--ocr-url", ocrCommands, "URL", "OpenAI-compatible OCR endpoint (implies OCR)", func(c *commonFlags) *string { return &c.ocrURL }),
	stringFlag("--ocr-model", ocrCommands, "MODEL", "OCR model identifier (implies OCR)", func(c *commonFlags) *string { return &c.ocrModel }),
	boolFlag("--ocr-allow-remote", ocrCommands, "allow documents to leave this machine for a remote HTTPS OCR endpoint", func(c *commonFlags) *bool { return &c.ocrAllowRemote }),
	boolFlag("--ocr-all-pages", ocrCommands, "OCR every PDF page", func(c *commonFlags) *bool { return &c.ocrAllPages }),
	intFlag("--ocr-max-pages", ocrCommands, "maximum PDF pages to OCR (default 20)", 1, func(c *commonFlags) *int { return &c.ocrMaxPages }),
	durationFlag("--ocr-timeout", ocrCommands, "per-page OCR timeout (default 2m)", func(c *commonFlags) *time.Duration { return &c.ocrTimeout }),
	stringFlag("--branch", "repo cicd", "REF", "select the repository/CI branch", func(c *commonFlags) *string { return &c.cmd.branch }),
	intFlag("--depth", "repo", "clone depth (at least 1)", 1, func(c *commonFlags) *int { return &c.cmd.depth }),
	intFlag("--concurrency", "org hermes-audit", "source concurrency", 1, func(c *commonFlags) *int { return &c.cmd.concurrency }),
	listFlag("--exclude-repo", "org", "skip matching repository URL substrings", true, func(c *commonFlags) *[]string { return &c.cmd.excludeRepos }),
	boolFlag("--gists", "org", "scan a GitHub user's public gists", func(c *commonFlags) *bool { return &c.cmd.gists }),
	boolFlag("--audit-public", "domain mobile", "read-only public-key permission audit; requires --authorized", func(c *commonFlags) *bool { return &c.auditPublic }),
	listFlag("--audit-firestore-collection", "domain mobile", "explicit Firestore collection path; requires --audit-public; up to 8", false, func(c *commonFlags) *[]string { return &c.auditCollections }),
	listFlag("--audit-supabase-table", "domain mobile", "explicit public-schema Supabase table name; requires --audit-public; up to 8", false, func(c *commonFlags) *[]string { return &c.auditTables }),
	boolFlag("--authorized", "domain mobile hermes-audit", "attest that all targets are in your authorized scope", func(c *commonFlags) *bool { return &c.cmd.authorized }),
	boolFlag("--recon", "domain", "enumerate public subdomains and historical assets", func(c *commonFlags) *bool { return &c.cmd.recon }),
	intFlag("--max-assets", "domain", "maximum web assets (default 300)", 1, func(c *commonFlags) *int { return &c.cmd.maxAssets }),
	stringFlag("--targets", "domain hermes-audit", "FILE", "read a newline-delimited target inventory", func(c *commonFlags) *string { return &c.cmd.targetsFile }),
	stringFlag("--addr", "serve", "HOST:PORT", "listen address (default 127.0.0.1:8080)", func(c *commonFlags) *string { return &c.cmd.addr }),
	intFlag("--max-concurrent", "serve", "maximum concurrent requests; 0 selects the default", 0, func(c *commonFlags) *int { return &c.cmd.maxConcurrent }),
	enumFlag("--image-input", "image", "force image source kind", []string{"ref", "tar", "oci-dir", "stdin"}, func(c *commonFlags) *string { return &c.imageInput }),
	stringFlag("--base-url", "jira confluence", "URL", "Atlassian deployment base URL", func(c *commonFlags) *string { return &c.cmd.baseURL }),
	boolFlag("--current-only", "jira confluence", "scan only the latest issue/page version", func(c *commonFlags) *bool { return &c.cmd.currentOnly }),
	listFlag("--project", "jira", "include Jira projects (comma-separated)", true, func(c *commonFlags) *[]string { return &c.cmd.projects }),
	listFlag("--space", "confluence", "include Confluence spaces (comma-separated)", true, func(c *commonFlags) *[]string { return &c.cmd.spaces }),
	listFlag("--field", "jira", "include additional Jira fields (comma-separated)", true, func(c *commonFlags) *[]string { return &c.cmd.fields }),
	intFlag("--max-items", "jira confluence", "maximum issues/pages", 1, func(c *commonFlags) *int { return &c.cmd.maxItems }),
	intFlag("--max-runs", "cicd", "maximum CI runs (default 20)", 1, func(c *commonFlags) *int { return &c.cmd.maxRuns }),
	intFlag("--max-artifacts", "cicd", "maximum CI artifacts (default 100)", 1, func(c *commonFlags) *int { return &c.cmd.maxArtifacts }),
	sizeFlag("--max-download", "cicd", "maximum CI download size (default 100MB)", func(c *commonFlags) *int64 { return &c.cmd.maxDownload }),
	boolFlag("--logs-only", "cicd", "scan CI logs only", func(c *commonFlags) *bool { return &c.cmd.logsOnly }),
	boolFlag("--artifacts-only", "cicd", "scan CI artifacts only", func(c *commonFlags) *bool { return &c.cmd.artifactsOnly }),
	boolFlag("--no-strings", "mobile", "skip printable strings in mobile binaries", func(c *commonFlags) *bool { return &c.cmd.noStrings }),
	intFlag("--min-run", "mobile", "minimum printable string length", 1, func(c *commonFlags) *int { return &c.cmd.minRun }),
	stringFlag("--source", "rules.update verifiers.update", "SOURCE", "template source directory or git URL", func(c *commonFlags) *string { return &c.cmd.source }),
	boolFlag("--check", "rules.update verifiers.update", "check availability without installing", func(c *commonFlags) *bool { return &c.cmd.check }),
	boolFlag("--allow-unsigned", "rules.update verifiers.update verifiers.list verifiers.validate", "explicitly permit an unsigned template set", func(c *commonFlags) *bool { return &c.cmd.allowUnsigned }),
	listFlag("--target", "hermes-audit", "literal authorized IP or IP:port (comma-separated)", true, func(c *commonFlags) *[]string { return &c.cmd.targets }),
	listFlag("--provider", "hermes-audit", "passive inventory providers (comma-separated)", true, func(c *commonFlags) *[]string { return &c.cmd.providers }),
	intFlag("--max-retries", "hermes-audit", "bounded retries, 0..5 (default 2)", 0, func(c *commonFlags) *int { return &c.cmd.maxRetries }),
	boolFlag("--active", "hermes-audit", "probe bounded dashboard assets (default true)", func(c *commonFlags) *bool { return &c.cmd.active }),
	boolFlag("--passive", "hermes-audit", "query exact-IP passive inventory (default true)", func(c *commonFlags) *bool { return &c.cmd.passive }),
}

func integerValue(value string, minimum int) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || n < minimum {
		return 0, fmt.Errorf("expects an integer >= %d", minimum)
	}
	return n, nil
}

func booleanValue(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "t", "true", "y", "yes", "on":
		return true, nil
	case "0", "f", "false", "n", "no", "off":
		return false, nil
	default:
		return false, errors.New("expects true|false|yes|no|on|off|1|0")
	}
}

type commandHelpRequest struct{ command string }

func (e *commandHelpRequest) Error() string { return "help requested for " + e.command }

func commandParseError(err error) int {
	var help *commandHelpRequest
	if errors.As(err, &help) {
		helpFor(help.command)
		return 0
	}
	fmt.Fprintln(os.Stderr, err)
	return 2
}

func parseCommand(command string, args []string) (commonFlags, []string, error) {
	c := commonFlags{coverage: model.NewCoverage(), format: "pretty", maxSize: 10 << 20, dedupe: true, maxPerFile: 30, mlThreshold: .3, ocrMaxPages: 20, ocrTimeout: 2 * time.Minute}
	c.cmd = commandOptions{maxAssets: 300, addr: "127.0.0.1:8080", maxRuns: 20, maxArtifacts: 100, maxDownload: 100 << 20, minRun: minRunDefault}
	if command == "guard" {
		c.maxSize = 1 << 20
		c.timeout = 3 * time.Second
		c.cmd.guardProtocol = "raw"
	}
	if command == "hermes-audit" {
		c.timeout = 12 * time.Second
		c.cmd.maxRetries = 2
		c.cmd.concurrency = 2
		c.cmd.active = true
		c.cmd.passive = true
	}
	if command == "rules" || command == "verifiers" || command == "config" || command == "identity" {
		c.cmd.sub = "list"
		if command == "config" {
			c.cmd.sub = "validate"
		}
		if command == "identity" {
			c.cmd.sub = "init"
		}
		if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
			c.cmd.sub, args = args[0], args[1:]
		}
		command += "." + c.cmd.sub
		parent, _, _ := strings.Cut(command, ".")
		valid := false
		for _, sub := range commandSubcommands[parent] {
			valid = valid || sub == c.cmd.sub
		}
		if !valid {
			return c, nil, fmt.Errorf("unknown %s subcommand %q", parent, c.cmd.sub)
		}
	}
	var rest []string
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		token := args[i]
		if token == "--" {
			rest = append(rest, args[i+1:]...)
			break
		}
		if token == "-" || !strings.HasPrefix(token, "-") {
			rest = append(rest, token)
			continue
		}
		name, value, inline := strings.Cut(token, "=")
		var selected *flagSpec
		known := false
		for j := range cliFlags {
			for _, alias := range cliFlags[j].names {
				if alias == name {
					known = true
					if cliFlags[j].applies(command) {
						selected = &cliFlags[j]
					}
					break
				}
			}
		}
		if selected != nil {
			effective := selected.forCommand(command)
			selected = &effective
		}
		if selected == nil {
			if known {
				return c, nil, fmt.Errorf("flag %q does not apply to command %q", name, strings.ReplaceAll(command, ".", " "))
			}
			message := fmt.Sprintf("unknown flag %q", name)
			if suggestion := closest(name, commandFlagNames(command)); suggestion != "" {
				message += fmt.Sprintf("; did you mean '%s'?", suggestion)
			}
			return c, nil, errors.New(message)
		}
		if selected.value != "" {
			if !inline {
				i++
				if i >= len(args) || (strings.HasPrefix(args[i], "-") && args[i] != "-" && (len(args[i]) < 2 || args[i][1] < '0' || args[i][1] > '9')) {
					return c, nil, fmt.Errorf("flag %q expects a value (use %s=VALUE for values starting with --)", name, name)
				}
				value = args[i]
			}
			if value == "" {
				return c, nil, fmt.Errorf("flag %q expects a non-empty value", name)
			}
		} else if !inline {
			value = "true"
		}
		if err := selected.apply(&c, value); err != nil {
			return c, nil, fmt.Errorf("%s %w", name, err)
		}
		seen[selected.names[0]] = true
	}
	if c.cmd.help {
		return c, nil, &commandHelpRequest{command}
	}
	c.explicitFlags = seen
	if c.ci && !seen["--fail-on"] {
		c.failOn = "high"
	}
	if command == "guard" && (c.maxSize > 8<<20 || c.timeout <= 0 || c.timeout > 30*time.Second) {
		return c, nil, errors.New("guard: size is at most 8 MiB; timeout must be positive and at most 30s")
	}
	if command == "agents" && c.cmd.shellHistory && c.cmd.agentHome == "" {
		return c, nil, errors.New("--shell-history requires an explicit --agent-home DIR")
	}
	if command == "compare" && seen["--ml"] && !c.mlEmbed {
		return c, nil, errors.New("compare requires local L2; --ml=false is not supported")
	}
	if c.gitTimeline {
		c.history = true
	}
	if c.verifiedOnly || c.verifyAll {
		c.verify = true
	}
	if len(c.auditCollections) > 0 && !c.auditPublic {
		return c, nil, errors.New("--audit-firestore-collection requires --audit-public")
	}
	if len(c.auditTables) > 0 && !c.auditPublic {
		return c, nil, errors.New("--audit-supabase-table requires --audit-public")
	}
	if c.auditPublic {
		if !c.cmd.authorized {
			return c, nil, errors.New("--audit-public requires --authorized")
		}
		collections, err := publicaudit.ValidateCollections(c.auditCollections)
		if err != nil {
			return c, nil, err
		}
		c.auditCollections = collections
		tables, err := publicaudit.ValidateTables(c.auditTables)
		if err != nil {
			return c, nil, err
		}
		c.auditTables = tables
		if c.verify || c.failOnVerified {
			return c, nil, errors.New("--audit-public cannot be combined with verification flags")
		}
	}
	if c.semantic || seen["--semantic-url"] || seen["--semantic-model"] || c.semanticAllowRemote {
		c.semantic = true
		if c.semanticURL == "" {
			c.semanticURL = os.Getenv("PROWL_SEMANTIC_URL")
		}
		if c.semanticModel == "" {
			c.semanticModel = os.Getenv("PROWL_SEMANTIC_MODEL")
		}
		var err error
		c.semanticEngine, err = semantic.New(semantic.Config{URL: c.semanticURL, Model: c.semanticModel, APIKey: os.Getenv("PROWL_SEMANTIC_API_KEY"), AllowRemote: c.semanticAllowRemote})
		if err != nil {
			return c, nil, fmt.Errorf("semantic setup: %w", err)
		}
	}
	if err := validateTemplateSelection(c); err != nil {
		return c, nil, err
	}
	c.mlURL = strings.TrimRight(c.mlURL, "/")
	c.ocrURL = strings.TrimRight(c.ocrURL, "/")
	if c.ocrAllowRemote || c.ocrAllPages || seen["--ocr-url"] || seen["--ocr-model"] || seen["--ocr-max-pages"] || seen["--ocr-timeout"] {
		c.ocrEnabled = true
	}
	if command == "hermes-audit" && c.cmd.maxRetries > 5 {
		return c, nil, errors.New("--max-retries must be 0..5")
	}
	if c.cmd.logsOnly && c.cmd.artifactsOnly {
		return c, nil, errors.New("--logs-only and --artifacts-only are mutually exclusive")
	}
	if command == "index" || command == "diff" {
		if c.format != "pretty" && c.format != "json" {
			return c, nil, errors.New("index/diff supports --format pretty|json")
		}
		if c.indexDir == "" {
			return c, nil, errors.New("--index DIR is required")
		}
	} else if c.indexDir != "" && strings.TrimSpace(c.indexScope) == "" {
		return c, nil, errors.New("--index requires an explicit --scope NAME")
	} else if c.indexScope != "" && c.indexDir == "" {
		return c, nil, errors.New("--scope requires --index DIR")
	}
	if command == "domain" && c.cmd.targetsFile != "" && len(rest) > 0 {
		return c, nil, errors.New("domain accepts a target or --targets, not both")
	}
	switch command {
	case "serve", "doctor", "mcp", "lsp", "detectors", "version", "guard":
		if len(rest) > 0 {
			return c, nil, fmt.Errorf("%s does not accept positional arguments", command)
		}
	case "repo", "org", "cicd", "bucket", "domain", "mobile", "jira", "confluence", "config.validate":
		if len(rest) > 1 {
			return c, nil, fmt.Errorf("%s accepts at most one target", command)
		}
	}
	if c.indexDir != "" && command != "index" && command != "diff" {
		c.indexEvidence = &indexEvidence{}
	}
	for _, scanCommand := range strings.Fields(scanCommands) {
		if command == scanCommand {
			var err error
			c.identityKey, err = loadIdentityKey(c.identityKeyFile)
			if err != nil {
				return c, nil, fmt.Errorf("identity key: %w", err)
			}
			c.coverage.SetIdentityScope(c.identityKey)
			c.coverage.RegisterScope("command", command, map[string]any{
				"targets": rest, "command_options": fmt.Sprintf("%#v", c.cmd), "stdin_name": c.stdinName,
				"history": c.history, "staged": c.staged, "since": c.since, "git_timeline": c.gitTimeline,
			})
			break
		}
	}
	return c, rest, nil
}

func commandFlagNames(command string) []string {
	var names []string
	for _, flag := range cliFlags {
		if flag.applies(command) {
			names = append(names, flag.names...)
		}
	}
	sort.Strings(names)
	return names
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

type commonFlags struct {
	coverage                                 *model.Coverage
	identityKeyFile                          string
	identityKey                              []byte
	verifyAll                                bool
	indexDir, indexScope                     string
	indexEvidence                            *indexEvidence
	indexCoverageComplete                    func() bool // optional source-specific completion evidence (e.g. OCR)
	cmd                                      commandOptions
	explicitFlags                            map[string]bool // immutable after parsing; explicit defaults override configuration
	format, failOn, taxonomy, config, output string
	since, baseline, writeBaseline           string
	logFormat, logLevel                      string
	stdinName                                string
	staged, history, gitTimeline             bool
	ci                                       bool
	silence, quiet, verbose, noColor         bool
	bundled                                  bool
	rulesOnly                                bool
	noAutoPolicy                             bool // agents: only explicit rule and suppression inputs
	noAutoConfig                             bool // repo/org: don't honor the scanned tree's own .prowl.yaml
	dedupe                                   bool // collapse the same secret found repeatedly in one file (default on)
	maxPerFile                               int  // cap generic findings per file (data-file guard; 0 = off)
	mlEmbed                                  bool // run the L2 model in-process (embedded), no sidecar
	semantic                                 bool
	semanticURL, semanticModel               string
	semanticAllowRemote                      bool
	semanticEngine                           *semantic.Engine
	reconstruct                              bool
	mlModel                                  string            // load the in-process model from this file (implies --ml)
	mlURL                                    string            // ML sidecar URL for the L2 secret/not-secret stage (off if empty)
	mlThreshold                              float64           // drop a non-checksum finding the ML scores below this
	mlThresholdSet                           bool              // user passed --ml-threshold (so config must not override it)
	mlPrepared                               *mlscore.Embedded // immutable model snapshot from early preflight
	mlPreparedPath                           string            // selector that produced the snapshot
	minConfidence                            float64           // report-time: drop findings below this confidence (0 = off)
	minSeverity                              string            // report-time: drop findings below this severity (incl. built-ins)
	disable                                  string            // report-time: comma-separated detector types to drop
	rules                                    []string
	rulesDir                                 []string
	tags, excludeTags, ruleSeverity          string
	auditCollections                         []string
	auditTables                              []string
	auditPublic                              bool
	verify, verifiedOnly                     bool
	showSecrets                              bool // --show-secrets: emit the full unredacted value
	failOnVerified                           bool // gate (exit 1) only on a provider-confirmed-LIVE secret
	verifiers                                []string
	verifyTimeout                            time.Duration
	exclude                                  []string
	maxSize                                  int64
	workers                                  int
	timeout                                  time.Duration
	imageInput                               string // force the image source kind: ref|tar|oci-dir|stdin (empty = auto)
	ocrEnabled                               bool
	ocrURL, ocrModel                         string
	ocrAllowRemote, ocrAllPages              bool
	ocrMaxPages                              int
	ocrTimeout                               time.Duration
}

// parseByteSize parses a byte size: a plain integer, or an integer with a KB/MB/GB (or K/M/G, optional
// trailing B) base-1024 suffix, case-insensitive. It rejects trailing garbage (fmt.Sscan would
// partial-parse "10MB" to 10 bytes, skipping every file and exiting 0).
func parseByteSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	mult := int64(1)
	for _, u := range []struct { // longest suffix first so "KB" wins over a trailing "B"
		suf string
		m   int64
	}{{"KB", 1 << 10}, {"MB", 1 << 20}, {"GB", 1 << 30}, {"K", 1 << 10}, {"M", 1 << 20}, {"G", 1 << 30}, {"B", 1}} {
		if len(s) >= len(u.suf) && strings.EqualFold(s[len(s)-len(u.suf):], u.suf) {
			mult, s = u.m, strings.TrimSpace(s[:len(s)-len(u.suf)])
			break
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	if n < 0 || (mult > 1 && n > math.MaxInt64/mult) {
		return 0, fmt.Errorf("size out of range")
	}
	return n * mult, nil
}
