// Command prowl drives the secret scanner CLI.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/Lercas/prowl/tool/internal/lsp"
	"github.com/Lercas/prowl/tool/internal/safehttp"
)

// version is the binary version, stamped at release via -ldflags; "dev" for a plain go build.
var version = "dev"

func main() { os.Exit(runCLI(os.Args[1:])) }

func runCLI(args []string) int {
	args = normalizeScanArgs(args)
	// Block outbound connections to private/loopback IPs (SSRF guard) by default; opt out explicitly.
	safehttp.AllowPrivate.Store(os.Getenv("PROWL_ALLOW_PRIVATE_IPS") != "")
	cmd := args[0]
	if cmd == "version" || cmd == "--version" || cmd == "-V" {
		c, _, err := parseCommand("version", args[1:])
		if err != nil {
			return commandParseError(err)
		}
		return printVersions(c.bundled)
	}
	if cmd == "help" || cmd == "-h" || cmd == "--help" {
		topic := ""
		if len(args) > 1 {
			topic = args[1]
		}
		helpFor(topic)
		return 0
	}
	switch cmd {
	case "guard":
		return cmdGuard(args[1:])
	case "correlate":
		return cmdCorrelate(args[1:])
	case "remediation-check":
		return cmdRemediation(args[1:])
	case "identity":
		return cmdIdentity(args[1:])
	case "agents":
		return cmdAgents(args[1:])
	case "scan":
		return cmdScan(args[1:])
	case "compare":
		return cmdCompare(args[1:])
	case "index", "diff":
		return cmdIndex(cmd, args[1:])
	case "repo":
		return cmdRepo(args[1:])
	case "org":
		return cmdOrg(args[1:])
	case "cicd":
		return cmdCICD(args[1:])
	case "image":
		return cmdImage(args[1:])
	case "mobile":
		return cmdMobile(args[1:])
	case "bucket":
		return cmdBucket(args[1:])
	case "domain":
		return cmdDomain(args[1:])
	case "hermes-audit":
		return cmdHermesAudit(args[1:])
	case "jira":
		return cmdJira(args[1:])
	case "confluence":
		return cmdConfluence(args[1:])
	case "serve":
		return cmdServe(args[1:])
	case "config":
		return cmdConfig(args[1:])
	case "selftest":
		return cmdSelftest(args[1:])
	case "doctor":
		return cmdDoctor(args[1:])
	case "detectors":
		if _, _, err := parseCommand("detectors", args[1:]); err != nil {
			return commandParseError(err)
		}
		return cmdDetectors()
	case "rules":
		return cmdRules(args[1:])
	case "verifiers":
		return cmdVerifiers(args[1:])
	case "lsp":
		c, _, err := parseCommand("lsp", args[1:])
		if err != nil {
			return commandParseError(err)
		}
		if err := lsp.ServeWithBundled(c.bundled); err != nil {
			if errors.Is(err, lsp.ErrExitWithoutShutdown) {
				return 1
			}
			fmt.Fprintln(os.Stderr, "lsp error:", err)
			return 2
		}
	case "mcp":
		return cmdMCP(args[1:])
	case "init":
		return cmdInit(args[1:])
	case "completion":
		return cmdCompletion(args[1:])
	default:
		fmt.Fprintln(os.Stderr, unknownCommandMessage(cmd))
		return 2
	}
	return 0
}
