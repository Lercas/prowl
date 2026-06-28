# MCP Server

`prowl mcp` runs Prowl as a **Model Context Protocol server over stdio**, so an AI agent — Claude Code, Claude Desktop, or any MCP client — can drive scans as tools. It speaks newline-delimited JSON-RPC on stdin/stdout; there is no port to open and no network listener. Each tool call runs a scan and returns the same JSON findings envelope the CLI produces.

```sh
prowl mcp
```

Where [Server Mode](Server-Mode.md) exposes an HTTP API for content you push at it, `prowl mcp` exposes the *commands* (scan a path, a domain, a mobile app, a repo) as agent-callable tools over a single stdio pipe.

## Registration

Register Prowl once with your MCP client and it stays available across sessions:

```bash
claude mcp add prowl -- prowl mcp
```

The `-- prowl mcp` after the name is the command the client launches and talks to over stdio. Any MCP-capable client works the same way — point it at `prowl mcp` as a stdio server.

The full agent-facing guide — flag reference, output shape, and a triage decision tree — lives in [`AGENTS.md`](https://github.com/Lercas/prowl/blob/main/AGENTS.md) at the repo root.

## Tools

Each tool runs the corresponding scan and returns the JSON findings envelope as text (`{"findings": [...], "truncated": bool, ...}`; see [Output Formats](Output-Formats.md)).

| Tool | Required args | Optional | Use for |
|------|---------------|----------|---------|
| `prowl_scan` | `path` | `verify`, `ml`, `show_secrets` | a local file or directory |
| `prowl_domain` | `target`, `authorized` | `recon`, `verify` | a domain's public web surface |
| `prowl_mobile` | `path` | `ml` | an Android `.apk` / iOS `.ipa` |
| `prowl_repo` | `url` | `verify` | a git repository |

The optional args map to the CLI flags of the same name: `verify` → [`--verify`](Live-Verification.md) (L3 live verification), `ml` → `--ml` (the [L2 ML filter](Data-Flywheel.md)), `show_secrets` → `--show-secrets` (raw values for authorized triage), `recon` → `--recon` (the [domain deep sweep](Domain-Scanning.md)).

## The `authorized` gate

`prowl_domain` **refuses to run unless `authorized: true` is set** in the tool call. This is the same hard consent gate as the CLI's `--authorized` flag — an explicit attestation that you are permitted to fetch the target's published pages and assets. There is no config or environment override; the agent must set it on every `prowl_domain` call. Set it only for a target you are authorized to test: your own asset, a bug-bounty scope, or an explicit engagement.

`prowl_scan`, `prowl_mobile`, and `prowl_repo` operate on artifacts you already hold (a local path or a git URL) and have no such gate.

## See also

- [Server Mode](Server-Mode.md) — `prowl serve`, the stateless HTTP scan API
- [Domain Scanning](Domain-Scanning.md) — the `--authorized` consent gate in depth
- [Mobile Scanning](Mobile-Scanning.md) — `prowl mobile`, the APK/IPA target
- [Live Verification](Live-Verification.md) — `--verify` and the blast-radius report
- [Data Flywheel](Data-Flywheel.md) — the `--ml` filter behind the `ml` arg
- [Output Formats](Output-Formats.md) — the JSON findings envelope each tool returns
- [Home](README.md)
