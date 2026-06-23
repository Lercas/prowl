# Editor Integration (LSP)

`prowl lsp` runs Prowl as a **Language Server** over stdio. Editors that speak the [Language Server Protocol](https://microsoft.github.io/language-server-protocol/) connect to it and get **real-time secret diagnostics** — secrets are highlighted as you type, powered by the same detection engine as `prowl scan`.

```sh
prowl lsp
```

It reads JSON-RPC from **stdin** and writes to **stdout**, so you point your editor's LSP client at the `prowl` binary with the single argument `lsp` and a stdio transport.

## What it does

When you open or edit a document, Prowl scans the buffer's text and publishes diagnostics for anything that looks like a secret. Each diagnostic is placed on the exact range of the match and labelled with the detector type, confidence, and detection stage, e.g.:

```
possible secret: AWS Access Key (conf 0.95, L1)
```

Diagnostics carry `source: "prowl"` so you can filter Prowl's findings from other language servers in your editor.

### Severity mapping

Diagnostic severity is derived from the finding's category and confidence:

| Condition | LSP severity |
|-----------|--------------|
| High-impact categories (`pki`, `payment`, `db`, `cloud`, `vcs`, `ai`, `comms`, `messaging`, `ci`, `saas`, `observability`, `auth`) | Error (1) |
| `generic` category, or anything unrecognised | Warning (2) |
| Confidence `< 0.70` (unverified/generic) | Warning (2) |

So a confirmed cloud or database credential surfaces as an Error, while a low-confidence generic match surfaces as a Warning.

## Protocol support

The server implements a minimal but complete diagnostics loop. It speaks Content-Length-framed JSON-RPC 2.0 over stdio.

| Message | Direction | Behaviour |
|---------|-----------|-----------|
| `initialize` | request → response | Advertises `textDocumentSync: 1` (**full** document sync) and `serverInfo` (`name: prowl`). |
| `textDocument/didOpen` | notification | Scans the opened document, publishes diagnostics. |
| `textDocument/didChange` | notification | Re-scans the latest full document text, publishes diagnostics. |
| `textDocument/publishDiagnostics` | ← notification | Emitted by Prowl with the findings for a document URI. |
| `shutdown` | request → response | Replies with a null result. |
| `exit` | notification | Terminates the server. |

Because sync mode is **full**, the editor must send the entire document text on each change (the default for `textDocumentSync: 1`); Prowl scans the last full snapshot it receives. There is no incremental/range sync, no hover, no code actions, and no completion — this server's sole job is secret diagnostics.

Robustness notes: a single JSON-RPC frame is capped at 16 MiB, malformed frames (bad/oversized `Content-Length`) are skipped rather than dropping the connection, and a panic in any handler is recovered so the loop keeps serving.

## Wiring it into an editor

Prowl is a generic LSP server, so configure it the way your editor configures any custom language server: a **command** (`prowl`), its **arguments** (`["lsp"]`), and a **stdio** transport. Attach it to whatever file types you want scanned (or all of them).

### Neovim (built-in LSP)

```lua
vim.api.nvim_create_autocmd("FileType", {
  pattern = "*",
  callback = function(args)
    vim.lsp.start({
      name = "prowl",
      cmd = { "prowl", "lsp" },
      root_dir = vim.fn.getcwd(),
    }, { bufnr = args.buf })
  end,
})
```

### VS Code

There is no bundled extension; use a generic LSP client extension (or a thin custom extension) configured with:

```json
{
  "command": "prowl",
  "args": ["lsp"],
  "transport": "stdio"
}
```

### Helix (`languages.toml`)

```toml
[language-server.prowl]
command = "prowl"
args = ["lsp"]
```

Then add `prowl` to the `language-servers` list of the languages you want scanned.

### General checklist

- Ensure `prowl` is on the editor's `PATH` (or give an absolute path to the binary).
- Use **stdio** transport — Prowl does not listen on a socket.
- Attach the server to the file types/buffers you care about; it scans raw text and is language-agnostic.

Diagnostics update on open and on every change. To scan whole files, directories, or git history instead of a live buffer, use [Scanning Files](Scanning-Files.md).

## See also

- [Scanning Files](Scanning-Files.md)
- [Output Formats](Output-Formats.md)
- [Configuration](Configuration.md)
- [Server Mode](Server-Mode.md)
- [Home](README.md)
