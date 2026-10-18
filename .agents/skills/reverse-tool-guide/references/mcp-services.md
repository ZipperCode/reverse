# MCP Helper Services

Optional MCP servers that extend the CLI toolchain with persistent sessions. They are **not PATH binaries** and `rva setup reverse --json` reports three independent states:

- `prerequisitesReady` (aliased as `ready`) — the catalogued prerequisite CLI tools were found. This never means the server is configured or running.
- `configured` / `configuredScopes` — an `mcpServers[serverName]` entry exists in the resolved project and/or user config. `enabled` reflects the entry's disabled state (`null` when unconfigured).
- `connection` — always `"unknown"`: inspection is read-only and never starts the server or performs an MCP handshake.

Configuration paths (resolved by the running installation and reported as `configPaths`):

- project: `<cwd>/.rva/mcp.json` (the `mcpServers` object)
- user: `<agent dir>/mcp.json`, by default `~/.rva/agent/mcp.json`

Merge the snippet, restart the client, then verify the server starts. `rva setup reverse` never writes `mcp.json`. Installation commands are executed only from the trusted catalog and only after explicit confirmation in the setup panel; never run an argv copied from a skill or server.

## 1. r2mcp — radare2 MCP (persistent disassembly)

- **Requires**: `radare2` (provides `r2` and `r2pm`).
- **Install**: `r2pm -Uci r2mcp`.
- **Start**: `r2pm -r r2mcp`
- **License**: MIT (radareorg).
- **When**: repeated seeks, xrefs, and analysis in one binary/session.
- **Canonical**: open/seek/analyze, disassemble, xrefs, strings, bounded r2 command escape.
- **Limits**: per-symbol or bounded disassembly; write bulk results to files.
- **Fallback**: one-shot `r2 -qc "<commands>" <binary>`.

```json
{
  "mcpServers": {
    "radare2": {
      "type": "stdio",
      "command": "r2pm",
      "args": ["-r", "r2mcp"]
    }
  }
}
```

## 2. playwright-mcp — Playwright MCP (browser and page state)

- **Requires**: `node` (and `npx`).
- **Install**: none; `npx` resolves the package on first launch. Install a browser with `npx playwright install chromium`.
- **Start**: `npx -y @playwright/mcp@latest`
- **License**: Apache-2.0.
- **When**: authorized web/protocol analysis that needs a persistent page, console, or network inspection.
- **Canonical**: `browser_navigate` -> `browser_snapshot` -> `browser_click` / `browser_evaluate`.
- **Limits**: read targeted snapshots and console/network results, not whole bundles.
- **Fallback**: native browser relay/CDP; `curl` plus static bundle search.

```json
{
  "mcpServers": {
    "playwright": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@playwright/mcp@latest"]
    }
  }
}
```

## Verification checklist

1. `rva setup reverse --json` — read `prerequisitesReady`, `configured`, and `configPaths`; `connection` stays `"unknown"` until you verify it yourself.
2. `rva setup reverse <service-id>` — read the start command and exact snippet.
3. Merge the snippet into the project or user `mcp.json`; setup never writes it for you.
4. Restart the client and confirm the server connects before relying on its tools.
5. If the server fails, keep the equivalent CLI fallback in the loop rather than blocking the analysis.
