# MCP Helper Services

Optional MCP servers that extend the CLI toolchain with persistent sessions. They are **not PATH binaries** and `reverse setup reverse --json` reports three independent states:

- `prerequisitesReady` — catalogued prerequisite CLI tools were found. `ready` is prerequisite-only for launch-on-demand services; managed jshookmcp also requires `installed: true` and an entry that is not explicitly disabled. Neither field means connected.
- `configured` / `configuredScopes` — an `mcpServers[serverName]` entry exists in the resolved project and/or user config. `enabled` reflects the entry's disabled state (`null` when unconfigured).
- `connection` — always `"unknown"`: inspection is read-only and never starts the server or performs an MCP handshake.

Configuration paths (resolved by the running installation and reported as `configPaths`):

- project: `<cwd>/.reverse/mcp.json` (the `mcpServers` object)
- user: `<agent dir>/mcp.json`, by default `~/.reverse/agent/mcp.json`

For r2mcp and Playwright, merge the snippet and verify the connection in the client. The managed jshookmcp installer instead installs a pinned local package, verifies its MCP handshake and tools, and writes the active-profile user configuration automatically. Setup installations require explicit confirmation; the agent installation action uses the normal write approval boundary.

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

## jshookmcp — frontend debugging and deobfuscation

- **Setup**: `reverse setup reverse jshookmcp --execute`, or `/setup` → reverse toolchain → jshookmcp → install.
- **Agent installation**: `reverse_capability(action: "install", service: "jshookmcp")`; `scope: "project"` is available when project-only configuration is desired. Obtain authorization for installation first.
- **Runtime**: supported Node.js and npm; installs `@jshookmcp/jshook@0.4.2` and `webcrack@2.16.0` in the active profile's managed tools directory. Native dependencies may require a local compiler.
- **Defaults**: independent local stdio MCP named `jshook`, search profile, vector search disabled. Browser downloads and other optional engines are separate actions.
- **Dispatch**: use the mounted jshook `search_tools` → `describe_tool` → `activate_tools` → `call_tool` tools for debugging, AST transforms, protocol analysis, and signature experiments. Query schemas rather than guessing arguments. If the tool activation budget is reached, free unused tools with `deactivate_tools` before retrying rather than attempting to raise limits.
- **Ownership**: one controller per browser target. Let jshook own targets under active debugging; use reverse native tools for separate static analysis.
- **License**: upstream AGPL-3.0-only, installed as an external service; source is not copied into reverse. Review obligations before redistribution or providing modified services to others.
- **Limits**: reverse currently does not advertise MCP sampling; client-sampling-dependent LLM suggestions are unavailable. The main agent can reason about deterministic tool outputs directly.

## 3. Unidbg Integration Note (Manual Maven Java Harness)

- **Upstream Status**: Upstream `zhkl0228/unidbg` is a Java library, not a standalone pre-packaged CLI server executable. While unidbg supports MCP via `McpToolkit` within a running JVM debugger session, it requires manual Java project integration.
- **Requires**: Java (JDK 8 / OpenJDK 8) and Maven.
- **Install/Compile**: `git clone https://github.com/zhkl0228/unidbg.git && cd unidbg && mvn package -DskipTests`.
- **Harness Setup**: Implement a Maven test case or standalone Java application initializing `AndroidEmulator` and registering custom tools via `McpToolkit`.
- **Fallback**: `android_native_workflow` (built-in ELF & JNI triage), live device instrumentation via `frida_session`, or static disassembly via `r2_inspect` / `ghidra_inspect`.


## Verification checklist

1. `reverse setup reverse --json` — read `prerequisitesReady`, `configured`, and `configPaths`; `connection` stays `"unknown"` until you verify it yourself.
2. `reverse_capability(action: "status")` — inspect observable runtime state distinguishing configured, connected, discovered, targetMatched, and executed.
3. `reverse setup reverse <service-id>` — read the start command and exact snippet.
4. For jshookmcp, run its confirmed setup installation; the installer verifies and writes configuration. For other services, merge the displayed snippet.
5. In search-mode MCP (jshook), follow the sequence: `search_tools` → `describe_tool` → `activate_tools` → `call_tool`. If the activation budget is exhausted, call `deactivate_tools` to free unneeded tools before retrying. When tools list is unrefreshed, invoke via the `call_tool` bridge.
6. Retain single-owner control for stateful targets, emulators, debuggers, and browser controllers; delegate only independent, bounded sub-tasks.
7. If the server fails or target is unmatched, keep the equivalent CLI fallback in the loop with a brief verifiable rationale rather than blocking the analysis.
