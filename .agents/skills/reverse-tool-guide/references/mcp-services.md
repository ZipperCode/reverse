# MCP Helper Services

Optional MCP servers that extend the CLI toolchain with persistent sessions. They are **not PATH binaries** and `reverse setup reverse --json` reports three independent states:

- `prerequisitesReady` — catalogued prerequisite CLI tools were found. `ready` is prerequisite-only for launch-on-demand services; managed jshookmcp also requires `installed: true` and an entry that is not explicitly disabled. Neither field means connected.
- `configured` / `configuredScopes` — an `mcpServers[serverName]` entry exists in the resolved project and/or user config. `enabled` reflects the entry's disabled state (`null` when unconfigured).
- `connection` — always `"unknown"`: inspection is read-only and never starts the server or performs an MCP handshake.

Configuration paths (resolved by the running installation and reported as `configPaths`):

- project: `<cwd>/.reverse/mcp.json` (the `mcpServers` object)
- user: `<agent dir>/mcp.json`, by default `~/.reverse/agent/mcp.json`

For static MCP configuration, merge snippets into config paths. For native debuggers and decompilers, reverse provides the first-class `native_mcp_session` tool to manage active sessions dynamically across Ghidra, radare2, and x64dbg. Setup installations (CLI/TUI panel IDs: `x64dbg-mcp`, `ghidra-mcp`, `r2mcp`) require explicit operator confirmation; agent installation actions respect normal approval boundaries.

## 1. r2mcp — radare2 MCP (persistent disassembly)

- **Requires**: `radare2` (provides `r2` and `r2pm`).
- **Setup / Panel ID**: `r2mcp` via `reverse setup reverse r2mcp --execute` or TUI `/setup` → reverse tools.
- **Install**: `r2pm -Uci r2mcp`.
- **Start**: `r2pm -r r2mcp` (or managed via `native_mcp_session`).
- **License**: MIT (radareorg).
- **Managed Lifecycle**: `native_mcp_session(action: "connect", service: "radare2", target: "<binary_path>")`. Opens binary via upstream `open_file`, queries `show_info`, keeping file open across turns without re-seeking or spawning one-shot r2 commands.
- **Dynamic Tool Discovery**: Dynamically mounts upstream r2mcp tools into the active session without hardcoding static tool lists.
- **Safe Detach**: `native_mcp_session(action: "disconnect", session_id: "...")` unmounts session cleanly.
- **When**: repeated seeks, xrefs, and analysis in one binary/session.
- **Canonical**: open/seek/analyze, disassemble, xrefs, strings, bounded r2 command escape.
- **Limits**: per-symbol or bounded disassembly; write bulk results to files.
- **Fallback**: one-shot `r2 -qc "<commands>" <binary>` or `r2_inspect`.

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

## 2. ghidra-mcp — Ghidra MCP (persistent project & GUI backend)

- **Requires**: Python >= 3.10, Ghidra (12.1.4+), JDK 21+.
- **Setup / Panel ID**: `ghidra-mcp` via `reverse setup reverse ghidra-mcp --execute` or TUI `/setup` → reverse tools. Installs managed LaurieWired GhidraMCP 2.0 wheel + extension JAR in agent venv.
- **License**: Apache-2.0.
- **Managed Lifecycle**:
  - **Headless persistent mode**: `native_mcp_session(action: "connect", service: "ghidra", target: "/path/to/binary", project_dir?: "/path/to/project")`. Automatically caches project metadata with `--save` outside `/tmp` across turns. Enforces single Java project mutual exclusion lock per project directory.
  - **GUI backend mode**: omit `target`, specify `backend_url` (default `http://127.0.0.1:8080/`).
- **Dynamic Tool Discovery**: Upstream GhidraMCP tools are mounted dynamically into the active session without hardcoding static lists.
- **Target Verification**: Validates target SHA256 against `get_program_info` to prevent analyzing wrong or outdated project samples.
- **Safe Detach**: `native_mcp_session(action: "disconnect", session_id: "...")` releases project locks and unmounts session cleanly.
- **Fallback**: `ghidra_inspect` or headless `analyzeHeadless` scripts.

## 3. x64dbg-mcp — x64dbg MCP (Windows dynamic debugging)

- **Requires**: Python >= 3.10.
- **Setup / Panel ID**: `x64dbg-mcp` via `reverse setup reverse x64dbg-mcp --execute` or TUI `/setup` → reverse tools. Installs managed Python bridge (`x64dbg_automate[mcp]==0.9.2`) in agent venv; on Windows, optionally installs portable x64dbg with ghost_fungus plugin.
- **License**: MIT (ghost_fungus).
- **Managed Lifecycle**:
  - **Local start**: `native_mcp_session(action: "connect", service: "x64dbg", target: "C:\\targets\\crackme.exe", x64dbg_path?: "...")`. Note: Absolute Windows target paths remain Windows host paths.
  - **Local attach**: `native_mcp_session(action: "connect", service: "x64dbg", session_pid: 12345)`.
  - **Remote connect**: `native_mcp_session(action: "connect", service: "x64dbg", host: "127.0.0.1", req_rep_port: 31337, pub_sub_port: 31338)`.
- **Security Notice**: ZeroMQ remote RPC has **NO built-in authentication**. Always tunnel through private loopback or secure SSH tunnels (`ssh -L 31337:127.0.0.1:31337 -L 31338:127.0.0.1:31338 user@remote-windows-host`); never expose x64dbg automation ports to untrusted networks.
- **Dynamic Tool Discovery**: Dynamically mounts discovered upstream x64dbg tools into the session.
- **Target Matching**: Queries `get_debugger_status` and module image maps from memory map.
- **Safe Detach**: `native_mcp_session(action: "disconnect", session_id: "...")` calls upstream `disconnect` to detach cleanly without terminating target process or host debugger (never calls `terminate_session`).
- **Fallback**: `windows_observe` offline traces or `debug` (DAP).

## 4. playwright-mcp — Playwright MCP (browser and page state)

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

## 5. jshookmcp — frontend debugging and deobfuscation

- **Setup**: `reverse setup reverse jshookmcp --execute`, or `/setup` → reverse toolchain → jshookmcp → install.
- **Agent installation**: `reverse_capability(action: "install", service: "jshookmcp")`; `scope: "project"` is available when project-only configuration is desired. Obtain authorization for installation first.
- **Runtime**: supported Node.js and npm; installs `@jshookmcp/jshook@0.4.2` and `webcrack@2.16.0` in the active profile's managed tools directory. Native dependencies may require a local compiler.
- **Defaults**: independent local stdio MCP named `jshook`, search profile, vector search disabled. Browser downloads and other optional engines are separate actions.
- **Dispatch**: use the mounted jshook `search_tools` → `describe_tool` → `activate_tools` → `call_tool` tools for debugging, AST transforms, protocol analysis, and signature experiments. Query schemas rather than guessing arguments. If the tool activation budget is reached, free unused tools with `deactivate_tools` before retrying rather than attempting to raise limits.
- **Ownership**: one controller per browser target. Let jshook own targets under active debugging; use reverse native tools for separate static analysis.
- **License**: upstream AGPL-3.0-only, installed as an external service; source is not copied into reverse. Review obligations before redistribution or providing modified services to others.
- **Limits**: reverse currently does not advertise MCP sampling; client-sampling-dependent LLM suggestions are unavailable. The main agent can reason about deterministic tool outputs directly.

## 6. Unidbg Integration Note (Manual Maven Java Harness)

- **Upstream Status**: Upstream `zhkl0228/unidbg` is a Java library, not a standalone pre-packaged CLI server executable. While unidbg supports MCP via `McpToolkit` within a running JVM debugger session, it requires manual Java project integration.
- **Requires**: Java (JDK 8 / OpenJDK 8) and Maven.
- **Install/Compile**: `git clone https://github.com/zhkl0228/unidbg.git && cd unidbg && mvn package -DskipTests`.
- **Harness Setup**: Implement a Maven test case or standalone Java application initializing `AndroidEmulator` and registering custom tools via `McpToolkit`.
- **Fallback**: `android_native_workflow` (built-in ELF & JNI triage), live device instrumentation via `frida_session`, or static disassembly via `r2_inspect` / `ghidra_inspect`.


## 7. Native MCP Session Address Mapping (`locate`)

`native_mcp_session(action: "locate", ...)` maps dynamic runtime addresses to static decompilation coordinates:

```javascript
native_mcp_session({
  action: "locate",
  runtime_address: "0x7ff6a0001050",
  module_base: "0x7ff6a0000000",
  static_base: "0x140000000",
  module_name: "target.exe"
})
```

- **Arithmetic**: Uses 64-bit BigInt unsigned integer arithmetic:
  - `module_offset (RVA) = runtime_address - module_base`
  - `static_address (VA) = static_base + module_offset`
  - Generated locator: `<module_name>+0x<RVA> -> static:0x<static_address>`
- **Discipline**: `source: "supplied"`, `computation: "arithmetic"`, `evidence_verified: false`.
- **Coordinates Source**: Pure supplied arithmetic projection, **NOT empirically verified execution facts or physical file offsets** (file offsets differ from virtual addresses due to PE/ELF section alignment and headers).

## 8. Frida Dynamic Trace Templates (`jni_register` & `native_functions`)

Reverse provides built-in Frida trace templates for `frida(action: "trace", ...)` and `frida_session(action: "create" | "load", ...)`:

1. **`template: "jni_register"`**:
   - Traces Android JNI `RegisterNatives` dynamic registrations without requiring manual scripts.
   - Automatically resolves `RegisterNatives` from `libart.so` symbols and JNIEnv vtable index 215.
   - Captures: `class` (reflection-decoded Java class name without Java bridge requirement), method `name`, `signature`, native function pointer (`fnPtr`), module `base` address, and relative hex `offset` (`0x` + `fnPtr - mod.base`).
   - **Confirmation Contract**: In the JNI specification, `RegisterNatives` returns 0 on success. **ONLY `retval === 0` confirms registration** (`status: "confirmed"`); non-zero return value indicates failure (`status: "rejected"`).

2. **`template: "native_functions"`**:
   - Traces native function calls with bounded argument decoding.
   - Supports `symbol` / `symbols`, `offset` / `offsets`, `module`.
   - **Bounded typed argument decoding**: `args_decode` (mapping argument index to type like `"string"`, `"int"`, `"uint"`, `"pointer"`, `"hexdump"`), bounded by `maxBufferBytes` (default 256 bytes) and `args_count` (default 4).
   - Captures `retval` (boolean) and `backtrace` (`true`, `"accurate"`, `"fuzzy"`, or `false`).
   - Enforces `max_events` bound and safely unregisters only its own listener handles upon cleanup (never calls global detachAll).

## Verification checklist

1. `reverse setup reverse --json` — read `prerequisitesReady`, `configured`, and `configPaths`; `connection` stays `"unknown"` until verified.
2. **Distinguish 5 Observable State Tiers**:
   - `installed`: Host dependency / managed venv is present (e.g. `x64dbg-mcp`, `ghidra-mcp`, `r2mcp`).
   - `configured`: Entry exists in project or user `mcp.json`.
   - `transport connected`: JSON-RPC / stdio / ZeroMQ transport handshake active in MCPManager.
   - `target matched`: Target binary, PID, or SHA256 verified inside the engine (e.g. x64dbg memory map, Ghidra `get_program_info` hash, radare2 `open_file`).
   - `executed verified`: Concrete inspection or debugger commands executed with verified results recorded in EvidenceStore.
3. `reverse setup reverse <service-id>` — read the start command and exact snippet.
4. For jshookmcp, run its confirmed setup installation; the installer verifies and writes configuration. For other services, merge the displayed snippet or use `native_mcp_session`.
5. In search-mode MCP (jshook), follow the sequence: `search_tools` → `describe_tool` → `activate_tools` → `call_tool`. If the activation budget is exhausted, call `deactivate_tools` to free unneeded tools before retrying.
6. Retain single-owner control for stateful targets, emulators, debuggers, and browser controllers; delegate only independent, bounded sub-tasks.
7. If the server fails or target is unmatched, keep the equivalent CLI fallback in the loop with a brief verifiable rationale rather than blocking the analysis.
8. **Host Verification Claim Limits**: Current development host (macOS darwin arm64) has no Windows host / x64dbg smoke and no live Ghidra backend smoke; Frida native tracing was verified using local C ABI fixtures (`mock_RegisterNatives`), not Android `libart.so` on real devices.
