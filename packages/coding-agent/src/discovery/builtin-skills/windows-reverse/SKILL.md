---
name: windows-reverse
description: Windows PE binary and dynamic library reverse engineering specialist. Focuses on PE header triage, IAT auditing, IDA Pro integration, radare2 disassembler, and anti-debug analysis.
metadata:
  requiresOptional: radare2, ida, x64dbg-mcp
---

# Windows PE Reverse Engineering Specialist

`windows-reverse` is the specialized domain skill for auditing Windows Portable Executable (PE) binaries (`.exe`, `.dll`, `.sys`, `.node`). It provides focused static disassembler inspection, Import Address Table (IAT) auditing, and reproducible hypothesis validation.

For full multi-platform routing, consult `skill://reverse-lab/SKILL.md`.

---

## 1. Operating Contract & Evidence Standards

- **Target Authorization & Environment**: Operators MUST analyze binaries, execute unpacking routines, and attach debuggers exclusively within explicitly authorized Windows laboratory environments or hypervisor sandboxes.
- **Sample Integrity & Artifact Isolation**: Operators MUST preserve original PE sample binaries strictly read-only. Unpacked binaries, patch artifacts, and memory dumps MUST be written to separate dedicated artifact paths (`./artifacts/`).
- **Evidence Precision**: Documented findings MUST reference unambiguous binary coordinates:
  - Relative Virtual Address (RVA) and file offset (e.g. `RVA 0x140001020`, File Offset `0x0E20`)
  - Verbatim assembly opcode sequences (e.g. `test eax, eax; jz loc_14000108A`)
  - Full imported/exported API symbol name (e.g. `KERNEL32.dll!IsDebuggerPresent`)
- **Stateful Debugger Rule**: Operators MUST assign dynamic debugging sessions to a single stateful session controller to avoid port collisions and process conflicts.

Read `skill://reverse-lab/references/evidence.md` for report schemas.

---

## 2. Toolchain & Dependencies

- **Primary CLI Disassembler (`radare2`)**: OPTIONAL. Provides headless disassembler analysis, symbol extraction, function graph mapping, and string cross-references (`r2 -qc "iI; iS; ii; is" <pe>`).
- **Advanced Decompilation Engine (`ida`)**: OPTIONAL. When available with `idalib`, leverage reverse's native `read-binary` selectors (`:overview`, `:imports`, `:exports`, `:xrefs:<sym>`, `:decompile:<func>`).
- **Offline Windows API Trace Analysis (`windows_observe`)**: OPTIONAL (Built-in tool). Analyze existing ETW, API Monitor, or structured JSON/NDJSON capture files offline. Supports `inspect` (process/module/category summary), paged `list`/`search` (filtering by PID, module, API, category, direction, time range), and sanitized `export`. It never attaches, injects, or replays; all analysis is read-only.
- **Interactive Windows Debugger (`native_mcp_session` / `x64dbg-mcp`)**: OPTIONAL. Provides dynamic debugging, register/memory inspection, and breakpoint tracing via managed x64dbg automation.
  - Setup / Panel ID: `x64dbg-mcp` via `reverse setup reverse x64dbg-mcp --execute` or TUI `/setup` → reverse tools. Installs managed Python bridge (`x64dbg_automate[mcp]==0.9.2`) and on Windows optional portable x64dbg with ghost_fungus plugin.
  - Connection modes:
    - Local start: `native_mcp_session(action: "connect", service: "x64dbg", target: "C:\\targets\\crackme.exe", x64dbg_path?: "...")`. Note: Absolute Windows target paths remain Windows host paths.
    - Local attach: `native_mcp_session(action: "connect", service: "x64dbg", session_pid: 12345)`.
    - Remote connect: `native_mcp_session(action: "connect", service: "x64dbg", host: "127.0.0.1", req_rep_port: 31337, pub_sub_port: 31338)`.
  - Security Notice: ZeroMQ remote RPC has **NO built-in authentication**. Always tunnel through private loopback or secure SSH tunnels (`ssh -L 31337:127.0.0.1:31337 -L 31338:127.0.0.1:31338 user@remote-windows-host`); never expose x64dbg automation ports to untrusted networks.
  - Dynamic Tool Discovery: Upstream tools are dynamically discovered and mounted upon connection without hardcoded tool lists.
  - Clean Detach: `native_mcp_session(action: "disconnect", session_id: "...")` cleanly detaches without terminating the target process or host debugger (calls upstream `disconnect`).
  - Address Mapping (`locate`): `native_mcp_session(action: "locate", runtime_address: "...", module_base: "...", static_base: "...")` maps dynamic addresses to static coordinates using 64-bit BigInt unsigned integer arithmetic. Coordinate discipline: `source: "supplied"`, `computation: "arithmetic"`, `evidence_verified: false` (projections, not verified execution facts or physical file offsets).

When IDA Pro or x64dbg is unconfigured or absent, operators SHOULD continue directly with `radare2` as documented in `skill://reverse-lab/references/tool-fallback.md`.

---

## 3. Recommended Workflow

1. **PE Header & Mitigation Profiling**:
   - Inspect machine type (x86/x64/ARM64), subsystem (GUI/CUI), ASLR, and DEP/NX via `r2 -qc "iI" <pe>`.
2. **Import Address Table (IAT) Triage**:
   - Identify capability indicators (e.g. `VirtualAlloc`, `WriteProcessMemory`, `CryptDecrypt`, `IsDebuggerPresent`) using `r2 -qc "ii" <pe>`.
3. **Cross-Reference & Control Flow Analysis**:
   - Locate callers of security-sensitive APIs via `r2 -qc "aaa; axt @ <sym>" <pe>`.
   - Disassemble candidate validation functions with `r2 -qc "aaa; pdf @ <func>" <pe>`.
4. **Anti-Analysis & Unpacking (Isolated Target Only)**:
   - Detect UPX compression and decompress to a dedicated artifact path with `upx -d -o ./artifacts/unpacked_target.exe <pe>`.
   - Audit PEB queries (`BeingDebugged`, `NtGlobalFlag`) and hardware breakpoint checks (`GetThreadContext`).

5. **Offline API Trace & Behavior Auditing**:
   - For captured execution traces (ETW / API Monitor / JSON/NDJSON), run `windows_observe(action: "inspect", path: "<trace>")` to profile active modules and APIs.
   - Use `windows_observe(action: "list" | "search", ...)` to examine specific call parameters with automated credential redaction.

6. **Dynamic Debugging & Address Mapping (`native_mcp_session`)**:
   - Launch or attach via `native_mcp_session(action: "connect", service: "x64dbg", ...)` using Windows host paths.
   - Verify session health and target loading via `native_mcp_session(action: "status", session_id: "...")`.
   - Map dynamic runtime addresses to static PE decompilation base via `native_mcp_session(action: "locate", ...)`.
   - Detach cleanly via `native_mcp_session(action: "disconnect", session_id: "...")`.
   - Distinguish the 5 observable state tiers: `installed`, `configured`, `transport connected`, `target matched`, and `executed verified`.
   - Verification claim limit: Current development host (macOS darwin arm64) has no Windows host / x64dbg smoke testing executed.

Read `skill://reverse-lab/references/windows.md` for complete technical walkthroughs and radare2 command sequences.
