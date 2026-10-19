---
name: windows-reverse
description: Windows PE binary and dynamic library reverse engineering specialist. Focuses on PE header triage, IAT auditing, IDA Pro integration, radare2 disassembler, and anti-debug analysis.
metadata:
  requiresOptional: radare2, ida
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

When IDA Pro is unconfigured or absent, operators SHOULD continue directly with `radare2` as documented in `skill://reverse-lab/references/tool-fallback.md`.

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

Read `skill://reverse-lab/references/windows.md` for complete technical walkthroughs and radare2 command sequences.
