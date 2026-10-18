# crashdump_inspect

> Native offline read-only crash dump and core file analysis without external debuggers or code execution.

## Source
- Entry: `packages/coding-agent/src/tools/crashdump-inspect.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/crashdump-inspect.md`

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `action` | `"info" \| "threads" \| "mappings" \| "registers" \| "notes"` | Yes | `info` catalogs crash summary, architecture, faulting thread/instruction, and exception/signal; `threads` lists threads with fault status and register pointers; `mappings` catalogs memory mappings and loaded modules; `registers` dumps general-purpose registers; `notes` catalogs raw ELF notes or Minidump streams. |
| `path` | `string` | Yes | Path to target core dump or minidump file. |
| `thread_id` | `number >= 0` | No | Specific thread ID to inspect for registers or thread details. |
| `limit` | `number >= 1` | No | Maximum threads, mappings, or notes to return (default 50, max 500). |
| `offset` | `number >= 0` | No | Pagination offset (default 0). |
| `max_bytes` | `number >= 1` | No | Maximum dump file bytes to read (default 100MB, max 500MB). |

## Capabilities & Analysis
- **Crash Summary & Termination Diagnostics (`info`)**:
  - Automatically identifies dump format (Linux ELF Core ET_CORE 32/64-bit, Microsoft Minidump MDMP, Apple Mach-O Core MH_CORE) or reports structured unsupported status.
  - Extracts target architecture (x86_64, x86, ARM, AArch64, MIPS, RISC-V), endianness, operating system, and dump timestamp.
  - Decodes termination signal (e.g. SIGSEGV, SIGABRT, SIGBUS, SIGILL) or Windows exception code (e.g. 0xC0000005 STATUS_ACCESS_VIOLATION, 0x80000003 STATUS_BREAKPOINT).
  - Identifies faulting thread ID, faulting instruction pointer (IP/PC), faulting memory address, process executable name, and invocation arguments.
  - Summarizes total thread and module/memory mapping counts.
- **Thread Enumeration & Status (`threads`)**:
  - Catalogs all captured threads with thread ID, faulting/crashed status, signal, and essential pointers (instruction pointer IP/PC, stack pointer SP, frame pointer FP).
  - Paged with `limit` and `offset` for context budget management.
- **Memory Mappings & Module Inspection (`mappings`)**:
  - Catalogs loaded shared libraries, executable segments, and memory regions with start/end virtual addresses, memory permissions (rwxp), offset, and file paths.
  - In ELF core, correlates `PT_LOAD` segments with `NT_FILE` mapped filenames.
  - In Minidump, decodes `ModuleListStream` entries with module base addresses, sizes, timestamps, and filenames.
- **Register State Decoding (`registers`)**:
  - Decodes complete general-purpose register dump for the faulting thread or requested `thread_id`.
  - Formats registers with hexadecimal values (e.g. RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, R8-R15, RIP, EFLAGS for x86_64; R0-R15, CPSR for ARM; X0-X30, SP, PC for AArch64).
- **Notes & Stream Descriptors (`notes`)**:
  - Lists raw/parsed ELF program notes (`NT_PRSTATUS`, `NT_PRPSINFO`, `NT_SIGINFO`, `NT_FILE`, `NT_AUXV`, `NT_GNU_BUILD_ID`).
  - Lists Minidump stream headers (`SystemInfoStream`, `ExceptionStream`, `ThreadListStream`, `ModuleListStream`, `MemoryListStream`).
- **Structured Unsupported / Corrupt Handling**:
  - When provided an invalid or non-crash dump file (e.g. an ELF executable instead of a core dump, or a truncated header), safely returns `{ status: "unsupported" | "corrupt", format: "unknown", unsupportedReason: "..." }` without throwing unhandled exceptions.

## Security & Operational Boundaries
- **Strictly Read-Only**: Performs memory-bounded buffer reading and parsing.
- **No External Debuggers**: Never invokes `gdb`, `lldb`, `cdb`, or `windbg`.
- **No Arbitrary Shell**: Does not execute shell commands or spawned processes.
- **Bounded Resource Consumption**: Limits maximum read bytes (up to 500MB) and bounds table rows.

## Registration Details
- `name`: `crashdump_inspect`
- `approval`: `read`
- `loadMode`: `discoverable`
- `strict`: `true`
