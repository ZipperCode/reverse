Native offline read-only crash dump and core file analysis without external debuggers or code execution.

Capabilities:
- **Crash Summary & Exception Forensics (`info`)**:
  - Automatically identifies dump format (Linux ELF Core ET_CORE 32/64-bit, Microsoft Minidump MDMP, Apple Mach-O Core MH_CORE) or reports structured unsupported status.
  - Extracts target architecture (x86_64, x86, ARM, AArch64, MIPS, RISC-V), endianness, operating system, and dump timestamp.
  - Decodes termination signal (e.g. SIGSEGV, SIGABRT, SIGBUS, SIGILL) or Windows exception code (e.g. 0xC0000005 STATUS_ACCESS_VIOLATION, 0x80000003 STATUS_BREAKPOINT).
  - Identifies faulting thread ID, faulting instruction pointer (IP/PC), faulting memory address, process executable name, and invocation arguments.
  - Summarizes total thread and module/memory mapping counts.
- **Thread Inspection (`threads`)**:
  - Catalogs all captured threads with thread ID, faulting/crashed status, signal, and essential pointers (instruction pointer IP/PC, stack pointer SP, frame pointer FP).
  - Paged with `limit` and `offset` for context budget management.
- **Memory Mappings & Loaded Modules (`mappings`)**:
  - Catalogs loaded shared libraries, executable segments, and memory regions with start/end virtual addresses, memory permissions (rwxp), offset, and file paths.
  - In ELF core, correlates `PT_LOAD` segments with `NT_FILE` mapped filenames.
  - In Minidump, decodes `ModuleListStream` entries with module base addresses, sizes, timestamps, and filenames.
- **Register State (`registers`)**:
  - Decodes complete general-purpose register dump for the faulting thread or requested `thread_id`.
  - Formats registers with hexadecimal values (e.g. RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, R8-R15, RIP, EFLAGS for x86_64; R0-R15, CPSR for ARM; X0-X30, SP, PC for AArch64).
- **Notes & Stream Descriptors (`notes`)**:
  - Lists raw/parsed ELF program notes (`NT_PRSTATUS`, `NT_PRPSINFO`, `NT_SIGINFO`, `NT_FILE`, `NT_AUXV`, `NT_GNU_BUILD_ID`).
  - Lists Minidump stream headers (`SystemInfoStream`, `ExceptionStream`, `ThreadListStream`, `ModuleListStream`, `MemoryListStream`).

Inputs:
- `action`: `"info"`, `"threads"`, `"mappings"`, `"registers"`, or `"notes"`.
- `path`: Path to target core dump or minidump file.
- `thread_id`: Optional specific thread ID to inspect in `registers` or `threads`.
- `limit`: Maximum threads, mappings, or notes to return (default 50, max 500).
- `offset`: Pagination offset (default 0).
- `max_bytes`: Maximum dump file bytes to read (default 100MB, max 500MB).

<examples>
```
crashdump_inspect(action: "info", path: "core.dump")
crashdump_inspect(action: "info", path: "crash.dmp")
crashdump_inspect(action: "threads", path: "core.dump")
crashdump_inspect(action: "mappings", path: "core.dump", limit: 30)
crashdump_inspect(action: "registers", path: "crash.dmp")
crashdump_inspect(action: "registers", path: "core.dump", thread_id: 1234)
crashdump_inspect(action: "notes", path: "core.dump")
```
</examples>
