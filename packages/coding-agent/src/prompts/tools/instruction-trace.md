Controlled dynamic instruction tracing and execution state recording via Frida Stalker and QuarkslaB Dynamic binary Instrumentation (QBDI, Apache-2.0).

Capabilities:
- **Environment & Engine Status Probe (`status`)**:
  - Probes availability of Frida CLI (`frida`), persistent Frida Live environment (`probeFridaLiveDependency`), and Frida Stalker engine across ARM32, AArch64, x86, and x86_64.
  - Resolves managed QBDI runtime assets (v0.12.1) via authoritative `resolveProtectionTool("qbdi")` and reports whether deterministic memory read interception is available.
  - Distinguishes missing QBDI assets and provides exact remediation command (`reverse setup reverse qbdi --execute`) without implicit internet downloads.
  - Read approval tier; allowed in plan mode.
- **Bounded Instruction & Memory Capture (`capture`)**:
  - Attaches to running process (`pid` or `process`), spawns target (`spawn`), or connects to active Frida live session (`session_id`).
  - Scopes tracing to explicit bounds: function export/symbol (`function`), RVA offset (`offset`), absolute address (`address`), or explicit address range (`range`).
  - Thread-scoped execution: isolates trace collection to the calling thread or specified `thread_id`, preventing performance degradation and background thread noise.
  - Multi-engine architecture:
    - **QBDI (`engine: "qbdi"`)**: Leverages upstream QuarkslaB DBI for deterministic instruction interception and exact memory read tracking (`getInstMemoryAccess`).
    - **Stalker (`engine: "stalker"`)**: Uses Frida's native Stalker engine to instrument ARM32, AArch64, and x86 instruction streams with pre-instruction context callouts.
    - **Auto (`engine: "auto"`, default)**: Prefers QBDI when installed and provided function scalar signature for complete memory read observability; automatically falls back to Frida Stalker.
  - Structured Triton-compatible JSONL trace output:
    - `{"type": "registers", "values": {<name>: <hex>}}`: Concrete CPU register state captured *before* instruction execution. Canonical lowercase names (`r0`-`r12`, `sp`, `lr`/`r14`, `pc`, `apsr`/`cpsr` on ARM32; `x0`-`x30`, `sp`, `pc`, `nzcv` on AArch64; `rax`-`r15`, `rip`, `rflags` on x86_64).
    - `{"type": "memory_read", "address": <hex>, "size": <int>, "value": <hex>}`: Concrete memory read state dereferenced *before* instruction execution.
    - `{"type": "instruction", "address": <hex>, "bytes": <hex>, "size": <int>, "disasm": <str>}`: Executed instruction with address, raw opcode bytes, size, and disassembly.
  - Legacy Salwan format support: Configurable `format: "salwan"` (`mr:` memory read, `r:` CPU register snapshot, `i:` instruction address/size/bytes/disassembly) for backward compatibility.
  - Provenance sidecar manifest (`<trace>.manifest.json`): Records target PID, architecture, module base address, size, SHA-256 target hash, Thumb mode flags, NZCV/APSR register status, memory read completeness flag, and execution completion reason (`function_return`, `max_instructions_reached`, `range_exit`, `timeout`, `max_bytes_exceeded`).
  - Triton replay request handoff: Generates and returns a pre-configured `replay_handoff` parameter object ready to pass directly to `triton_analyze`.
  - Owned hook lifecycle: strictly cleans up all injected hooks (`Interceptor.detach()`, `Stalker.unfollow()`, `Stalker.flush()`) upon completion or cancellation.
  - Exec approval tier; blocked in plan mode.

Inputs:
- `action`: `"status"` (read capability probe) or `"capture"` (dynamic execution trace capture).
- `pid`: Target process ID to attach to.
- `process`: Target process name or package identifier.
- `spawn`: Target binary or package to spawn and trace.
- `session_id`: Identifier of an existing active Frida live session to reuse.
- `device`: Target device ID / serial (adb serial for `-D`).
- `usb`: Target USB device/emulator (shorthand for `-U`).
- `host`: Target remote frida-server host (e.g. `192.168.1.5:27042`).
- `module`: Target module/library name (e.g. `libnative-lib.so`).
- `function`: Target function symbol name or export to trace (e.g. `Java_com_example_Calc` or `validate_license`).
- `offset`: RVA offset from module base (hex string or integer, e.g. `"0x1020"`).
- `address`: Absolute memory address to trace.
- `thread_id`: Specific thread ID to trace (defaults to calling thread).
- `scope`: Tracing scope: `"function"` (trace until return), `"thread"` (trace thread execution), or `"range"` (trace within address range).
- `range`: Explicit address range `{ start, end }` for range-scoped tracing.
- `max_instructions`: Maximum instructions to collect (default: 10000, max: 200000).
- `timeout_ms`: Subprocess execution timeout in milliseconds (default: 30000).
- `max_bytes`: Maximum trace output size in bytes (default: 33554432 / 32MB).
- `engine`: Tracing engine: `"auto"` (prefer QBDI when signature provided, fallback to Stalker), `"qbdi"` (QBDI DBI with VM.call), or `"stalker"` (Frida Stalker observational tracing).
- `format`: Trace output format: `"jsonl"` (default, Triton worker JSONL) or `"salwan"` (Salwan mr:/r:/i: text format).
- `signature`: Explicit C function scalar signature required for `engine: "qbdi"`: `{ return_type: "uint64", arg_types: ["uint64", "pointer"] }` (supported types: `pointer`, `uint64`, `int64`, `uint32`, `int32`, `int`, `uint`, `void`).
- `output_path`: Optional file path to copy/publish the trace output.

<examples>
```
// Check Frida, Stalker, and QBDI availability
instruction_trace(
  action: "status"
)

// Trace native function in Android app using USB device and Stalker/QBDI auto engine
instruction_trace(
  action: "capture",
  usb: true,
  process: "com.example.secureapp",
  module: "libnative-lib.so",
  function: "Java_com_example_secureapp_MainActivity_verifyKey",
  max_instructions: 5000,
  engine: "auto"
)

// Trace explicit RVA offset in a spawned local binary
instruction_trace(
  action: "capture",
  spawn: "./crackme_arm64",
  module: "crackme_arm64",
  offset: "0x1a40",
  scope: "function",
  max_instructions: 20000
)

// Range-scoped trace within a packed routine
instruction_trace(
  action: "capture",
  pid: 14820,
  module: "libprotect.so",
  range: {
    start: "0x7f80001000",
    end: "0x7f80002000"
  },
  scope: "range",
  max_instructions: 50000
)

// Trace native function with QBDI and explicit C signature
instruction_trace(
  action: "capture",
  spawn: "./reverse_trace_target_smoke",
  module: "reverse_trace_target_smoke",
  function: "reverse_trace_target",
  signature: {
    return_type: "uint64",
    arg_types: ["uint64", "pointer"]
  },
  engine: "qbdi"
)
```
</examples>
