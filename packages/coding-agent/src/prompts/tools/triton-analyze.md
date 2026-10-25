Offline dynamic binary analysis, symbolic execution, trace replay, AST simplification/synthesis, and LLVM IR lifting using Jonathan Salwan's Triton library.

Capabilities:
- **Environment and Capability Probe (`status`)**:
  - Probes the managed Python runtime resolved for Triton (`resolveVmpTool("triton")`).
  - Distinguishes whether the Triton library is installed, its version, and supported target architectures (`x86`, `x86_64`, `arm32`, `aarch64`).
  - Reports solver availability (`Z3`, `BITWUZLA`) and AST synthesizer availability via actual execution probes.
  - Performs an actual probe for LLVM IR lifting capability (`liftToLLVM`), distinguishing whether Triton was compiled with the LLVM interface enabled or disabled.
  - Allowed in plan mode and categorized under read approval tier.
- **Architecture Information (`arch_info`)**:
  - Returns canonical register naming, bitness, program counter, stack pointer, zero registers, and flag parents for `x86`, `x86_64`, `arm32`, or `aarch64`.
  - Allowed in plan mode under read approval tier.
- **Offline Bounded Trace Replay (`replay`)**:
  - Replays execution traces offline inside Triton's symbolic execution engine across x86, x86_64, ARM32, and AArch64. Target code is strictly emulated and never executed on the host system.
  - Supports ARM Thumb execution mode (`thumb: true` or automatically detected from odd address bit / CPSR).
  - Enforces AArch64 Wn zero-extension: writing 32-bit `Wn` (or `wsp`) automatically zeroes upper bits 32..63 in `Xn` (or `sp`).
  - Correctly models hardware zero registers (`xzr`, `wzr` in AArch64) as always initialized to zero.
  - Enforces strict SIMD/vector register tracking: vector reads (`xmm`/`ymm`/`zmm` in x86; `s`/`d`/`q` in ARM32; `v`/`q`/`d`/`s`/`h`/`b` in AArch64) are verified for prior initialization and explicitly rejected if uninitialized rather than zero-filled.
  - Compatible with Jonathan Salwan's documented trace text format (`mr:` memory read, `r:` CPU register snapshot, `i:` instruction address/size/bytes/disassembly) and structured JSONL entries (`{"type": "instruction"|"registers"|"memory_read", ...}`).
  - Requires trace file on disk (`trace`).
  - Configurable architecture (`arch`: `"x86"`, `"x86_64"`, `"arm32"`, `"aarch64"`), explicit initial registers (`initial_registers`), and explicit concrete memory (`initial_memory`).
  - Never hardcodes Linux SysV calling conventions (`rdi`/`rsi`/`eax`). Symbolic register inputs (`symbolic_registers`), symbolic memory inputs (`symbolic_memory`), and target output expressions (`output`) must be explicitly declared.
  - Symbolic inputs require genuine concrete seed values (via `initial_registers`/`initial_memory` or `seed` property); never assumes zeroes.
  - Validates ISA register bit ranges, sub-register bit coverage, and memory definition.
  - Strict missing state validation: if an instruction reads uninitialized memory, an uninitialized general-purpose register, or an uninitialized flag/vector, the execution fails with an explicit missing evidence error rather than silently inventing zeroes.
  - Synchronizes trace register/memory snapshots without resetting live symbolic expressions, raising an unmodelled execution gap error on symbolic divergence.
  - Computes path constraints along the replayed trace path.
  - Simplifies AST expressions and synthesizes deobfuscated formulas (`synthesize: true`).
  - Lifts deobfuscated expressions to LLVM IR (`lift_llvm: true`) when the LLVM feature is available in Triton, or returns a clean explicit feature-unavailable status without fake fallbacks.
  - Context bounding and artifact retention: long symbolic AST expressions and complete LLVM IR modules are persisted to session artifacts (`artifact://<id>`) or local artifact fallback files, keeping model context concise.
  - Explicit execution notice: offline trace replay models only the executed trace path, never claiming full-function equivalence across unexecuted branches.
  - Gated outside plan mode with write approval tier (executes emulation and writes persistent artifacts).

Inputs:
- `action`: `"status"`, `"arch_info"`, or `"replay"`.
- `trace`: Path to trace file on disk (required for `replay`).
- `arch`: Target architecture: `"x86"`, `"x86_64"`, `"arm32"`, or `"aarch64"`. Default: `"x86_64"`.
- `thumb`: Enable Thumb execution mode for ARM32 (default `false`).
- `initial_registers`: Key-value map of register names to concrete integer/hex values (e.g. `{"rip": "0x401000", "rdi": "0x1234"}` for x86_64; `{"pc": "0x401000", "x0": "0x1234"}` for AArch64; `{"pc": "0x401000", "r0": "0x1234"}` for ARM32).
- `initial_memory`: Array of concrete memory definitions:
  - `address`: Hex string or integer.
  - `size`: Byte count (default 1).
  - `value`: Concrete integer or hex value.
- `symbolic_registers`: Array of registers to symbolize as inputs:
  - `name`: Register name (e.g. `"rdi"`, `"rsi"`, `"x0"`, `"r0"`).
  - `alias`: Variable label in AST expressions (e.g. `"x"`, `"y"`).
  - `seed`: Concrete seed value if not provided in `initial_registers`.
- `symbolic_memory`: Array of memory regions to symbolize:
  - `address`: Target memory address.
  - `size`: Byte count to symbolize.
  - `alias`: Variable label in AST expressions.
  - `seed`: Concrete seed value.
- `output`: Output target specification (required for `replay`):
  - Register: `{ kind: "register", target: "rax" }` (or `"x0"`, `"r0"`)
  - Memory: `{ kind: "memory", address: "0x7ffffff0", size: 8 }`
- `bounds`: Execution and output bounds:
  - `max_instructions`: Instruction bound before abort (default: 50000, max: 200000).
  - `max_trace_bytes`: Maximum trace file size in bytes (default: 32MB).
  - `timeout_ms`: Subprocess execution timeout in milliseconds (default: 60000).
  - `max_expr_chars`: Inline character cap before saving expression to artifact (default: 2000).
- `synthesize`: Perform AST synthesis/simplification (default `true`).
- `lift_llvm`: Perform LLVM IR lifting (default `true`).

<examples>
```
// Check whether Triton and optional solver/LLVM features are available
triton_analyze(
  action: "status"
)

// Query AArch64 register and flag specifications
triton_analyze(
  action: "arch_info",
  arch: "aarch64"
)

// Replay AArch64 trace with concrete seed values and symbolization
triton_analyze(
  action: "replay",
  arch: "aarch64",
  trace: "artifacts/traces/aarch64_branch.trace",
  initial_registers: {
    pc: "0x401000",
    sp: "0x7ffffff0",
    x0: "0x3"
  },
  symbolic_registers: [
    { name: "x0", alias: "arg0" }
  ],
  output: { kind: "register", target: "x0" }
)

// Replay ARM32 Thumb trace
triton_analyze(
  action: "replay",
  arch: "arm32",
  thumb: true,
  trace: "artifacts/traces/arm_thumb.trace",
  initial_registers: {
    pc: "0x401000",
    sp: "0x7ffffff0",
    r0: "0x4"
  },
  symbolic_registers: [
    { name: "r0", alias: "x" }
  ],
  output: { kind: "register", target: "r0" }
)
```
</examples>
