# Salwan Execution Trace Format, Instruction Tracing & Triton Replay Guide

This reference documents the Salwan colon execution trace format (`mr:` / `r:` / `i:`) and the structured JSONL trace format consumed by `triton_analyze` and `native_recover` for offline symbolic execution, taint tracking, expression synthesis, and bounded path recovery.

---

## 1. Trace Syntax Specification

A valid symbolic trace consists of newline-delimited ASCII or JSONL records generated during dynamic execution. Both formats are parsed deterministically by `triton_analyze` and `native_recover`.

### Format A: Salwan Colon-Separated Format

| Prefix | Description | Format | Example |
| :--- | :--- | :--- | :--- |
| **`i:`** | Executed instruction | `i:<addr>:<size>:<bytes_hex>:<disasm>` | `i:0x140001000:3:488b01:mov rax, qword ptr [rcx]` |
| **`r:`** | Register concrete read | `r:<reg>=<val>[:<reg>=<val>...]` | `r:rcx=0x00007ffffff0:rdx=0x0000000000000005` |
| **`mr:`** | Memory concrete read | `mr:<addr>:<size>:<data>` | `mr:0x7ffffff0:8:0x2a` |

#### Trace Sequence Invariant
Before each instruction (`i:`), any memory location or register read by that instruction that was not previously initialized or computed within the trace MUST be supplied as a concrete reading (`r:` or `mr:`). This allows Triton to maintain complete concrete-symbolic synchronization without requiring direct access to target process memory.

```text
r:rcx=0x7ffffff0:rdx=0x5
mr:0x7ffffff0:8:0x2a
i:0x140001000:3:488b01:mov rax, qword ptr [rcx]
i:0x140001003:3:4801d0:add rax, rdx
i:0x140001006:1:c3:ret
```

### Format B: Structured JSONL Format

JSONL records represent discrete telemetry events. Register names MUST be strictly lowercase (e.g. `rax`, `rcx`, `r0`-`r12`, `x0`-`x30`, `sp`, `pc`, `nzcv`, `cpsr`).

```jsonl
{"type": "registers", "values": {"rcx": "0x7ffffff0", "rdx": "0x5"}}
{"type": "memory_read", "address": "0x7ffffff0", "size": 8, "value": "0x2a"}
{"type": "instruction", "address": "0x140001000", "bytes": "488b01", "size": 3, "disasm": "mov rax, qword ptr [rcx]"}
{"type": "instruction", "address": "0x140001003", "bytes": "4801d0", "size": 3, "disasm": "add rax, rdx"}
{"type": "instruction", "address": "0x140001006", "bytes": "c3", "size": 1, "disasm": "ret"}
```

---

## 2. Capturing Traces with `instruction_trace`

Execution traces MUST be captured in an authorized laboratory environment using controlled tracing facilities.

### Why Placeholder Stalker `events: { exec: true }` Is Insufficient
Basic Frida Stalker execution events (`Stalker.follow(..., { events: { exec: true } })`) record only instruction entry addresses. They completely omit:
1. Concrete register states prior to instruction execution;
2. Dynamic memory reads (`mr:`) required when instructions dereference memory pointers.

Without synchronized pre-instruction register and memory states, symbolic execution engines cannot resolve memory dereferences or validate concrete pointers, resulting in incomplete models or execution faults.

### Capturing via `instruction_trace`
Use the built-in `instruction_trace` tool to capture instruction traces with synchronized memory and register states via upstream QBDI bindings or Frida session supervisors:

```json
instruction_trace({
  action: "capture",
  process: "target_process",
  scope: "function",
  module: "libtarget.so",
  function: "vm_dispatcher",
  engine: "auto",
  format: "jsonl",
  max_instructions: 20000,
  timeout_ms: 30000,
  max_bytes: 33554432,
  output_path: "./artifacts/trace_vm_dispatcher.jsonl"
})
```

#### Companion Manifest Sidecar (`<trace>.manifest.json`)
Every captured trace produces a companion manifest sidecar containing:
- Target architecture (`x86`, `x86_64`, `arm32`, `aarch64`);
- Target PID, device, and process identifier;
- Module base address, mapped size, and SHA-256 hash;
- Total instruction count and truncation/completion reason;
- `memory_reads_complete`: boolean flag confirming whether pre-instruction memory accesses were captured;
- `replay_handoff`: `{ tool, valid, notice?, params }`; invoke `triton_analyze(replay_handoff.params)` when valid. `native_recover` separately requires an explicit bounded memory snapshot.

---

## 3. Instruction Capture Completeness vs. Replay vs. Recovery

Understanding the boundaries of each analytical stage is critical for valid evidence:

```
[Dynamic Target] ──> instruction_trace (capture) ──> Synchronized JSONL / Salwan Trace
                           │
         ┌─────────────────┴─────────────────┐
         ▼                                   ▼
[Single-Path Replay]               [Bounded Multi-Path Recovery]
 (triton_analyze)                   (native_recover)
 - Trace-local replay               - Triton DSE worklist
 - Single executed path AST         - Prefix branch inversion via Z3
 - Path-specific MBA synthesis      - Edge frontier & coverage tracking
 - Path-predicate output formula    - Guarded ITE merge & SMT2/LLVM IR
                                    - Differential verify vs machine bytes
```

### 1. Instruction Capture Completeness
A trace is complete only if every register read and memory read is captured before the reading instruction executes. If `memory_reads_complete` is `false`, the trace represents an execution skeleton rather than a full symbolic replay input.

### 2. Trace-Local Replay (`triton_analyze`)
`triton_analyze` operates on a recorded execution trace.
- **Scope**: Replays instructions along the single executed path recorded in the trace.
- **Simplification**: Simplifies Mixed Boolean-Arithmetic (MBA) formulas along that path using Triton's AST rewriting rules and Z3.
- **Boundary**: Proves equivalence **only along the captured execution path**. It does NOT prove totality or cover alternate branches not exercised in that dynamic run.

### 3. Bounded Multi-Path Recovery (`native_recover`)
`native_recover` operates on a bounded machine memory snapshot (`BoundedSnapshot`).
- **Scope**: Implements Triton Dynamic Symbolic Execution (DSE) worklist algorithms to systematically explore multiple feasible execution paths.
- **Branch Inversion**: Evaluates path constraints under prefix branch conditions using Z3 solver to generate new concrete input seeds and discover previously unvisited branches.
- **Handler Synthesis**: Extracts symbolic transition formulas and sliced data dependencies for explicit address ranges.
- **Guarded Merge**: Merges multiple path ASTs under mutually exclusive path predicates into a unified guarded ITE tree, checking consistency across overlapping domains, proving domain coverage, and lifting to LLVM IR and SMT2.
- **Differential Verification**: Executes the original machine snapshot independently against the recovered artifact across boundary and random vectors, comparing return registers and observed memory writes.

---

## 4. Invoking `triton_analyze` with Captured Traces

Once the trace file and manifest are written to `./artifacts/`:

```json
triton_analyze({
  action: "replay",
  trace: "./artifacts/trace_vm_dispatcher.jsonl",
  arch: "aarch64",
  initial_registers: {
    "x0": "0x1000",
    "x1": "0x2000",
    "sp": "0x7ffffff0"
  },
  symbolic_registers: [
    { "name": "x0", "alias": "input_arg0" },
    { "name": "x1", "alias": "input_arg1" }
  ],
  output: {
    "kind": "register",
    "target": "x0"
  },
  synthesize: true,
  lift_llvm: true,
  bounds: {
    "max_instructions": 50000,
    "timeout_ms": 30000
  }
})
```

### Key Parameters:
- `arch`: Target CPU architecture (`x86`, `x86_64`, `arm32`, `aarch64`). In `aarch64`, Wn registers zero-extend to Xn and `xzr`/`wzr` zero registers are handled natively.
- `thumb`: Boolean flag for ARM32; automatically enabled if the entry address has an odd least-significant bit.
- `initial_registers`: Sets concrete values for base registers (e.g. stack pointer `sp`) to avoid uninitialized pointer dereference faults.
- `symbolic_registers`: Designates variables that Triton will treat as unconstrained algebraic symbols.
- `output`: Register target `{ kind: "register", target: "x0" }` or memory target `{ kind: "memory", address: "0x140003000", size: 4 }`.
- `synthesize`: Directs Triton to simplify complex Mixed Boolean-Arithmetic (MBA) formulas using AST rewriting rules.
- `lift_llvm`: Emits standard LLVM IR for the symbolic expression.

---

## 5. Context Budget & Artifact Discipline

- Symbolic AST formulas and LLVM IR for virtualized handlers can exceed hundreds of kilobytes.
- `triton_analyze` and `native_recover` emit concise summaries in stdout and write full AST expressions, SMT2 models, and LLVM IR to session artifacts (`./artifacts/...`).
- Always inspect summary metrics (complexity reduction, visited edges, domain coverage) before requesting complete artifact content.
