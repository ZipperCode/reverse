# Devirtualization Backends Comparison & Selection Guide

This guide provides technical specifications, version compatibility, and runtime constraints for the devirtualization and symbolic recovery backends supported in `reverse`.

---

## 1. Technical Backend Comparison Matrix

| Property | `native_recover` | `triton` (`triton_analyze`) | `mergen` (NaC-L/Mergen) | `novmp` (can1357/NoVmp) | Research Prototypes (`vmp-devirt` / `d810g`) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Analysis Paradigm** | Bounded Multi-Path DSE Worklist & Synthesis | Dynamic Symbolic Trace Replay & AST Synthesis | Static Function Symbolic Lifting | Static VTIL Devirtualization | Dynamic Emulation / Experimental IDA decompilation |
| **Target Architecture** | x86, x86-64, ARM32, AArch64 | x86, x86-64, ARM32, AArch64 | x86-64 PE only | x86-64 PE only | Experimental x86-64 / IDA 8+ |
| **Protector Scope** | Android custom VMP, OLLVM, VMProtect handlers | Trace-based, protector-agnostic | VMP 3.4 – 3.6, 3.8.x | VMP 3.0 – 3.5 | VMP 3.9.4 experimental / D810 research fork |
| **SMC Boundary** | Executes concrete live snapshot bytes; symbolized instruction bytes remain unsupported | Replays the captured instruction bytes and state; unobserved code paths stay outside the model | No self-modifying code support | Static analysis of the supplied PE image | Experimental implementation-dependent behavior |
| **Multi-Path Exploration** | **Yes** (Z3 branch inversion under prefixes) | **No** (Replays single recorded path only) | No (Static CFG traversal) | No (Static handler graph) | Experimental |
| **Primary Output** | Guarded ITE tree, SMT2, LLVM IR, Differential Report | Simplified AST & synthesized formulas | LLVM IR (`.ll`) | VTIL representation & lifted IL | Remill LLVM bitcode / experimental AST |
| **Host Environment** | Universal (macOS, Linux, Windows venv) | Universal (macOS, Linux, Windows venv) | Windows x64 (or Docker / source build) | Windows x64 (requires AVX/x64) | Linux/Windows Rust + LLVM / IDA Pro |
| **Tool in reverse** | `native_recover` | `triton_analyze` | `native_devirtualize(backend: "mergen")` | `native_devirtualize(backend: "novmp")` | **Research-only reference** (not production catalog) |

---

## 2. Backend Deep Dive: `native_recover` (`native_path_recovery`)

### Overview
`native_recover` implements bounded multi-path Dynamic Symbolic Execution (DSE) worklist algorithms on top of the Triton symbolic engine. Starting from a concrete machine memory snapshot (`BoundedSnapshot`), it executes actual machine instructions, accumulates path predicates, systematically inverts feasible conditional branches under prefixes using the Z3 solver, discovers new execution frontiers, extracts handler transition formulas, merges path formulas into guarded ITE trees, and performs differential verification.

### When to Select
- The target is protected by custom Android/native virtual machines, control-flow flattening (OLLVM), or opaque branch predicates.
- Exploration must cover multiple execution branches from a bounded machine snapshot rather than just a single linear execution trace.
- Algorithmic handlers need to be extracted as pure symbolic transition formulas and lifted to LLVM IR.
- Rigorous differential verification (original machine snapshot vs. recovered AST/IR) is required across finite boundary and fuzz vectors.

### Operational Lifecycle:
1. `action: "explore"`: Traverses execution tree within bounded branch budgets, tracking visited edges, unexplored frontiers, and path predicates.
2. `action: "handlers"`: Analyzes explicit address ranges, extracting input/output variable dependencies and symbolic formulas without opcode heuristics.
3. `action: "merge"`: Merges path ASTs into a guarded ITE tree, proving domain coverage and absence of contradictions, and emitting LLVM IR / SMT2.
4. `action: "verify"`: Executes machine snapshot vs recovered model independently across test vectors, comparing return registers and observed memory side effects.

---

## 3. Backend Deep Dive: Triton (`symbolic_trace_analysis`)

### Overview
`triton_analyze` utilizes the `triton-library` concolic symbolic execution framework. It operates on captured execution traces (Salwan `mr:` / `r:` / `i:` colon format or structured JSONL) recorded by `instruction_trace` or debugger harnesses.

### Supported Architectures & Models:
- **x86 / x86_64**: Full 32-bit and 64-bit general purpose registers, flags, and stack semantics.
- **ARM32**: Thumb mode execution (auto-detected via odd entry addresses), CPSR condition codes.
- **AArch64**: 64-bit `x0`-`x30` registers, automatic 32-bit `Wn` zero-extension into `Xn`, zero registers (`xzr`/`wzr`), NZCV condition flags, and vector/SIMD state tracking.

### When to Select
- Simplifying complex Mixed Boolean-Arithmetic (MBA) formulas recorded from a single dynamic execution trace.
- Deobfuscating isolated arithmetic routines where an execution trace is already captured via `instruction_trace`.
- Deriving pure mathematical functions: `output = f(inputs)` along the recorded path.

### Execution Boundaries
- **Path-Local Scope**: Triton analyzes the *recorded path only*. It does not generate new test vectors or explore branches not present in the trace.

---

## 4. Backend Deep Dive: Mergen (`native_function_lifting`)

### Overview
Mergen translates protected x64 machine code into standard LLVM IR without relying on fixed VM handler signature matching. It performs symbolic lifting and leverages standard LLVM optimization passes (`mem2reg`, `sroa`, `dce`, `gvn`) to eliminate VM dispatcher tables, context switching overhead, and dead flag calculations.

### When to Select
- Target function has a standard x64 calling convention (SysV or MS x64 ABI).
- The binary is compiled with VMP 3.4–3.6 or 3.8.x without active self-modifying code.
- Static virtual addresses (VA) can be identified in an unpacked or dumped PE.

---

## 5. Backend Deep Dive: NoVmp (`vmp_legacy_devirtualization`)

### Overview
NoVmp is a classic static devirtualizer built on top of the VTIL (Virtual-machine Translation Intermediate Language) framework. It parses VM entry handlers in unpacked VMProtect 3.0–3.5 binaries, tracks virtual register mappings, and produces devirtualized assembly routines.

---

## 6. Research Prototypes (D810G & vmp-devirt)

`vmp-devirt` (Rasetsuu) and `D810G` represent external academic or experimental research prototypes:
- **`vmp-devirt`**: Dynamic emulation with Unicorn and Remill LLVM lifting. Highly experimental, requires non-standard LLVM versions, and is not integrated into production catalogs.
- **`D810G`**: overkazaf's experimental IDA microcode deobfuscation research branch. It remains a reference; production `d810-ng` integrates IDA Pro 9+ microcode through `deobfuscate(backend: "d810-ng")`.
