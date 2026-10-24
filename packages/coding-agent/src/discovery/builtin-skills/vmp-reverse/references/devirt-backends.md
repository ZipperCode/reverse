# Devirtualization Backends Comparison & Selection Guide

This guide provides technical specifications, version compatibility, and runtime constraints for the devirtualization backends supported in `reverse`.

---

## 1. Technical Backend Comparison Matrix

| Property | `mergen` (NaC-L/Mergen) | `novmp` (can1357/NoVmp) | `triton` (`triton_analyze`) | `vmp-devirt` (Rasetsuu) |
| :--- | :--- | :--- | :--- | :--- |
| **Analysis Paradigm** | Static Function Symbolic Lifting | Static VTIL Devirtualization | Dynamic Symbolic Execution & AST Synthesis | Dynamic Emulation & Remill LLVM Lifting |
| **Target Architecture** | x86-64 PE only | x86-64 PE only | x86 (32-bit) & x86-64 | x86-64 PE |
| **VMP Version Scope** | VMP 3.4 – 3.6, 3.8.x | VMP 3.0 – 3.5 | Version-agnostic (analyzes traces) | VMP 3.9.4 experimental |
| **SMC Tolerance** | **None** (Fails on self-modifying code) | Low (Static analysis of PE image) | **High** (Replays dynamic memory writes) | **High** (Unicorn execution sensor) |
| **SEH / Interrupt Traps** | Unsupported (halts at `INT 2`) | Partial | Supported if recorded in trace | Emulated in Unicorn |
| **Floating Point Math** | Unsupported (6 integer SSE2 only) | Unsupported | Full symbolic FPU/SSE models | Full x87/SSE |
| **Primary Output** | LLVM IR (`.ll`) | VTIL representation & lifted IL | Simplified AST & synthesized formulas | Remill LLVM bitcode & replay tests |
| **Host Environment** | Windows x64 (or Docker / source build) | Windows x64 (requires AVX/x64) | Universal (macOS, Linux, Windows venv) | Linux/Windows Rust + LLVM 22 |
| **Tool in reverse** | `native_devirtualize(action: "lift", backend: "mergen")` | `native_devirtualize(action: "lift", backend: "novmp")` | `triton_analyze(action: "replay")` | External research prototype |

---

## 2. Backend Deep Dive: Mergen (`native_function_lifting`)

### Overview
Mergen translates protected x64 machine code into standard LLVM IR without relying on fixed VM handler signature matching. It performs symbolic lifting and leverages standard LLVM optimization passes (`mem2reg`, `sroa`, `dce`, `gvn`) to eliminate VM dispatcher tables, context switching overhead, and dead flag calculations.

### When to Select
- The target function has a standard x64 calling convention (SysV or MS x64 ABI).
- The binary is compiled with VMP 3.4–3.6 or 3.8.x without active self-modifying code.
- Static virtual addresses (VA) can be identified in an unpacked or dumped PE.

### Known Limitations & Failure Modes
1. **Self-Modifying Code (SMC)**: VMP 3.7+ frequently writes code bytes into memory before executing them. Mergen inspects static section bytes; if SMC is detected or assumed, lifting will produce invalid instructions or crash.
2. **Exception Dispatch (`INT 2`)**: In VMP 3.6, certain VM dispatchers use `INT 2` to trigger Structured Exception Handling (SEH) control transfer. Mergen halts when encountering unhandled interrupt traps.
3. **Indirect Control Flow**: Indirect jumps outside the analyzed function boundary or computed tail-calls cause CFG construction failures.

---

## 3. Backend Deep Dive: NoVmp (`vmp_legacy_devirtualization`)

### Overview
NoVmp is a classic static devirtualizer built on top of the VTIL (Virtual-machine Translation Intermediate Language) framework. It parses VM entry handlers in unpacked VMProtect 3.0–3.5 binaries, tracks virtual register mappings, and produces devirtualized assembly routines.

### When to Select
- The sample is known to be protected by VMProtect 3.0 through 3.5.
- The binary is already unpacked and the VM-entry RVAs are known.
- Analysis requires VTIL intermediate representations to study optimizer transformation stages.

### Known Limitations
1. **Experimental Recompilation**: Although NoVmp offers `-experimental:recompile`, output binaries require independent dynamic verification to confirm correct relocations and stack frames.
2. **Version Lock**: Ineffective against modern VMP 3.6+ multi-stage dynamic handlers.

---

## 4. Backend Deep Dive: Triton (`symbolic_trace_analysis`)

### Overview
`triton_analyze` utilizes the `triton-library` concolic symbolic execution framework. Rather than lifting an entire binary statically, it operates on captured execution traces (Salwan `mr:` / `r:` / `i:` text format).

### When to Select
- The target contains complex Mixed Boolean-Arithmetic (MBA) obfuscation (e.g. `((x & ~y) + (y & ~x))`).
- The code uses self-modifying code (SMC) or anti-analysis tricks that break static lifters.
- A single security-critical decision point (such as key verification or license check) needs to be expressed as a pure mathematical formula: `output_register = f(input_registers)`.

### Execution Discipline
- **Input / Output Specification**: Always specify concrete initial register states (e.g. stack pointer `rsp`, base pointer `rbp`) and designate explicit symbolic input registers (`symbolic_registers`) and output targets.
- **Trace Boundaries**: Bound the maximum instruction count to prevent memory exhaustion during symbolic AST expansion.
- **Path Coverage Acknowledgment**: Triton proves equivalence ONLY along the recorded execution trace. It does NOT prove that unexercised branches have identical behavior.
