# Salwan Execution Trace Format & Triton Replay Guide

This reference documents the Salwan execution trace format (`mr:` / `r:` / `i:`) consumed by `triton_analyze` for offline symbolic execution, taint tracking, and expression synthesis.

---

## 1. Trace Syntax Specification

The trace consists of newline-delimited ASCII records generated during dynamic execution:

| Prefix | Description | Format | Example |
| :--- | :--- | :--- | :--- |
| **`i:`** | Executed instruction | `i: <virtual_address> <disassembly_text>` | `i: 0x1400021A0 mov rax, qword ptr [rcx + 0x10]` |
| **`r:`** | Register concrete read | `r: <register_name> = <hex_value>` | `r: rdx = 0x0000000000000005` |
| **`mr:`** | Memory concrete read | `mr: <hex_address> = <hex_value>` | `mr: 0x00007ffffff0 = 0x0000000012345678` |

### Trace Sequence Invariant
Before each instruction (`i:`), any memory or register values read by that instruction that were not previously defined or computed within the trace MUST be supplied as concrete readings (`r:` or `mr:`). This allows Triton to maintain complete concrete-symbolic synchronization without requiring direct access to target process memory.

```text
r: rcx = 0x00007ffffff0
mr: 0x00007ffffff0 = 0x000000000000002a
i: 0x140001000 mov rax, qword ptr [rcx]
r: rdx = 0x0000000000000008
i: 0x140001004 add rax, rdx
i: 0x140001007 ret
```

---

## 2. Capturing Traces from Isolated Lab Environments

Execution traces MUST be captured inside an isolated laboratory environment:

### Option A: Via x64dbg Tracing (Windows Host / `native_mcp_session`)
1. In x64dbg, set breakpoints at the VM handler entry and exit.
2. Enable trace recording with register and memory logging (`Trace into` or automated script).
3. Export trace log and format into `i:`, `r:`, `mr:` records.

### Option B: Via Frida Stalker / Memory Hooks
When using Frida within an authorized sandbox:
```javascript
// Example stalker block tracing snippet
Stalker.follow(Process.getCurrentThreadId(), {
  events: { exec: true },
  onReceive: function (events) {
    // Format instruction pointer and registers into Salwan syntax
  }
});
```

---

## 3. Invoking `triton_analyze` with Captured Traces

Once the trace file is written to `./artifacts/trace.txt`:

```json
triton_analyze({
  action: "replay",
  trace: "./artifacts/trace.txt",
  arch: "x86_64",
  initial_registers: {
    "rip": "0x140001000",
    "rax": "0x0",
    "rdi": "0x1234",
    "rsi": "0x5678",
    "rsp": "0x7ffffff0",
    "rbp": "0x7ffffff8"
  },
  symbolic_registers: [
    { "name": "rdi", "alias": "input_arg1" },
    { "name": "rsi", "alias": "input_arg2" }
  ],
  output: {
    "kind": "register",
    "target": "eax"
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
- `initial_registers`: Sets concrete values for registers (e.g. stack pointer) to avoid uninitialized pointer faults during memory dereferences.
- `symbolic_registers`: Designates variables that Triton will treat as unconstrained algebraic symbols.
- `output`: The register or memory location to solve. Triton calculates the AST representing the relationship between the inputs and this output.
- `synthesize`: Directs Triton to simplify complex Mixed Boolean-Arithmetic (MBA) formulas using AST rewriting rules.
- `lift_llvm`: Emits standard LLVM IR for the symbolic expression.

---

## 4. Context Budget & Artifact Discipline

- Symbolic AST formulas for heavily virtualized handlers can exceed hundreds of kilobytes.
- `triton_analyze` automatically provides concise summaries in tool outputs and saves full AST expressions and LLVM IR into session artifacts (`artifact://...`).
- Inspect the summary preview first before requesting full artifact contents.
