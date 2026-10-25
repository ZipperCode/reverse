---
name: vmp-reverse
description: VMProtect and virtualized native code analysis, process memory dumping, symbolic trace analysis, and function devirtualization workflow. Guides VM entry/dispatch identification, process memory dump and IAT reconstruction, offline Salwan execution trace recording, symbolic simplification with Triton, and function lifting via Mergen and NoVmp backends with lockstep differential verification.
metadata:
  capabilities: symbolic_trace_analysis, native_path_recovery, instruction_trace_capture, vmp_dump_repair, native_function_lifting, vmp_legacy_devirtualization
  requiresOptional: triton, tritondse, qbdi, vmpdump, mergen, novmp, radare2, x64dbg-mcp
---

# VMProtect & Virtualized Native Code Devirtualization Workflow

`vmp-reverse` is the specialized workflow skill for analyzing binaries protected by VMProtect (VMP 2.x, 3.x) and similar virtualizing protectors. It coordinates process memory dumping, Import Address Table (IAT) reconstruction, offline symbolic execution trace analysis, function-level bytecode devirtualization, and lockstep differential verification.

It operates within `reverse`'s **skill-first, tool-selective** architecture: the skill directs hypothesis formation, target triage, backend selection, and verification discipline, while dedicated tools (`vmp_dump`, `native_devirtualize`, `triton_analyze`) act as bounded, single-action executors.

For general multi-platform orchestration and evidence chains, consult `skill://reverse-lab/SKILL.md`. For standard Windows PE auditing, consult `skill://windows-reverse/SKILL.md`.

---

## 1. Operating Contract, Safety & Evidence Standards

### Target Authorization & Sandbox Isolation
- **Lab Environment Containment**: Execute protected targets exclusively within authorized laboratory environments, isolated virtual machines, or disposable container sandboxes to maintain host safety against aggressive anti-debugging and system hooks.
- **Authorized Audit Scopes**: Restrict analysis to user-owned, authorized, or licensed sample binaries.
- **Sample Integrity & Artifact Isolation**: Retain original sample binaries in their unmodified read-only state. Store all memory dumps, lifted LLVM IR (`.ll`), VTIL files, traces, and differential test harnesses under dedicated `./artifacts/` subdirectories.

### Concrete Coordinates & Affirmative Evidence Standards
- **Entropy as Packing Indicator**: Record Shannon entropy (> 7.2 bits/byte) and non-standard section names (`.vmp0`, `.vmp1`) as general packing indicators; confirm specific VMP versions and compilation modes through entrypoint instructions and VM dispatcher analysis.
- **Coordinate Discipline**: Disambiguate binary coordinates by explicitly distinguishing:
  - File Offset (physical byte offset in the on-disk PE image);
  - Relative Virtual Address (RVA, offset from module base);
  - Virtual Address (VA, absolute address based on `ImageBase`).
  Explicitly record the original image base (e.g. `0x140000000`) and runtime module base to maintain coordinate alignment across ASLR-relocated runs.
- **Dump Role**: Treat VMPDump memory dumping and IAT reconstruction as stage preparation that restores executable headers and imports for static analysis; follow up with function lifting or symbolic analysis to recover virtualized bytecode semantics.
- **Trace Coverage Scope**: Treat offline trace replay with Triton as recovering semantics along the specifically executed trace paths; state unexercised branches and alternatives as unconfirmed hypotheses.
- **Backend Suitability & Boundaries**:
  - **Mergen**: Applies to standard calling convention x64 PE functions without self-modifying code (SMC). Note that VMP 3.6 functions utilizing `INT 2` structured exception handling represent best-effort lifting targets.
  - **NoVmp**: Applies to unpacked legacy VMProtect 3.0–3.5 x64 targets with known VM entry RVAs.
  - **Triton**: Operates via Python `triton-library` (Jonathan Salwan / Quarkslab symbolic execution engine, distinct from NVIDIA Triton).
  - **Host Platform Realism**: Offline Triton symbolic execution is supported on configured and managed Python runtimes (with source-build prerequisites on macOS darwin arm64 such as CMake, Ninja, and Z3, and Linux/Windows environments with triton-library). Precompiled Windows x64 binaries (`vmpdump.exe`, `lifter-windows-iced.exe`, `NoVmp.exe`) require a Windows host; on non-Windows platforms, report availability accurately and proceed with offline trace analysis via `triton_analyze` or conduct Windows-specific dynamic steps in an authorized virtual machine.
  - **Empirical Verification**: Validate all lifted or synthesized logic through lockstep differential testing comparing original execution against the recovered model.

### Dependency Guidance & Selective Prompting
- When an optional tool is absent, prompt the operator ONLY for the tool required by the selected task and backend (e.g. prompt for `vmpdump` only when attempting a process dump, `mergen` only when lifting an x64 PE function, `novmp` only for legacy VMP 3.0–3.5 routines, or `triton` for trace replay or bounded path recovery).
- When the required tool is already present, proceed silently without prompts.

---

## 2. Six Method Capabilities & Catalog Mapping

`vmp-reverse` routes tasks across six distinct method capabilities:

| Capability ID | Purpose & Scenario | Tool Name & Backend | Catalog Tool ID | Trusted Setup Command | Fallback Tier |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`vmp_dump_repair`** | Dump running x64 PE process past OEP & rebuild IAT on Windows | `vmp_dump` | `vmpdump` | `reverse setup reverse vmpdump --execute` | Debugger memory dump via `native_mcp_session` (x64dbg) or Scylla; manual import fix |
| **`native_function_lifting`** | Lift single x64 PE function to LLVM IR (`.ll`) for deobfuscation | `native_devirtualize(action: "lift", backend: "mergen")` | `mergen` | `reverse setup reverse mergen --execute` | Symbolic trace replay (`triton_analyze`) or static disassembly via `r2_inspect` / IDA |
| **`vmp_legacy_devirtualization`** | Static devirtualization of unpacked VMP 3.0–3.5 x64 routines into VTIL | `native_devirtualize(action: "lift", backend: "novmp")` | `novmp` | `reverse setup reverse novmp --execute` | `native_function_lifting` (Mergen) or `symbolic_trace_analysis` (Triton) |
| **`instruction_trace_capture`** | Capture bounded execution traces with synchronized register and memory access | `instruction_trace` | `qbdi` | `reverse setup reverse qbdi --execute` | Dynamic hook via `frida` / `frida_session` or debugger stepping |
| **`symbolic_trace_analysis`** | Dynamic concolic replay of execution traces across x86/x64/ARM32/AArch64, MBA simplification, LLVM IR | `triton_analyze(action: "replay")` | `triton` | `reverse setup reverse triton --execute` | Static pattern deobfuscation with `r2_inspect` or IDA Pro |
| **`native_path_recovery`** | Bounded multi-path DSE exploration, handler extraction, guarded ITE merge, and differential verification | `native_recover` | `triton` | `reverse setup reverse triton --execute` | Single-path replay (`triton_analyze`) or static disassembly via `r2_inspect` |
---

## 3. Tool Invocations & Actual Schemas

### 1. `vmp_dump` (Process Memory Dump & IAT Reconstruction)
Used on Windows x64 after dynamic execution has reached the Original Entry Point (OEP).

- **Status Check**:
  ```json
  vmp_dump({ action: "status" })
  ```
- **Dump Invocation**:
  ```json
  vmp_dump({
    action: "dump",
    pid: 4128,
    module_path: "C:\\targets\\protected_app.exe",
    observed_oep: true,
    entry_point: "0x1000",
    output_path: "./artifacts/dumped_app.exe"
  })
  ```
  - `pid`: Process identifier (decimal or hex string, required for dump).
  - `module_path`: Path to target module on disk (required for dump).
  - `process_image_path`: Optional path to host process executable on disk if dumping a secondary DLL (defaults to `module_path` for main image).
  - `module`: Optional target module name (e.g. `"target.dll"`, defaults to `""` for main image).
  - `observed_oep`: Boolean gate (MUST be `true`, required for dump). Acknowledges that the operator or debugger has verified execution is past the protector unpacking loop at the real OEP.
  - `entry_point`: Optional OEP RVA in hex form (e.g. `"0x1000"`).
  - `disable_reloc`: Optional boolean to mark relocations as stripped in output PE headers.
  - Output artifacts: Dumped PE file saved to `dumpedPath` with calculated SHA-256 and rebuild status.

### 2. `native_devirtualize` (Function Lifting via Mergen or NoVmp)
Used on an unpacked PE binary to lift virtualized functions into structured compiler IR.

- **Status Check**:
  ```json
  native_devirtualize({ action: "status", backend: "mergen" })
  native_devirtualize({ action: "status", backend: "novmp" })
  ```
- **Backend: `mergen` (LLVM IR Lifting for VMP 3.4–3.6 / 3.8.x)**:
  ```json
  native_devirtualize({
    action: "lift",
    backend: "mergen",
    path: "./artifacts/dumped_app.exe",
    start_address: "0x1400021A0",
    output_dir: "./artifacts/mergen_out"
  })
  ```
  - `action`: `"lift"`.
  - `start_address`: Virtual Address (VA) of the target function to lift (e.g. `"0x1400021A0"`, required for Mergen).
  - Produces: LLVM IR file (`.ll`), diagnostics, and stage logs.
  - Scope guidance: If the function contains SMC or SEH dispatch, Mergen will indicate an interruption or halt at `INT 2`; record this evidence and transition to `triton_analyze`.
- **Backend: `novmp` (VTIL Lifting for VMP 3.0–3.5)**:
  ```json
  native_devirtualize({
    action: "lift",
    backend: "novmp",
    path: "./artifacts/dumped_app.exe",
    vms: ["0x12050"],
    image_base: "0x140000000",
    output_dir: "./artifacts/novmp_out"
  })
  ```
  - `action`: `"lift"`.
  - `vms`: Array of VM-entry RVAs (e.g. `["0x12050"]`, targeted list recommended).
  - `image_base`: Optional override image base address.
  - Produces: VTIL intermediate language files and devirtualized assembly logs in `output_dir`.

### 3. `triton_analyze` (Symbolic Execution & Trace Simplification)
Used to analyze instruction traces of VM handlers or obfuscated routines using Salwan `mr:` / `r:` / `i:` trace syntax.

- **Status Check**:
  ```json
  triton_analyze({ action: "status" })
  ```
- **Replay & Symbolic Simplification**:
  ```json
  triton_analyze({
    action: "replay",
    trace: "./artifacts/trace_key_check.txt",
    arch: "x86_64",
    initial_registers: {
      "rip": "0x140001000",
      "rax": "0x0",
      "rdi": "0x1234",
      "rsi": "0x5678",
      "rsp": "0x7ffffff0"
    },
    symbolic_registers: [
      { "name": "rdi", "alias": "input_key1" },
      { "name": "rsi", "alias": "input_key2" }
    ],
    output: { "kind": "register", "target": "eax" },
    synthesize: true,
    lift_llvm: true
  })
  ```
  - `trace`: Path to recorded execution trace file containing concrete memory reads (`mr:`), register reads (`r:`), and instructions (`i:`).
  - `initial_registers`: Concrete register seed values before trace execution.
  - `symbolic_registers`: Registers designated as symbolic variables for algebraic tracking.
  - `output`: Object identifying the evaluation target: register object `{ kind: "register", target: "eax" }` or memory object `{ kind: "memory", address: "0x140003000", size: 4 }`.
  - Produces: Simplified AST formula, synthesized algebraic expression artifact (`synth_expr_artifact_id`), and optional LLVM IR (`llvm_ir_artifact_id`).

### 4. `instruction_trace` (Controlled Dynamic Tracing)
Used to record synchronized instruction sequences, register values, and memory reads into JSONL or Salwan trace formats.

- **Status Check**:
  ```json
  instruction_trace({ action: "status" })
  ```
- **Capture Invocation**:
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
    output_path: "./artifacts/trace_target.jsonl"
  })
  ```
  - Produces: Trace file (`.jsonl` or `.txt`) and companion sidecar `.manifest.json` with `memory_reads_complete: true` and `replay_handoff` for `triton_analyze`.

### 5. `native_recover` (Bounded DSE Exploration, Handler Extraction & Differential Verification)
Used for multi-path bounded DSE analysis on concrete machine snapshots (`BoundedSnapshot`).

- **Status Check**:
  ```json
  native_recover({ action: "status" })
  ```
- **Explore Bounded Paths**:
  ```json
  native_recover({
    action: "explore",
    snapshot: {
      arch: "aarch64",
      entry: "0x1000",
      stop_addresses: ["0x1004"],
      registers: { pc: "0x1000", sp: "0x8000" },
      segments: [{ address: "0x1000", bytes: "00040091", permissions: "r-x" }],
      symbolic_inputs: [{ name: "x0", alias: "x", seed: "0x0" }],
      output: { kind: "register", target: "x0" }
    },
    bounds: { branch_budget: 4, max_depth: 4, max_instructions: 100 }
  })
  ```
- **Extract Handler Semantics**:
  ```json
  native_recover({
    action: "handlers",
    snapshot: {
      arch: "aarch64",
      entry: "0x1000",
      stop_addresses: ["0x1004"],
      registers: { pc: "0x1000", sp: "0x8000" },
      segments: [{ address: "0x1000", bytes: "00040091", permissions: "r-x" }],
      symbolic_inputs: [{ name: "x0", alias: "x", seed: "0x0" }],
      output: { kind: "register", target: "x0" }
    },
    range: { start: "0x1000", stop: "0x1004" },
    inputs: [{ name: "x0", alias: "x", seed: "0x0" }],
    output: { kind: "register", target: "x0" }
  })
  ```
- **Merge Paths into Guarded ITE Tree**:
  ```json
  native_recover({
    action: "merge",
    paths: [
      { path_id: 0, status: "completed", predicate: "(= x 0)", output_ast: "x" },
      { path_id: 1, status: "completed", predicate: "(not (= x 0))", output_ast: "(bvadd x (_ bv1 64))" }
    ],
    inputs: [{ name: "x", size_bits: 64 }],
    output_size_bits: 64
  })
  ```
- **Differential Verification**:
  ```json
  native_recover({
    action: "verify",
    snapshot: {
      arch: "aarch64",
      entry: "0x1000",
      stop_addresses: ["0x1004"],
      registers: { pc: "0x1000", sp: "0x8000" },
      segments: [{ address: "0x1000", bytes: "00040091", permissions: "r-x" }],
      symbolic_inputs: [{ name: "x0", alias: "x", seed: "0x0" }],
      output: { kind: "register", target: "x0" }
    },
    recovered: {
      kind: "smt2",
      expression: "(bvadd x (_ bv1 64))",
      inputs: [{ name: "x", size_bits: 64, reg: "x0" }],
      output: { kind: "register", target: "x0" },
      strict_memory_check: true
    },
    vectors: [{ x: "0x0" }, { x: "0xa" }, { x: "0xffffffffffffffff" }],
    test_generation: { boundary: true, random_count: 8, seed: 42 },
    proof_mode: "both"
  })
  ```

*(For full multi-path branching, ARM32 handler extraction and domain merge workflows, consult `docs/tools/native_recover.md`.)*
## 4. End-to-End Recommended Workflow

```
[1. Triage & VM Entry Detection] ──> triage / r2_inspect
               │
               ▼
[2. OEP Breakpoint & Process Dump] ──> vmp_dump(action: "dump", observed_oep: true)
               │
               ▼
[3. Trace Capture or Memory Dump]
       ├─────────────────────────────────┬─────────────────────────────────┐
       ▼ (Windows Running PE)            ▼ (Controlled Function Tracing)   ▼ (Static Dump/Snapshot)
[vmp_dump: dump OEP]              [instruction_trace: capture]      [triage / r2_inspect]
       │                                 │                                 │
       ▼                                 ▼                                 ▼
[4. Analysis & Devirtualization Backend]
       ├─────────────────────────────────┬─────────────────────────────────┤
       ▼ (Clean x64 Function)            ▼ (Single-Path Trace MBA)         ▼ (Multi-Path Bounded DSE)
[native_devirtualize: mergen]     [triton_analyze: replay]          [native_recover: explore/handlers]
       │                                 │                                 │
       └─────────────────────────────────┴─────────────────────────────────┘
                                         │
                                         ▼
[5. Guarded Merge & Differential Verify] ──> native_recover(action: "merge" / "verify")
                                         │
                                         ▼
[6. Evidence Ledger Confirmation] ───────> evidence(action: "verify", ...)
```

### Phase 1: Triage & VM Entry Identification
1. Run `triage(path: "sample.exe")` to inspect architecture (x86 vs x64), section names (`.vmp0`, `.vmp1`), and entropy distribution.
2. In disassembler (`r2_inspect` or IDA): Locate VM entry stubs. Standard VMP entry sequence:
   ```asm
   push    <relocated_key_or_bytecode_ptr>
   call    vm_entry_dispatcher
   ```
   Record the VM entry RVA and target function address in Evidence Ledger.

### Phase 2: Dynamic Execution to OEP & Memory Dumping
1. Under an isolated Windows debugger (`native_mcp_session` with x64dbg):
   - Set a hardware breakpoint or memory breakpoint on the `.text` section or suspect OEP.
   - Run the process until unpacking completes and execution reaches the unvirtualized original code entry point.
2. Resolve capability:
   ```json
   reverse_capability({ action: "resolve", capability: "vmp_dump_repair" })
   ```
   If `vmpdump` is missing, prompt the operator with `reverse setup reverse vmpdump --execute`.
3. Invoke `vmp_dump` to create an IAT-repaired PE image in `./artifacts/`:
   ```json
   vmp_dump({
     action: "dump",
     pid: <pid>,
     module_path: "<target_module_path>",
     observed_oep: true,
     output_path: "./artifacts/unpacked_target.exe"
   })
   ```

### Phase 3: Function Lifting & Simplification
Select the appropriate backend based on the target function's characteristics:
- **Clean x64 Function without SMC (VMP 3.4–3.6 / 3.8.x)**:
  Resolve `native_function_lifting`, then run `native_devirtualize` with backend `"mergen"` and `action: "lift"`. Inspect the resulting LLVM IR (`.ll`). Run standard LLVM optimization passes (`opt -O2` or SROA/DCE/GVN) to simplify VM interpreter dispatch tables into direct computations.
- **Legacy VMProtect 3.0–3.5 with known VM Entry**:
  Resolve `vmp_legacy_devirtualization`, then run `native_devirtualize` with backend `"novmp"` and `action: "lift"`. Inspect the resulting VTIL representation.
- **Trace-Based Semantic Analysis / Mixed Obfuscation**:
  When analyzing self-modifying code, complex indirect branches, or isolated handlers:
  1. Record an instruction execution trace from the isolated debugger or Frida session in Salwan format (`mr:`, `r:`, `i:`).
  2. Resolve `symbolic_trace_analysis` and run `triton_analyze` with `synthesize: true` and `lift_llvm: true`.
  3. Extract simplified mathematical formulas (e.g. simplifying Mixed Boolean-Arithmetic expressions like `(x ^ y) + 2 * (x & y)` into `x + y`).

### Phase 4: Lockstep Differential Verification
Establish certainty by testing functional equivalence:
1. **Prepare Independent Input Vectors**: Generate a set of representative inputs (boundary values, random numbers, known good keys).
2. **Execute Original Binary**: Run the original function in the isolated VM/debugger and record the exact outputs and side effects (register values, memory writes).
3. **Execute Recovered Model**: Compile the lifted LLVM IR or evaluate the simplified Triton AST against the exact same test vectors.
4. **Compare Outputs**: Confirm 100% agreement on all test vectors. If discrepancies exist, identify whether unexecuted trace branches or unmodeled memory accesses caused the mismatch.
5. Read `skill://vmp-reverse/references/differential-verification.md` for full test harness templates.

### Phase 5: Empirical Evidence Ledger Recording
Record findings through the structured empirical evidence chain:
```json
// 1. Record observed trace facts
evidence({
  action: "add",
  kind: "fact",
  target: "sample.exe",
  sourceTool: "triton_analyze",
  locator: "sub_1400021A0+0x42",
  content: "Triton trace replay indicates output rax evaluates to (input_key ^ 0x5A5A) == 0x1234 along replayed path",
  subject: "vmp_key_check",
  assurance: "algorithm_recovery"
})

// 2. Formulate verification hypothesis
evidence({
  action: "add",
  kind: "hypothesis",
  target: "sample.exe",
  claim: "Devirtualized formula accurately models key check across all input keys",
  verificationPlan: "Run 20 independent test vectors through original binary in sandbox and compare against recovered formula",
  subject: "vmp_key_check"
})

// 3. Establish verified conclusion
evidence({
  action: "verify",
  hypothesisId: "ev_hyp_018f...",
  method: "Lockstep differential execution",
  command: "clang -O2 -c lifted.ll -o lifted.o && ./harness",
  result: "100% agreement (20/20 test vectors) on return values and memory side effects",
  conclusion: "Confirmed: Recovered LLVM IR accurately models the original protected function semantics across all tested domains",
  subject: "vmp_key_check",
  assurance: "algorithm_recovery",
  reproducibility: "100% (20/20 runs)"
})
```

---

## 5. Domain Dispatch & Skill Routing Rules

To preserve clean skill boundaries:
- **General Windows PE Triage & Win32 APIs**: Route to `windows-reverse`.
- **General Native ELF / Mach-O / Non-Virtualized PE**: Route to `native-binary-reverse`.
- **Protected by VMProtect or Virtualized Handlers**: Route to `vmp-reverse`.
- **Multi-Platform Orchestration & Fallbacks**: Governed by `reverse-lab`.

---

## 6. References

- `skill://vmp-reverse/references/devirt-backends.md`: Technical comparison matrix of Mergen vs NoVmp vs Triton vs vmp-devirt.
- `skill://vmp-reverse/references/vmp-trace-format.md`: Salwan execution trace format reference and recording guidelines.
- `skill://vmp-reverse/references/differential-verification.md`: Differential verification methodology, test vectors, and lockstep execution discipline.
