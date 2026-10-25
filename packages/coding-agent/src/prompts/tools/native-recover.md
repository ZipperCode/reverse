Bounded native recovery using Jonathan Salwan's Triton binary analysis framework, Z3, and LLVM/llvmlite.

Actions:
- `status`: inspect installed architectures, solvers, synthesis and LLVM support. Read approval; allowed in plan mode.
- `explore`: execute a bounded machine snapshot, invert feasible branches under their full prefixes, and return per-path predicates, output ASTs, stores and incomplete frontier. Exec approval.
- `handlers`: execute `[range.start, range.stop]`, extract the conditional output transition and its input dependencies. Exec approval. Use only completed results together with their path predicates.
- `merge`: check overlap consistency and input-domain coverage before exporting guarded SMT2 and available LLVM artifacts. Write approval.
- `verify`: compare the original snapshot against the selected candidate representation, including return values and byte-addressed memory effects. Exec approval.

Snapshot contract:
- `arch`: `x86`, `x86_64`, `arm32`, or `aarch64`; optional `thumb` selects ARM32 Thumb mode.
- `entry`, nonempty `stop_addresses`, explicit `registers`, and `segments: [{ address, bytes, permissions? }]` define the bounded machine state. Supply all state read by execution, including data and stack bytes when used.
- `symbolic_inputs`: register `{ name, alias?, seed, min?, max? }` or memory `{ kind: "memory", address, size, alias, seed, min?, max? }`. Bounds are unsigned. Use hex strings for exact machine values and addresses.
- `output`: `{ kind: "register", target }` or `{ kind: "memory", address, size }`.
- `bounds`: `branch_budget`, `max_instructions`, `max_depth`, `timeout_ms`. Retain incomplete frontier when a bound prevents exploration.

Merge contract:
- Pass `paths: [{ path_id?, predicate, output_ast, status? }]` from exploration and `inputs: [{ name, size_bits }]` with exact symbolic widths.
- Set `output_size_bits` to match the actual output AST.
- Read returned `coverage_guard`, conflicts, and full formula/IR artifacts. A generated artifact alone is not a semantic proof.

Verification contract:
- `recovered.kind`: `smt2`, `ast`, or `llvm_ir`. Supply `expression` or `llvm_ir` for that exact representation, `inputs` with bindings (`reg` or memory `kind/address/size`), and `output`.
- Optional `domain_predicate`/`domain_guard` restricts the candidate domain. Out-of-domain vectors are reported separately.
- `memory_side_effects: [{ address, size, condition?, value, else_value? }]` describes expected writes. `strict_memory_check` requests rejection of unmodeled effects.
- Supply complete `vectors` and/or deterministic `test_generation: { boundary, random_count, seed }`.
- `proof_mode`: `finite_vectors`, `smt_formal`, or `both`. Finite agreement is observation-level evidence. Formal proof uses the same strict original execution engine and must cover the declared domain.
- Inspect `formal_proof_scope`, `smt_formal_proved`, `side_effects_proved`, counterexamples and uncovered samples. `return_only` proof does not establish side-effect equivalence. Full-domain return and effect proofs can recommend `algorithm_recovery`.
- LLVM verification executes the submitted LLVM IR through bounded snapshot memory callbacks, preserving finite-vector evidence. Formal proof applies to SMT2/AST candidates; a companion formula does not prove LLVM equivalence. Unsupported native-memory/ABI contracts return explicit errors.

<examples>
```js
native_recover({ action: "status" })

native_recover({
  action: "explore",
  snapshot: {
    arch: "aarch64",
    entry: "0x1000",
    stop_addresses: ["0x1004"],
    registers: { pc: "0x1000", sp: "0x8000" },
    segments: [{ address: "0x1000", bytes: "00040091", permissions: "r-x" }],
    symbolic_inputs: [{ name: "x0", alias: "x", seed: "0x1" }],
    output: { kind: "register", target: "x0" }
  },
  bounds: { branch_budget: 4, max_depth: 4, max_instructions: 100 }
})
```
</examples>

Dependencies are discovered through the existing managed Triton environment. When missing, offer `reverse setup reverse triton --execute` or the matching TUI setup action; analysis does not install dependencies automatically.
