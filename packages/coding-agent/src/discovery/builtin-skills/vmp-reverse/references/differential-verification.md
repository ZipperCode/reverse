# Differential Verification: Bounded Snapshots and Proof Scope

## Execution contract

Use `native_recover(action: "verify")` to execute the original bounded machine snapshot and the selected recovered representation independently. Original execution shares the strict snapshot engine used by `explore` and `handlers`; candidate SMT/AST is evaluated with Z3 and candidate LLVM is executed as submitted when its ABI and memory contract are supported.

Preserve exact machine state: instruction bytes, data bytes, initial registers, symbolic bindings, explicit stopping addresses and unsigned input bounds. Missing state, instruction faults and paths that never reach a declared stop are failed or incomplete executions.

## Complete example

This AArch64 snapshot executes `add x0, x0, #1` and stops immediately after that instruction. The modeled return is a 64-bit modular addition with no memory writes.

```js
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

For memory effects, supply `memory_side_effects: [{ address, size, condition?, value, else_value? }]`. Compare the final written bytes bidirectionally: return values, extra and missing stores, write widths, overlapping writes and stored values are separate obligations. Preserve the entire observed effect set in the report.

For recovered formulas valid only on a subset, pass `recovered.domain_predicate` or `domain_guard` using the declared bitvector widths. `out_of_domain_vectors` records excluded vectors. Use unsigned bitvector comparisons for unsigned machine bounds.

## Proof levels

| Result | Meaning | Evidence recommendation |
|---|---|---|
| Finite vector agreement | Original and candidate agree on the tested inputs and effects | `dynamic_call_observation` |
| Formal return-only proof | Return formulas agree across the modeled domain; effects remain a separate obligation | Retain explicit `return_only` scope |
| Full modeled-domain proof | Complete original path coverage, return equivalence and side-effect equivalence are established | `algorithm_recovery` |
| Counterexample or incomplete execution | A mismatch, fault, uncovered input, unsupported boundary or solver-unknown remains | Preserve unverified status and the concrete remaining obligation |

Inspect `formal_proof_scope`, `smt_formal_proved`, `side_effects_proved`, `counterexamples` and `uncovered_domain_sample`. Finite vectors never establish universal equivalence. LLVM verification executes the exact submitted IR through bounded snapshot memory callbacks and retains observation-level evidence; a companion SMT formula does not establish formal equivalence for that LLVM artifact.

## Recovery decisions

- Return mismatch: inspect widths, sign/zero extension, branch predicates and modular arithmetic.
- Missing or extra stores: declare and reproduce the complete modified byte ranges; rerun against the original snapshot.
- Uncovered branch combinations: increase the explicit exploration budget or choose additional concrete seeds, retaining the remaining frontier.
- External call or runtime boundary: supply a reproducible bounded environment or narrow the verified claim to a self-contained region.
- Uninitialized state: capture the missing register or memory bytes before rerunning the same experiment.

Record the sample hash, snapshot, exact candidate artifact, input domain, generated-vector seed, tested-vector count, effects, proof scope and remaining obligations in the existing evidence workflow. Promote only the verified scope.
