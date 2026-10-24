# Lockstep Differential Verification Guide

This guide establishes the empirical verification protocol for devirtualized routines. Deobfuscation is an empirical claim: an extracted formula or lifted function remains a `[HYPOTHESIS]` until its runtime behavior is proven equivalent to the original protected binary across independent test vectors.

---

## 1. The Verification Contract

1. **Empirical Verification Over Visual Inspection**: Treat lifted LLVM IR or simplified algebraic formulas as unconfirmed hypotheses until runtime testing demonstrates semantic equivalence.
2. **Independent Dual Execution**: Execute both the original protected sample and the recovered artifact under identical test vectors and compare outputs lockstep.
3. **Sandbox Isolation**: Confine execution of the original sample to authorized laboratory environments, virtual machines, or controlled debugger sessions.

---

## 2. Five-Step Differential Testing Protocol

```
[1. Select Test Vectors] ──> Boundary, Random & Representative Inputs
           │
           ├───────────────────────────────┐
           ▼                               ▼
[2. Execute Original in Sandbox]  [3. Execute Recovered Model]
 (Frida / x64dbg / Test Harness)   (Clang-compiled IR / Triton AST)
           │                               │
           └───────────────┬───────────────┘
                           ▼
             [4. Compare Outputs & States]
              (RAX, Memory, Status Flags)
                           │
                           ▼
             [5. Record Verified Evidence]
```

### Step 1: Select Diverse Input Test Vectors
Prepare at least 10–20 test vectors spanning:
- Boundary conditions: `0x0`, `0x1`, `-1` (`0xFFFFFFFFFFFFFFFF`), maximum/minimum integer values;
- Random uniform test patterns (e.g. `0x1122334455667788`, `0xA5A5A5A5A5A5A5A5`);
- Known domain inputs (e.g. valid license key string, target hash, expected token format).

### Step 2: Record Original Ground Truth Outputs
In the isolated environment, execute the original function for each input vector:
- Hook the function entry with Frida or an automated debugger script;
- Set input registers (`RCX`, `RDX`, `R8`, `R9` or stack parameters);
- Capture return values (`RAX`), output buffer bytes, and CPU flags;
- Save the results into `./artifacts/ground_truth_vectors.json`.

### Step 3: Execute the Recovered Implementation
For LLVM IR produced by Mergen:
1. Compile the lifted IR with Clang:
   ```bash
   clang -O2 -c ./artifacts/mergen_out/lifted.ll -o ./artifacts/lifted.o
   ```
2. Link against a minimal C test driver harness:
   ```c
   // harness.c
   #include <stdio.h>
   #include <stdint.h>

   extern uint64_t lifted_func(uint64_t a, uint64_t b);

   int main() {
       uint64_t inputs[][2] = { {0, 0}, {1, 5}, {0x100, 0x200}, {0xFFFFFFFF, 1} };
       for (int i = 0; i < 4; i++) {
           printf("Input (%llx, %llx) -> Output: %llx\n",
                  inputs[i][0], inputs[i][1], lifted_func(inputs[i][0], inputs[i][1]));
       }
       return 0;
   }
   ```
3. Run the harness and record the results into `./artifacts/recovered_vectors.json`.

For AST formulas produced by Triton:
Evaluate the synthesized expression across the input vectors using Python's `eval` or Z3 solver.

### Step 4: Lockstep Comparison & Discrepancy Attribution
Compare the outputs byte-for-byte:
- **Bitwise Match (100% agreement)**: The devirtualized model correctly preserves function semantics across tested domains.
- **Mismatch Detected**: Attribute the failure:
  1. *Flag Truncation*: Did the original code rely on 32-bit register aliasing (e.g. writing `EAX` zero-extending into `RAX`) while the lifter modeled 64-bit arithmetic?
  2. *Unmodeled Memory Side-Effects*: Did the original routine write to global state or thread-local storage (TLS) that was omitted from the lifted function?
  3. *Unexplored Branch*: In trace-based analysis (Triton), did the test vector trigger a conditional branch that was not present in the captured trace?

### Step 5: Evidence Promotion
When all test vectors pass without discrepancy:
```json
evidence({
  action: "verify",
  hypothesisId: "ev_hyp_devirt_key_check",
  method: "Lockstep differential execution",
  command: "clang -O2 -c ./artifacts/mergen_out/lifted.ll -o ./artifacts/lifted.o && ./artifacts/harness",
  result: "100% agreement (20/20 test vectors) on return values and memory side effects",
  conclusion: "Confirmed: Recovered LLVM IR accurately models the original protected function semantics across all tested domains",
  subject: "vmp_key_check",
  assurance: "algorithm_recovery",
  reproducibility: "100% (20/20 runs)"
})
```
