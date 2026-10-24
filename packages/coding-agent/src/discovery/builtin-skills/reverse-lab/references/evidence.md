# Evidence Chain & Scientific Verification Guide

In `reverse`, reverse engineering claims MUST rest on empirical proof. This reference establishes the standard for separating observable facts from working hypotheses, documenting evidence chains, and formatting proof artifacts.

---

## 1. Tri-Part Separation: Fact vs. Hypothesis vs. Conclusion

Every analytical observation and report in `reverse-lab` must maintain unambiguous distinction across three stages:

```
┌────────────────────────────────────────────────────────────────────────┐
│ [FACT]       Empirical Ground Truth (unambiguous, reproducible)         │
│   │                                                                    │
│   ▼                                                                    │
│ [HYPOTHESIS] Inferred Mechanism / Suspected Logic (requires test)     │
│   │                                                                    │
│   ▼                                                                    │
│ [CONCLUSION] Confirmed Deduction (backed by experimental proof)        │
└────────────────────────────────────────────────────────────────────────┘
```

### 1. [FACT] (事实 - Empirical Observation)
A Fact is raw data observed directly from the tool, binary, or network traffic.
- **Requirements**: MUST cite exact location (file path, SHA-256 hash, function symbol, virtual address / RVA, line number, or packet sequence ID).
- **Example**:
  - `[FACT]` `Sample SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
  - `[FACT]` `Function sub_14001A240 decompiled at line 42 compares local_var_8 against integer constant 0x539.`
  - `[FACT]` `APK AndroidManifest.xml line 18 declares android:debuggable="false".`

### 2. [HYPOTHESIS] (假设 - Inferred Mechanism)
A Hypothesis is an interpretation or prediction derived from facts that has not yet been experimentally confirmed.
- **Requirements**: MUST state the suspected logic and an actionable, falsifiable verification method.
- **Example**:
  - `[HYPOTHESIS]` `sub_14001A240 validates license key length; returning 1 from this function will bypass the startup license dialog.`
  - `[HYPOTHESIS]` `The HTTP POST /api/v2/auth payload signature uses HMAC-SHA256 with the hard-coded key located at string offset 0x38A0.`

### 3. [CONCLUSION] (铁证结论 - Verified Result)
A Conclusion is a confirmed finding proven through dynamic observation, breakpoint hit, memory mutation, or functional test.
- **Requirements**: MUST reference the specific experiment that verified the hypothesis and cite the observed outcome.
- **Example**:
  - `[CONCLUSION]` `Confirmed: Hooking sub_14001A240 with Frida to return 1 allowed application launch without license prompt (Test Artifact: frida_bypass_log.txt).`
  - `[CONCLUSION]` `Confirmed: Replaying POST /api/v2/auth with generated HMAC-SHA256 signature produced HTTP 200 OK with valid JWT session token.`

---

## 2. Evidence Standards & Verification Guardrails

### Mandatory Evidence Standards
1. **Verbatim Citation**: Quote exact assembly mnemonics, decompiled expressions, or network bytes directly as emitted by analysis tools.
2. **Reproducible Coordinates**: Anchor every finding to concrete file paths, virtual addresses (RVA/File offset), exported symbol names, or line numbers.
3. **Deterministic Verification**: Ensure experiments are repeatable by documenting the exact command, test script, or payload parameters.

### Ground Truth Guardrails
- **Calling Conventions**: Derive calling conventions from call-site disassembly, register usage, and stack teardown (`ret 0x0c` vs `ret`).
- **Cryptographic Primitives**: Confirm algorithm identification through verified S-box constants, round keys, or platform crypto API imports (`CryptEncrypt`, `BCryptEncrypt`, `Cipher.getInstance`).
- **Bypass Verification**: Confirm bypass claims through observable execution deltas (e.g. process behavior changes, logcat trace, successful network handshake).
- **Zero-Change Control**: Never evaluate patches without a baseline control. Pass the unmodified original binary through the identical repackaging/signing pipeline; confirm that this baseline reproduces original behavior and installs cleanly before testing semantic modifications. Combine this control run with entry diffing (`apk_artifact(action: "diff")` or `binary_diff`) and register derivative lineage with exact original and output SHA-256 hashes.
- **Four-Level Verification Hierarchy**:
  1. *Static Validation*: Structural validity of headers, Adler32/SHA-1 checksums, instruction boundaries, and ZIP entry alignments (including 16KiB page alignment for native `.so`).
  2. *Signed Artifact Verification*: Cryptographic validity of signature schemes (v1-v3) via `apksigner verify`.
  3. *Install & Launch Verification*: Successful non-root deployment and process startup via `apk_artifact(action: "install_verify")` or `adb install`.
  4. *Exact-Feature Verification*: Discrete experimental confirmation that the target functionality (e.g. license validation, authentication flow) operates as hypothesized. Launch stability does NOT constitute feature verification.
---

## 3. Evidence Artifact Markdown Schema

Save formal reverse engineering findings in a structured evidence artifact (e.g. `evidence/<target>_<finding>.md`):

````markdown
# Evidence Artifact: [Finding Title]

## 1. Target Metadata
- **File Name**: `sample_target.apk`
- **SHA-256**: `a6b1c2d3...`
- **Architecture**: `ARM64-v8a` / `x86_64 PE`
- **Analysis Date**: `2026-10-17`
- **Classification**: `CWE-602: Client-Side Enforcement of Security Attributes`

## 2. Evidence Chain

### [FACT] Observable Ground Truth
- **Location**: `com.example.app.LicenseValidator.checkLicense()` (lines 58-74)
- **Disassembly / Source Snippet**:
  ```java
  // jadx-cli output lines 62-65
  if (!SignatureVerifier.verify(context, LICENSE_PUBLIC_KEY)) {
      return false; // Target validation failure branch
  }
  return true;
  ```
- **Observed Constants**: `LICENSE_PUBLIC_KEY` loaded from `res/values/strings.xml` string ID `0x7f0f0042`.

### [HYPOTHESIS] Working Hypothesis
- If `SignatureVerifier.verify` is intercepted to return `true`, or if bytecode instruction at offset `0x004A` (`if-eqz v0, :cond_fail`) is inverted to `if-nez`, the application will enter activated state without network validation.

### [EXPERIMENT] Verification Procedure
- **Method**: Frida runtime hook script (`hooks/bypass_license.js`).
- **Execution Command**:
  ```bash
  frida -U -f com.example.app -l hooks/bypass_license.js
  ```
- **Hook Code**:
  ```javascript
  Java.perform(function () {
      var Verifier = Java.use("com.example.app.SignatureVerifier");
      Verifier.verify.implementation = function (ctx, key) {
          console.log("[Frida] Hooked SignatureVerifier.verify -> forcing true");
          return true;
      };
  });
  ```

### [CONCLUSION] Verified Result
- **Observed Behavior**: Application booted straight to main dashboard; UI displayed "License Status: Active". Logcat confirmed hook triggered once at startup.
- **Reproducibility**: 100% reproducible across 5 test restarts in isolated emulator.
````

---

## 4. Common CWE Taxonomy for Reverse Engineering Findings

Align findings with standard Common Weakness Enumeration identifiers:

| CWE ID | Weakness Name | Typical Scenario in Audits |
| :--- | :--- | :--- |
| **CWE-602** | Client-Side Enforcement of Server Security | Client app decides whether user is VIP/licensed without server verification |
| **CWE-798** | Use of Hard-coded Credentials | Fixed AES key, JWT signing secret, or API token embedded in binary/smali |
| **CWE-295** | Improper Certificate Validation | TLS certificate pinning disabled or trusting all certificates (`X509TrustManager`) |
| **CWE-327** | Use of a Broken or Risky Cryptographic Algorithm | Using hard-coded DES/ECB or MD5 for sensitive payload integrity |
| **CWE-319** | Cleartext Transmission of Sensitive Information | Protocol payloads sent over unencrypted HTTP or raw TCP without TLS |
| **CWE-312** | Cleartext Storage of Sensitive Information | Passwords or tokens stored in plain SQLite databases or SharedPreferences |

---

## 5. Verified Reverse Knowledge & Reusability (`reverse_knowledge`)

To prevent knowledge pollution and ensure long-term maintainability:
1. **Strict Verification Gate**: ONLY verified conclusions (`evidence` kind: `conclusion` with `status: verified`) and successful recovery audits can be retained or learned as reusable knowledge.
2. **No Unverified Promotion**: Working hypotheses (`[HYPOTHESIS]`) and unknowns (`[UNKNOWN]`) are strictly barred from promotion to knowledge until empirical verification is completed.
3. **Autonomous Retrieval**: When initiating or planning reverse engineering workflows (`reverse_workflow action: 'create'` or `'plan'`), prior knowledge is queried and linked automatically.
4. **Automated Synthesis**: Use `reverse_knowledge(action: 'learn')` to scan the project evidence ledger and workflow recovery history to persist reusable patterns.

---

## 6. Subagent Task Handoff & Evidence Contract

When the orchestrator delegates tasks to specialized subagents (`task` or `scout`), structured task handoffs MUST specify concrete target coordinates, boundary scopes, and evidence lineage using existing contract fields:

### 1. Target Coordinate Anchors
Every reverse task MUST pin target identity using immutable coordinates to prevent drift across spawns:
- **`sha256`**: Immutable cryptographic hash of the target sample (computed before analysis/mutation).
- **`path`**: Concrete local file path to the sample binary or artifact.
- **`package`**: Android / mobile package identifier (e.g. `com.example.app`), required for mobile workflows.
- **`abi`**: Target CPU architecture (`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`).
- **`serial`**: Target ADB device serial for dynamic/device actions; NEVER assume or guess serial.

### 2. Delegation Envelope Fields
Task definitions MUST provide explicit boundary specifications:
- **`# Target`**: Concrete files, immutable `sha256`, `package`, `abi`, and device `serial` where applicable. Non-goals explicitly bounded.
- **`subject`**: Discrete function, symbol, component, or protocol endpoint under test (e.g. `Lcom/example/Auth;->verifyToken()Z`, `libcrypto.so!encrypt_payload`, `POST /api/v2/auth`).
- **`evidence_ids` / `artifact_paths`**: Upstream evidence IDs (`ev_fact_*`) and artifact file paths passed as ground truth.
- **`allowed_actions`**: Explicit whitelist of authorized tool actions (e.g. `manifest`, `listclass`, `getclass`, `diff`; no unapproved mutations or global installs).
- **`# Acceptance`**: Observable, reproducible criteria (e.g. exact byte offset identified, decompiler output verified, control baseline passed).

### 3. Child Reporting Contract
Children MUST report empirical ground truth rather than asserting high-level success:
- **Emit Facts (`[FACT]`)**: Cite exact virtual address, RVA, function name, line number, or byte offset.
- **Explicit Unknowns (`[UNKNOWN]`)**: Unambiguously report unresolved variables, unreached branches, or missing external tools.
- **Explicit Blockers (`[BLOCKER]`)**: State exact missing dependencies, environment constraints, or permission boundaries.
- **No Premature Promotion**: Observations from static fallbacks (e.g. manifest parsing or static disasm) MUST NOT be reported as dynamic execution or live feature verification.
