Empirical reverse-engineering evidence ledger tool. Maintains scientific verification chains separating facts, hypotheses, and verified conclusions with drift detection and structured export.

Actions:
- `add`: Record a `fact`, `hypothesis`, or `unknown`. Directly adding a `conclusion` is forbidden.
  - `fact`: Requires `sourceTool` (e.g. `triage`, `r2_inspect`, `droidasc`, `read`), `locator` (symbol, RVA/offset, line number), and `content`. Optional `target`, verbatim `excerpt`, `subject`, `assurance`, `artifactSha256`, `deviceAbi`, `os`, `pid`, `isExhaustive`, `searchTarget`, and quantitative completion ratio.
  - `hypothesis`: Requires `claim` (suspected logic/mechanism) and `verificationPlan` (actionable, falsifiable experiment plan). Optional supporting `facts` ID list, `subject`, `assurance`, `artifactSha256`, and search scope.
  - `unknown`: Requires `question` or `content` for unresolved questions, gaps, or anomalies. Optional `subject`.
- `verify`: Establish a verified conclusion for an existing hypothesis.
  - Requires `hypothesisId`, `method` (e.g. Frida hook, replay, patch), `command` (reproduction command/script), `result` (empirical delta observed), and confirmed `conclusion`.
  - Generates an immutable `conclusion` record linked to the hypothesis while preserving complete history.
  - Default reproducibility is `not specified` unless an explicit rate (e.g. `100% (5/5 runs)`) or quantitative ratio (`verifiedUnits`, `totalRequiredUnits`) is provided.
  - Verification rigor: verified conclusions cannot exceed declared supporting facts assurance tier:
    - `static_candidate`: Disassembly strings, symbol names, decompiled field patterns.
    - `dynamic_call_observation`: Runtime log start markers, hook invocations, observed non-null returns.
    - `algorithm_recovery`: Recovered logic, crypto/math formulas, and state transformations offline.
    - `independent_reproduction`: Verified standalone implementation accepted by server or target environment.
    Conclusions cannot verify if compound stages fail (`exitCode != 0`), cannot verify universal absence with non-exhaustive search (`claimScope: "universal"` requires `isExhaustive: true`), and cannot verify if supporting facts are refuted or target hash/subject mismatched.
  - Refutations: most recent refutation invalidates prior verified conclusions and derived knowledge via canonical validity resolution without rewriting history.
- `show`: Inspect an evidence record by `id`. Automatically recomputes target file SHA-256 and excerpt hash to detect drift warnings, and reports canonical validity status (verified, refuted, or stale).
- `list`: Browse and paginate ledger entries with optional `kind`, `target`, and `query` keyword filters.
- `export`: Export evidence chain to reverse-lab Markdown schema. Spills to a session artifact when large or when `to_artifact: true`.

Security & Guardrails:
- Target files are strictly read-only.
- Ledger data is isolated per-project under agent state and never written into the workspace repository.
- Automatic redaction strips credentials, API keys, tokens, and embedded URLs.
- Append-only JSONL storage backed by cross-process advisory locks and atomic file replacement.

<examples>
```
// 1. Add a fact observed from analysis with assurance tier and subject binding
evidence(action: "add", kind: "fact", target: "sample.apk", sourceTool: "droidasc", locator: "com.example.LicenseCheck.isPro()", content: "Returns boolean value checked at startup", excerpt: "return this.isLicensed;", subject: "license_check", assurance: "static_candidate")

// 2. Propose a working hypothesis
evidence(action: "add", kind: "hypothesis", target: "sample.apk", claim: "Forcing isPro() to return true bypasses license activation check", verificationPlan: "Run Frida script to hook isPro() and observe if dashboard unlocks", facts: ["ev_fact_018f..."], subject: "license_check")

// 3. Verify hypothesis into a confirmed conclusion
evidence(action: "verify", hypothesisId: "ev_hyp_018f...", method: "Frida runtime hook", command: "frida -U -f com.example -l hook.js", result: "Application unlocked dashboard with License: Active", conclusion: "Confirmed: Hooking isPro() completely bypasses client license dialog", subject: "license_check", assurance: "dynamic_call_observation", reproducibility: "100% (5/5 runs)")

// 4. Inspect finding with integrity and hash drift check
evidence(action: "show", id: "ev_conc_018f...")

// 5. Export structured Markdown report
evidence(action: "export", to_artifact: true)
```
</examples>
