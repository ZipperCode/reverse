Empirical reverse-engineering evidence ledger tool. Maintains scientific verification chains separating facts, hypotheses, and verified conclusions with drift detection and structured export.

Actions:
- `add`: Record a `fact`, `hypothesis`, or `unknown`. Directly adding a `conclusion` is forbidden.
  - `fact`: Requires `sourceTool` (e.g. `triage`, `r2_inspect`, `droidasc`, `read`), `locator` (symbol, RVA/offset, line number), and `content`. Optional `target` and verbatim `excerpt`.
  - `hypothesis`: Requires `claim` (suspected logic/mechanism) and `verificationPlan` (actionable, falsifiable experiment plan). Optional supporting `facts` ID list.
  - `unknown`: Requires `question` or `content` for unresolved questions, gaps, or anomalies.
- `verify`: Establish a verified conclusion for an existing hypothesis.
  - Requires `hypothesisId`, `method` (e.g. Frida hook, replay, patch), `command` (reproduction command/script), `result` (empirical delta observed), and confirmed `conclusion`.
  - Generates an immutable, verified `conclusion` record linked to the hypothesis while preserving complete history.
- `show`: Inspect an evidence record by `id`. Automatically recomputes target file SHA-256 and excerpt hash to detect and report drift warnings.
- `list`: Browse and paginate ledger entries with optional `kind`, `target`, and `query` keyword filters.
- `export`: Export evidence chain to reverse-lab Markdown schema. Spills to a session artifact when large or when `to_artifact: true`.

Security & Guardrails:
- Target files are strictly read-only.
- Ledger data is isolated per-project under agent state and never written into the workspace repository.
- Automatic redaction strips credentials, API keys, tokens, and embedded URLs.
- Append-only JSONL storage backed by cross-process advisory locks and atomic file replacement.

<examples>
```
// 1. Add a fact observed from triage
evidence(action: "add", kind: "fact", target: "sample.apk", sourceTool: "droidasc", locator: "com.example.LicenseCheck.isPro()", content: "Returns boolean value checked at startup", excerpt: "return this.isLicensed;")

// 2. Propose a working hypothesis
evidence(action: "add", kind: "hypothesis", target: "sample.apk", claim: "Forcing isPro() to return true bypasses license activation check", verificationPlan: "Run Frida script to hook isPro() and observe if dashboard unlocks", facts: ["ev_fact_018f..."])

// 3. Verify hypothesis into a confirmed conclusion
evidence(action: "verify", hypothesisId: "ev_hyp_018f...", method: "Frida runtime hook", command: "frida -U -f com.example -l hook.js", result: "Application unlocked dashboard with License: Active", conclusion: "Confirmed: Hooking isPro() completely bypasses client license dialog")

// 4. Inspect finding with integrity and hash drift check
evidence(action: "show", id: "ev_conc_018f...")

// 5. Export structured Markdown report
evidence(action: "export", to_artifact: true)
```
</examples>
