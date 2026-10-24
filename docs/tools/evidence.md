# evidence

Empirical reverse-engineering evidence ledger: record facts, propose hypotheses, verify outcomes, track hash drift, and export structured proof artifacts conforming to the reverse reverse-lab standard.

## Source
- Entry: `packages/coding-agent/src/tools/evidence.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/evidence.md`
- Core engine: `packages/coding-agent/src/evidence/`

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `action` | `string` | Yes | Action: `"add"`, `"list"`, `"show"`, `"verify"`, `"export"`. |
| `kind` | `string` | No* | Evidence kind for add (`"fact"`, `"hypothesis"`, `"unknown"` - direct `"conclusion"` forbidden) or filter for list. |
| `id` | `string` | No* | Record ID to inspect (required for `show`; optional filter for `export`). |
| `hypothesisId` | `string` | No* | Target hypothesis ID to verify (required for `verify`). |
| `title` | `string` | No | Short title or summary for the evidence entry. |
| `target` | `string` | No | Target binary, package, library, or source path relative to project root. |
| `sourceTool` | `string` | No* | Analysis tool that produced the fact observation (required for `fact`). |
| `locator` | `string` | No* | Coordinate locator: symbol, RVA/offset `0x14001A240`, line number (required for `fact`). |
| `content` | `string` | No* | Ground truth for fact, context for hypothesis, or question for unknown. |
| `excerpt` | `string` | No | Verbatim disassembly, decompiled snippet, or string from target (tracked for excerpt drift). |
| `claim` | `string` | No* | Suspected mechanism or vulnerability claim (required for `hypothesis`). |
| `verificationPlan`| `string` | No* | Actionable, falsifiable verification procedure or test plan (required for `hypothesis`). |
| `facts` | `string[]` | No | Array of supporting fact record IDs. |
| `method` | `string` | No* | Experimental method used for verification, e.g. Frida hook, replay, memory patch (required for `verify`). |
| `command` | `string` | No* | Exact reproduction command or script invocation (required for `verify`). |
| `result` | `string` | No* | Observed outcome or delta produced by the experiment (required for `verify`). |
| `conclusion` | `string` | No* | Confirmed deductive conclusion backed by verification result (required for `verify`). |
| `status` | `string` | No | Verification outcome status: `"verified"` (default) or `"refuted"`. |
| `subject` | `string` | No | Target domain subject or component identity (e.g. `login_flow`, `license_check`). Immutable subject binding used to evaluate workflow acceptance criteria. |
| `assurance` | `string` | No | Assurance tier: `"static_candidate"`, `"dynamic_call_observation"`, `"algorithm_recovery"`, `"independent_reproduction"`. |
| `artifactSha256` | `string` | No | Exact SHA-256 hash of the execution artifact or library binary. |
| `deviceAbi` | `string` | No | Target device architecture or ABI (e.g. `arm64-v8a`, `x86_64`). |
| `os` | `string` | No | Operating system and kernel/platform version of the execution environment. |
| `pid` | `number` | No | Process ID of the observed execution. |
| `invalidatesConclusions` | `string[]` | No | Array of prior conclusion IDs invalidated or refuted by this conclusion. |
| `reproducibility`| `string` | No | Quantitative reproducibility description, e.g. `'5/5 runs (100%)'`. |
| `verifiedUnits` | `number` | No | Successful verification trial count. |
| `totalRequiredUnits` | `number` | No | Total required trial count denominator (> 0). |
| `unitDescription` | `string` | No | Unit description for quantitative ratio (e.g. `'runs'`, `'tests'`). |
| `isExhaustive` | `boolean` | No | Whether a negative search was exhaustive across the entire target space. |
| `searchTarget` | `string` | No | Target scope or container file for negative search. |
| `scopeBoundary` | `string` | No | Boundary of negative search (e.g. `single_file`, `process_memory`, `all_dex`). |
| `claimScope` | `string` | No | Scope of claim: `"bounded"` for local observations, `"universal"` for total absence claims. |
| `classification` | `string` | No | Taxonomy or weakness classification, e.g. `CWE-602`, `CWE-798`. |
| `tags` | `string[]` | No | Categorization tags, e.g. `['auth', 'crypto', 'license']`. |
| `query` | `string` | No | Keyword search string for filtering list. |
| `limit` | `number` | No | Maximum items returned in list (default 20, max 100). |
| `offset` | `number` | No | Zero-based pagination offset for list (default 0). |
| `to_artifact` | `boolean` | No | Force exporting markdown report to session artifact instead of inline text. |

## Actions
- **add**: Records a `fact` (requires `sourceTool` + `locator`), a `hypothesis` (requires `claim` + `verificationPlan`), or an `unknown`. Directly adding a `conclusion` is strictly forbidden. Accepts immutable `subject` and `assurance` level.
- **verify**: Verifies an existing hypothesis into a conclusion record with `status: "verified"` or `status: "refuted"`. Requires `hypothesisId`, `method`, `command`, `result`, and `conclusion`. Supports explicit refutations and `invalidatesConclusions` targeting earlier superseded conclusions.
- **show**: Retrieves an entry by ID, recomputes target file SHA-256 and excerpt hashes, and reports any drift or integrity warnings.
- **list**: Paginates and filters evidence entries by kind, target, subject, or keyword query.
- **export**: Generates a structured Markdown proof report matching `reverse-lab/references/evidence.md`. Spills to a session artifact (`artifact://<id>`) when output is large or when `to_artifact: true`.

## Canonical Evidence Graph & Refutation Disciplines

1. **Subject Binding & Proxy Distinctions**:
   - Evidence records bind to a canonical `subject` (e.g. `license_check`).
   - Observations recorded under a different subject (e.g. `login_flow`) are classified as proxy observations. When evaluated against workflow acceptance criteria, proxy evidence cannot satisfy the criterion without explicit human waiver (`waive_acceptance`).

2. **Chronological Evaluation & Stale Invalidations**:
   - Ledger records are append-only.
   - For any hypothesis, conclusions are resolved in chronological sequence. If the latest conclusion is `status: "refuted"`, the underlying hypothesis is marked refuted, and earlier conclusions for that hypothesis become `stale` (`invalidatedBy`).
   - Conclusions explicitly listing IDs in `invalidatesConclusions` mark those target conclusions `stale`.

3. **Transitive Refutation Cascades into Workflows**:
   - If a step or build derivative in a workflow relies on evidence that is later refuted or becomes stale, `cascadeEvidenceRefutation` invalidates the step back to `pending` (`held_pending_decision`, `decision: "invalidated_by_evidence"`), clears active proof, fails the build runtime status, and reopens completed workflows back to `active`.

4. **Quantitative Reproducibility & Negative Search Bounds**:
   - Percentages without explicit denominators are forbidden: supply `verifiedUnits` and `totalRequiredUnits` (`totalRequiredUnits > 0`).
   - Negative search results (e.g. missing string or symbol) are strictly bounded by `searchTarget` and `scopeBoundary`, and cannot claim universal absence across all execution paths without exhaustive proof.

## Security & Storage
- **Per-project state**: Stored under agent state directory (`~/.reverse/evidence/<project-key>/ledger.jsonl`), completely isolating ledger data from the workspace repository.
- **Append-only & Atomic**: Concurrent writes are serialized via in-process write chains and cross-process advisory file locks (`ledger.lock`). Writes are staged to temporary files and atomically renamed.
- **Read-only Target Files**: Target binaries and source files are accessed in read-only mode for hash calculation and excerpt verification; target files are never modified.
- **Sensitive Data Redaction**: Automatic redaction strips API keys, JWT tokens, AWS credentials, GitHub PATs, and URL-embedded passwords prior to persistence.
- **Approval Tiers**: Read actions (`show`, `list`, `export`) use tier `"read"`; mutating actions (`add`, `verify`) use tier `"write"`.
