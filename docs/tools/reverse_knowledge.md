# reverse_knowledge

> Bounded reverse-engineering knowledge repository and Mnemopi bridge: search, retain verified conclusions, learn recovery patterns, and apply findings without promoting unverified hypotheses.

## Source
- Entry: `packages/coding-agent/src/tools/reverse-knowledge.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/reverse-knowledge.md`
- Core engine: `packages/coding-agent/src/reverse-knowledge/`

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `action` | `string` | Yes | Action: `search`, `retain`, `learn`, `apply`, `audit`, `merge`, `expire`, `disable`. |
| `query` | `string` | No | Keyword search query across stored knowledge titles, summaries, and guidance. |
| `format` | `string` | No | Target binary/package format (`PE`, `ELF`, `Mach-O`, `APK`, `JS`, `WASM`, `PCAP`, `SQLite`). |
| `target` | `string` | No | Target binary, package, capture, or script path relative to workspace (alias `path`). |
| `path` | `string` | No | Alias for `target`. |
| `target_hash` | `string` | No | SHA256 hash of target binary for exact knowledge matching. |
| `tool` | `string` | No | Specific reverse engineering tool name (e.g. `r2_inspect`, `ghidra_inspect`). |
| `kind` | `string` | No* | Category of knowledge: `"verified_conclusion"` or `"recovery_pattern"`. Required for `retain`. |
| `title` | `string` | No* | Title or descriptive headline for retained knowledge. Required for `retain`. |
| `summary` | `string` | No* | Summary of verified findings, analytical methodology, or recovery outcome. Required for `retain`. |
| `pattern` | `string` | No | Applicability pattern or error condition signature. |
| `actionable_guidance` | `string` | No | Actionable instructions, suggested tool parameters, or analysis recommendations. |
| `params` | `string` | No | Suggested parameters or config adjustments as JSON or description. |
| `confidence` | `string` | No | Confidence level: `"high"`, `"medium"`, `"low"`. Verified conclusions require `"high"` or `"medium"`. |
| `source_evidence_ids` | `string[]` | No | Array of evidence ledger IDs (`ev_conc_...`, `ev_hyp_...`) backing this verified finding. |
| `source_workflow_id` | `string` | No | Originating reverse engineering workflow ID. |
| `source_step_id` | `string` | No | Originating workflow step ID. |
| `workflow_id` | `string` | No | Optional workflow ID to restrict `learn` action. |
| `error` | `string` | No | Error message or failure category to match against recovery patterns in `apply`. |
| `goal` | `string` | No | Analytical goal or objective for `search` or `apply`. |
| `limit` | `number` | No | Maximum results to return (default 5, max 20). |
| `include_bundled` | `boolean` | No | Whether to include bundled default knowledge seeds alongside local project records. |

- **`audit`**: Detects duplicate fingerprints, missing/refuted evidence backing, and expired records. Optional `mark_stale` marks records without deleting them.
- **`merge`**: Non-destructively marks duplicate records as merged into a primary record.
- **`expire`**: Marks a record expired with a reason; it remains auditable.
- **`disable`**: Disables a record with an explicit reason; disabled and expired records are excluded from application.

## Verification Safety Guarantee

- **No Premature Promotion**: Unverified hypotheses (kind: `hypothesis` without a verifying conclusion) and questions (kind: `unknown`) are rejected from retention and skipped during automated learning.
- **Evidence Ledger Traceability**: Retained conclusions link back to their originating evidence ledger IDs (`ev_conc_...`, `ev_hyp_...`) and workflow audit records.
- **Deterministic Prior Retrieval**: The `reverse_workflow` orchestrator automatically queries `reverse_knowledge` during `create` and `plan` actions to surface prior findings without executing unrequested commands.

## Bundled Default Knowledge Seeds

- **Curated Baseline Patterns**: Rea ships with embedded baseline recovery patterns across all supported formats (`PE`, `ELF`, `Mach-O`, `APK`, `JS`, `WASM`, `PCAP`, `SQLite`).
- **Deterministic Fallback**: When `reverse_knowledge search` or `apply` finds no local matching records in the project store (such as on a fresh install or for a newly targeted format), it automatically falls back to relevant bundled patterns.
- **Strict Non-Verified Status**: All bundled records are marked with `source: "bundled"` and metadata `{ source: "bundled", user_verified: false, baseline: true }`. They carry `medium` confidence and are never treated as project evidence-verified facts unless the user verifies them in the project ledger.
- **Read-Only Non-Polluting**: Querying or applying bundled seeds never creates uncommitted disk files in fresh projects until explicitly retained or customized.
