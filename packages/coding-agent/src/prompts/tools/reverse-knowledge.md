# Reverse Knowledge Tool (`reverse_knowledge`)

The `reverse_knowledge` tool provides a bounded, verified reverse engineering knowledge repository and Mnemopi bridge. It indexes reusable analytical findings, verified conclusions, and successful failure recovery patterns across projects and targets.

## Actions

- **`search`**: Query stored knowledge by keywords, target format (`PE`, `ELF`, `Mach-O`, `APK`, `JS`, `WASM`, `PCAP`, `SQLite`), SHA256 hash, tool name, or kind. Searches both local project store and Mnemopi recall. Bounded to 5 items by default (max 20).
- **`retain`**: Manually record verified reverse engineering conclusions or recovery patterns. Strictly verifies that unverified hypotheses or refuted claims are never promoted as facts.
- **`learn`**: Automatically scan the project's `EvidenceStore` and `ReverseWorkflowStore`. Extracts only verified conclusions (`status: verified`) and successful recovery audits (`applied: true` on completed steps) into reusable knowledge entries. Unverified hypotheses and failed attempts are safely skipped.
- **`apply`**: Match stored knowledge against a given target format, hash, tool, error message, or analytical goal. Returns actionable guidance, recommended fallback tools, and parameter configurations. Automatically excludes disabled, expired, and merged records, while exposing backing evidence sources and confidence.
- **`audit`**: Perform deterministic quality governance review across stored knowledge. Computes canonical fingerprints to detect duplicate records, checks backing evidence ledger IDs for missing or refuted conclusions (`stale: true`), reports expired records, and outputs consolidation recommendations.
- **`merge`**: Consolidate duplicate or related knowledge records into a designated primary record. Non-destructively preserves history by linking combined evidence IDs and usage metadata onto the primary record while marking source records with `status: "merged"` (`merged_into: <id>`).
- **`expire`**: Retire obsolete or outdated knowledge records with governance reasoning. Preserves records with `status: "expired"` for traceability while excluding them from active query retrieval.
- **`disable`**: Deactivate knowledge records from active retrieval and workflow auto progression with explicit audit reasoning.

## Verification & Governance Safety Guarantee

- **No Premature Promotion**: Unverified hypotheses (evidence kind: `hypothesis` without a verifying conclusion) and questions (evidence kind: `unknown`) are **never** promoted to knowledge.
- **Non-Destructive Governance**: Knowledge entries are never permanently deleted by default during quality governance; they transition through explicit lifecycle states (`active`, `merged`, `expired`, `disabled`).
- **Deterministic Duplicate Fingerprinting**: Records are indexed with canonical fingerprints derived from normalized kind, target format, tool, target hash, and core tokens.
- **Stale Source Detection**: Backing evidence records are validated against the project evidence ledger; any refuted conclusions or missing evidence items are flagged for review or retirement.
- **Evidence Ledger Traceability**: Retained conclusions link back to their originating evidence ledger IDs (`ev_conc_...`, `ev_hyp_...`) and workflow audit records.
- **Deterministic Prior Retrieval**: The `reverse_workflow` orchestrator automatically queries `reverse_knowledge` during `create`, `plan`, and `advance` actions to surface prior findings without executing unrequested commands.
