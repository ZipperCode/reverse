Standardized reverse-engineering workspace manager for `reverse`. Manages the local `.reverse/` workspace (with `.rea/` compatibility) with deterministic target profiles, execution plans, verified evidence chains, findings reports, and safe artifact references.

Actions:
- `export`: Export a reverse workflow and all hydrated evidence/findings into the standardized `.reverse/` workspace.
  - Generates `.reverse/manifest.json` indexing target profile, workflow metrics, evidence links, and generated files.
  - Records target metadata in `.reverse/target/target.json` read-only by reference (never mutates or duplicates original binary).
  - Emits `.reverse/workflow/workflow.json` and `workflow.md`.
  - Emits `.reverse/evidence/evidence.json` and `ledger.json` (scrubbed of credentials and secrets).
  - Emits `.reverse/findings/findings.json` and `findings.md`.
  - Safely copies small scripts/dumps (<= 1 MiB) to `.reverse/scripts/` and `.reverse/dumps/` while recording large files as safe references.
  - Produces executive summaries in `.reverse/reports/workflow_report.md` and `findings_report.md`.
- `status`: Inspect local `.reverse/` workspace integrity, validate `manifest.json`, check standard directory layout, and report file counts.
- `manifest`: Read and parse the workspace `manifest.json` file.
- `clean`: Safely clean experimental artifacts or dump files while strictly preserving verified baselines, originals, evidence, rollback archives, and user scripts.
  - Classifies artifacts: protected (`baseline`, `original`, `evidence`, `rollback`, `userfile`) vs disposable (`experiment`).
  - Refuses deletion of protected artifacts without explicit confirmation decision; preserves minimal reproducibility manifest.
  - Verifies deletion postconditions and reports locked or in-use files honestly.
  - Supports `experimental_targets` to clean specific named experimental attempts only.
Security & Integrity:
- Target binaries are accessed strictly read-only and preserved by reference.
- Atomic writes: files are written to temporary paths and atomically replaced.
- Secret redaction: tokens, passwords, and API keys are scrubbed before writing reports.
- Clutter prevention: raw huge binaries (> 1 MiB) are never duplicated into the workspace.
- Artifact lifecycle protection: baseline builds, verified evidence, rollback patches, and user scripts are protected by default from automated deletion.
- Postcondition verification: deletion is verified on disk; locked files or permission failures are reported honestly rather than assumed deleted.
- Minimal reproducibility preservation: core artifact references and hashes are recorded in manifest reproducibility metadata.
<examples>
```
// 1. Export workflow to default .reverse/ workspace
reverse_workspace(action: "export", workflow_id: "wf_rw_018f...")

// 2. Inspect workspace integrity and directory layout
reverse_workspace(action: "status")

// 3. Read workspace manifest
reverse_workspace(action: "manifest")

// 4. Clean heavy dump files from workspace
reverse_workspace(action: "clean", clean_dumps_only: true)
```
</examples>
