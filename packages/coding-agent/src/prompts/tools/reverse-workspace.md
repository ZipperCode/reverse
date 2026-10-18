Standardized reverse-engineering workspace manager for `rea`. Manages the local `.rea/` workspace with deterministic target profiles, execution plans, verified evidence chains, findings reports, and safe artifact references.

Actions:
- `export`: Export a reverse workflow and all hydrated evidence/findings into the standardized `.rea/` workspace.
  - Generates `.rea/manifest.json` indexing target profile, workflow metrics, evidence links, and generated files.
  - Records target metadata in `.rea/target/target.json` read-only by reference (never mutates or duplicates original binary).
  - Emits `.rea/workflow/workflow.json` and `workflow.md`.
  - Emits `.rea/evidence/evidence.json` and `ledger.json` (scrubbed of credentials and secrets).
  - Emits `.rea/findings/findings.json` and `findings.md`.
  - Safely copies small scripts/dumps (<= 1 MiB) to `.rea/scripts/` and `.rea/dumps/` while recording large files as safe references.
  - Produces executive summaries in `.rea/reports/workflow_report.md` and `findings_report.md`.
- `status`: Inspect local `.rea/` workspace integrity, validate `manifest.json`, check standard directory layout, and report file counts.
- `manifest`: Read and parse the workspace `manifest.json` file.
- `clean`: Safely clean dump or temporary files from `.rea/dumps/` while preserving reports, evidence, and manifests.

Security & Integrity:
- Target binaries are accessed strictly read-only and preserved by reference.
- Atomic writes: files are written to temporary paths and atomically replaced.
- Secret redaction: tokens, passwords, and API keys are scrubbed before writing reports.
- Clutter prevention: raw huge binaries (> 1 MiB) are never duplicated into the workspace.

<examples>
```
// 1. Export workflow to default .rea/ workspace
reverse_workspace(action: "export", workflow_id: "wf_rw_018f...")

// 2. Inspect workspace integrity and directory layout
reverse_workspace(action: "status")

// 3. Read workspace manifest
reverse_workspace(action: "manifest")

// 4. Clean heavy dump files from workspace
reverse_workspace(action: "clean", clean_dumps_only: true)
```
</examples>
