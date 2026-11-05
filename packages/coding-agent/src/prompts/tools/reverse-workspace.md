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
- `begin`: Allocate an isolated experiment run directory under `.reverse/analysis/<workflow_id>/runs/<run_id>/{scripts,dumps,reports,tmp}` before producing artifacts.
  - Requires `workflow_id`, `step_id`, `purpose`, and `command`; verifies workflow step and target SHA-256 against disk.
  - Records streaming SHA-256 hashes for the target binary, explicit `inputs`, and any pre-existing `script_paths`.
  - 运行状态置为 running。每次独立实验、验证不同假设或调整执行命令时，必须通过 begin 分配新的独立 run_id。
  - Returns managed directories, `run_id`, the 5 most recent runs for the same target SHA-256 (including failed attempts), and verified reusable script absolute paths for explicit `%load` or `bash` invocation.
- `record`: Finalize an experiment run in `run.json` and link artifacts to the workflow step.
  - Requires `workflow_id`, `run_id`, integer `exit_code` (`0` = `succeeded`, non-zero = `failed`), and `summary`.
  - 收齐本次实验的全部脚本与输出产物后仅调用一次 record 终结。终结后状态转为 succeeded 或 failed（已终结），禁止追加新产物、新脚本或改写摘要。
  - Re-verifies all recorded inputs and pre-existing scripts are unchanged; requires new `script_paths` and `output_paths` to reside within the run directory (and non-empty `output_paths` when `exit_code` is `0`).
  - Validates `evidence_ids` exist, persists `run.json` atomically under lock, and lock-safely merges script, output, and `run.json` references into the workflow step's `artifact_refs`.
  - 相同参数幂等重试：若步骤产物关联因意外失败，使用完全相同参数再次调用 record 会安全修复关联，不重复执行实验也不修改历史数据；任何不一致的改写或追加尝试均会被拒绝并提供恢复指引。
  - 终结后若需开展后续实验或生成新产物，必须显式调用 begin 分配新 run，严禁对已终结 run 重复调用 record。
  - `recall`: 只读检索跨会话的 run.json 实验历史并复核文件哈希；仅用于查询历史与复用脚本，不修改任何运行记录。
  - Supports exact `workflow_id` and `target_hash` filters, case-insensitive `query` matching across `purpose`, `summary`, `command`, and `script_paths`, and `limit` (1–20, default 5) ordered newest-first.
  - Re-checks recorded `inputs`, `scripts`, and `outputs` on disk to report `reuse_status` (`available` when `succeeded` and all hashes match, `changed` on hash drift, `missing` on absent files, `incomplete` for `failed` or `running` runs with failure summaries) alongside `reuse_reasons` and verified `reusable_script_paths`.
Security & Integrity:
- Target binaries are accessed strictly read-only and preserved by reference.
- Atomic writes: files are written to temporary paths and atomically replaced.
- Secret redaction: tokens, passwords, and API keys are scrubbed before writing reports.
- Clutter prevention: raw huge binaries (> 1 MiB) are never duplicated into the workspace.
- Artifact lifecycle protection: baseline builds, verified evidence, rollback patches, and user scripts are protected by default from automated deletion.
- Postcondition verification: deletion is verified on disk; locked files or permission failures are reported honestly rather than assumed deleted.
- Minimal reproducibility preservation: core artifact references and hashes are recorded in manifest reproducibility metadata.
- Experiment run isolation: active runs under `.reverse/analysis/` enforce realpath/symlink containment, reject input/script drift before recording, and remain untouched by workspace `clean`.
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

// 5. 为工作流步骤分配独立的实验运行目录（状态置为 running）
reverse_workspace(action: "begin", workflow_id: "wf_rw_018f...", step_id: "elf_step_1", purpose: "Extract XOR key table from .rodata", command: "bun .reverse/analysis/wf_rw_018f.../runs/<run_id>/scripts/extract.ts")

// 6. 实验完成收齐产物后，调用一次 record 终结记录并关联步骤产物（状态转为已终结的 succeeded 或 failed）
// 注意：已终结的 run 禁止再次追加产物或修改摘要；开展新实验请先调用 begin。
reverse_workspace(action: "record", workflow_id: "wf_rw_018f...", run_id: "run_018f...", exit_code: 0, summary: "Extracted 32-byte XOR key table", script_paths: [".reverse/analysis/wf_rw_018f.../runs/run_018f.../scripts/extract.ts"], output_paths: [".reverse/analysis/wf_rw_018f.../runs/run_018f.../dumps/key_table.json"])

// 7. 只读检索历史实验与复用脚本，不修改已有记录
reverse_workspace(action: "recall", target_hash: "e3b0c442...", query: "xor key", limit: 5)
```
</examples>
