# evidence

> Empirical reverse-engineering evidence ledger: record facts, propose hypotheses, verify outcomes, track hash drift, and export structured proof artifacts conforming to the reverse reverse-lab standard.

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
| `reproducibility`| `string` | No | Reproducibility rate or description, e.g. `'100% (5/5 runs)'`. |
| `classification` | `string` | No | Taxonomy or weakness classification, e.g. `CWE-602`, `CWE-798`. |
| `tags` | `string[]` | No | Categorization tags, e.g. `['auth', 'crypto', 'license']`. |
| `query` | `string` | No | Keyword search string for filtering list. |
| `limit` | `number` | No | Maximum items returned in list (default 20, max 100). |
| `offset` | `number` | No | Zero-based pagination offset for list (default 0). |
| `to_artifact` | `boolean` | No | Force exporting markdown report to session artifact instead of inline text. |

## Actions
- **add**: Records a `fact` (requires `sourceTool` + `locator`), a `hypothesis` (requires `claim` + `verificationPlan`), or an `unknown`. Directly adding a `conclusion` is strictly forbidden.
- **verify**: Verifies an existing hypothesis into a confirmed conclusion record. Requires `hypothesisId`, `method`, `command`, `result`, and `conclusion`. Preserves immutable append-only history.
- **show**: Retrieves an entry by ID, recomputes target file SHA-256 and excerpt hashes, and reports any drift or integrity warnings.
- **list**: Paginates and filters evidence entries by kind, target, or keyword query.
- **export**: Generates a structured Markdown proof report matching `reverse-lab/references/evidence.md`. Spills to a session artifact (`artifact://<id>`) when output is large or when `to_artifact: true`.

## Security & Storage
- **Per-project state**: Stored under agent state directory (`~/.reverse/evidence/<project-key>/ledger.jsonl`, with `~/.rva/` fallback), completely isolating ledger data from the workspace repository.
- **Append-only & Atomic**: Concurrent writes are serialized via in-process write chains and cross-process advisory file locks (`ledger.lock`). Writes are staged to temporary files and atomically renamed.
- **Read-only Target Files**: Target binaries and source files are accessed in read-only mode for hash calculation and excerpt verification; target files are never modified.
- **Sensitive Data Redaction**: Automatic redaction strips API keys, JWT tokens, AWS credentials, GitHub PATs, and URL-embedded passwords prior to persistence.
- **Approval Tiers**: Read actions (`show`, `list`, `export`) use tier `"read"`; mutating actions (`add`, `verify`) use tier `"write"`.
