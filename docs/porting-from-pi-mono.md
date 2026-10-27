# Porting From pi-mono: A Practical Merge Guide

This guide is a repeatable checklist for porting changes from pi-mono into this repo.
Use it for any merge: single file, feature branch, or full release sync.

## reverse ↔ oh-my-pi release tracking

reverse follows the stable [oh-my-pi releases](https://github.com/can1357/oh-my-pi/releases), retaining its own executable, package scope, configuration, prompts, providers, and reverse-engineering tools.

- Current upstream release: **18.13.1** (`0838d2ab4407b74e870de07e1a6780a13c7d542c`, 2026-10-27).
- Imported range: `v18.11.2` (`470b7efb67673960d37e3e64584669e6e9caad1c`) → `v18.13.1`.
- All release-train TypeScript packages, the workspace catalog, native crate versions, and lockfiles use the upstream release version. The independently versioned browser-relay extension and tool-views package retain their upstream versions.
- Development uses upstream's pinned **Bun 1.4.4**. Build the native addon before starting the updated CLI; version stamps and new native exports must match.

### 18.13.1 integration verification

- Frozen Bun installation, native addon build, standalone binary build, and the TypeScript lint/format/type gate passed with Bun 1.4.4.
- Source and standalone CLI report `reverse/18.13.1`; both pass `--smoke-test`. Isolated print mode completed through a loopback OpenAI-compatible provider without contacting configured user providers.
- Exercised the interactive setup/tool installer, localized browser submit-name round trips, real HTML session export expansion/Markdown safety, OAuth recovery, subprocess diagnostics, and cached/restricted-folder authorization for mixed reads and archive/literal/glob searches.
- Workspace (7 chunks), runtime (34), UI (71), singleton (1,251 passing tests), TUI (4,102), and isolated stats/identity suites (198) passed. Native/tooling/browser coverage passed 103 of 106 chunks; the three Node-dependent fixture groups failed with Node absent from the restricted verification PATH, then all 45 tests passed with the installed Node 24 runtime on PATH.
- Rust full-suite verification passed: **4,016 tests**, with 5 skipped; the runnable doctest passed too. Replaced the pre-existing macOS kernel/login-record equality assumption with per-host VFS fixtures proving default-file boot-record precedence and kernel fallback when no boot record exists, without changing runtime behavior or the host's login records. TypeScript and Rust quality gates, source/standalone CLI smoke checks, and live native `uptime -s` checks also passed.

### Future release syncs

1. Fetch the upstream repository and choose its latest stable tag, rather than unreleased `main` work:

   ```sh
   git fetch upstream --tags
   git diff v18.13.1..<next-stable-tag> -- packages crates docs scripts package.json bun.lock Cargo.toml Cargo.lock
   ```

2. Apply that release delta with a three-way merge using the recorded upstream release as the base. The original fork was imported as a source snapshot and has no shared upstream Git ancestor; a plain unrelated-history merge is not the integration baseline.
3. Map `@oh-my-pi/pi-*` imports to the existing `@reverse/*` packages, including `pi-agent-core` → `agent`, `omp-stats` → `stats`, and `omptype` → `reversetype`. Preserve app-level `reverse`/`REVERSE_*` identity and the existing low-level `PI_*` contracts. Keep third-party identifiers and protocols, such as DeepInfra `sort_by=omp`, OpenMP variables, and legacy pi extension imports, unchanged.
4. Keep intentionally removed public distribution infrastructure and hosted collab/share/update/automatic issue-reporting services absent. Merge their shared runtime fixes only where those paths still exist. Preserve the complete reverse tool registry, dependency checks, provider model discovery/multi-select, and all five CLI/TUI setup panels with real installation actions.
5. Regenerate compatibility rules, native bindings, browser-relay assets, and HTML tool views through their existing scripts. Keep English text and add Chinese configuration translations through the i18n layer. Synthesize system-prompt changes from parallel drafts; user prompt templates retain their existing content.
6. Run frozen dependency installation, native and executable builds, TypeScript/Rust checks, relevant behavioral suites, source and compiled CLI smoke tests, and an isolated interactive setup preview. Update this release marker and package changelogs with the new upstream range and any intentionally excluded surfaces.

The sections below describe the older **pi-mono → omp** porting process; its historical marker is separate from reverse's omp release baseline above.

## Last Sync Point (historical upstream marker)

**Commit:** `b21b42d032919de2f2e6920a76fa9a37c3920c0a`
**Date:** 2026-03-22

Update this section after each sync; do not reuse the previous range. This commit is an upstream pi-mono marker and may not exist in this repo's local object database.

When starting a new sync, generate patches from this commit forward in a pi-mono checkout or remote that contains the commit:

```bash
git format-patch b21b42d032919de2f2e6920a76fa9a37c3920c0a..HEAD --stdout > changes.patch
```

## 0) Define the scope

- Identify the upstream reference (commit, tag, or PR).
- List the packages or folders you plan to touch.
- Decide which features are in-scope and which are intentionally skipped.

## 1) Bring code over safely

- Prefer a clean, focused diff rather than a wholesale copy.
- Avoid copying built artifacts or generated files.
- If upstream added new files, add them explicitly and review contents.

## 2) Match import extension conventions

Most runtime TypeScript sources omit `.js` in internal imports, but several current entrypoints and tool modules keep `.js` for ESM/runtime compatibility. Follow the surrounding file and package export style; do not blanket-strip or blanket-add extensions.

- In `packages/coding-agent` runtime sources, prefer extensionless internal imports when the surrounding module does, but preserve existing `.js` imports in files that already require them.
- In `packages/tui/test` and `packages/natives/bench`, keep `.js` where surrounding files already use it.
- Keep real file extensions when required by tooling or import assertions (e.g., `.json`, `.css`, `.md` text embeds).
- Example: `import { x } from "./foo.js";` → `import { x } from "./foo";` only when that package/file convention is extensionless.

## 3) Replace import scopes

Upstream uses different package scopes. Replace them consistently.

- Replace old scopes with the local scope used here.
- Examples (adjust to match the actual packages you are porting):
  - `@mariozechner/pi-coding-agent` → `@reverse/coding-agent`
  - `@mariozechner/pi-agent-core` → `@reverse/agent`
  - `@mariozechner/pi-tui` → `@reverse/tui`
  - `@mariozechner/pi-ai` → `@reverse/ai`
  - `@mariozechner/pi-utils` → `@reverse/utils`
- Some upstream packages publish under the `@earendil-works/*` scope instead of `@mariozechner/*`. Map it the same way (`@earendil-works/pi-coding-agent` → `@reverse/coding-agent`, and so on).
- The bare `typebox` package is not an `@reverse/*` scope; do not rewrite it as one. See the Extensions divergence in section 15 for how tool-parameter schemas map.

## 4) Use Bun APIs where they improve on Node

We run on Bun, but the current source intentionally mixes Bun APIs with small Node standard-library APIs. Replace Node APIs only when Bun provides a clearer, safer, or simpler implementation; do not mechanically rewrite every Node import.

**Prefer replacing when porting new code:**

- Process spawning: prefer Bun Shell `$` for simple commands; use `Bun.spawn`/`Bun.spawnSync` for streaming or process control. Keep existing `child_process` only where its exact semantics are needed.
- HTTP clients: `node-fetch`, `axios` → native `fetch`
- SQLite: `better-sqlite3` → `bun:sqlite`
- Env loading: `dotenv` → Bun loads `.env` automatically
- Runtime text/assets: prefer Bun imports such as `with { type: "text" }` or `Bun.file()` over copy steps or bundled fallback file reads.

**DO NOT replace (these work fine in Bun):**

- `os.homedir()` — do NOT replace with `Bun.env.HOME` or literal `"~"`
- `os.tmpdir()` — do NOT replace with `Bun.env.TMPDIR || "/tmp"` or hardcoded paths
- `fs.mkdtempSync()` — do NOT replace with manual path construction
- `path.join()`, `path.resolve()`, etc. — these are fine

**Import style:** Use the `node:` prefix for Node standard-library imports. Namespace imports are common, but named imports are acceptable where the surrounding code already uses them.

**Additional Bun conventions:**

- Prefer Bun Shell `$` for short, non-streaming commands; use `Bun.spawn` only when you need streaming I/O or process control.
- Use `Bun.file()`/`Bun.write()` for simple files and `node:fs/promises` for directory-oriented operations. Existing synchronous `node:fs` calls are acceptable when the calling flow is intentionally synchronous.
- Avoid `Bun.file().exists()` checks; use `isEnoent` handling in try/catch.
- Prefer `Bun.sleep(ms)` over `setTimeout` wrappers.

**Wrong:**

```typescript
// BROKEN: env vars may be undefined, "~" is not expanded
const home = Bun.env.HOME || "~";
const tmp = Bun.env.TMPDIR || "/tmp";
```

**Correct:**

```typescript
import * as os from "node:os";
import * as fs from "node:fs";
import * as path from "node:path";

const configDir = path.join(os.homedir(), ".config", "myapp");
const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "myapp-"));
```

## 5) Prefer Bun embeds (no copying)

Do not add new runtime asset copy steps. Keep assets in repo and prefer Bun embeds/imports; preserve existing explicit generation workflows such as `packages/coding-agent/src/export/html/tool-views.generated.js` (built from collab-web sources via `bun run gen:tool-views`).

- If upstream copies assets into a dist folder, replace with Bun-friendly embeds.
- Prompts are static `.md` files; use Bun text imports (`with { type: "text" }`) and Handlebars instead of inline prompt strings.
- Use `import.meta.dir` + `Bun.file` to load adjacent non-text resources.
- Keep assets in-repo and let the bundler include them.
- Eliminate copy scripts unless the user explicitly requests them or the package already has an intentional generation step.
- If upstream reads a bundled fallback file at runtime, replace filesystem reads with a Bun text embed import unless the current package already uses a generated asset pipeline.
  - Example (Codex instructions fallback):
    - `const FALLBACK_PROMPT_PATH = join(import.meta.dir, "codex-instructions.md");` -> removed
    - `import FALLBACK_INSTRUCTIONS from "./codex-instructions.md" with { type: "text" };`
    - Use `return FALLBACK_INSTRUCTIONS;` instead of `readFileSync(FALLBACK_PROMPT_PATH, "utf8")`

## 6) Port `package.json` carefully

Treat `package.json` as a contract. Merge intentionally.

- Keep existing `name`, `version`, `type`, `exports`, and `bin` unless the port requires changes.
- Replace npm/node scripts with Bun equivalents (e.g., `bun check`, `bun test`).
- Ensure dependencies use the correct scope.
- Do not downgrade dependencies to fix type errors; upgrade instead.
- Validate workspace package links and `peerDependencies`.

## 7) Align code style and tooling

- Keep existing formatting conventions.
- Do not introduce `any` unless required.
- Avoid dynamic imports unless they are required for optional dependencies, startup cost, or runtime-only modules; prefer top-level imports otherwise.
- Never build prompts in code; prompts are static `.md` files rendered with Handlebars.
- In `packages/coding-agent`, use `logger` from `@reverse/utils` for internal/runtime logging; CLI command files may use `console.*` for intentional user-facing output.
- Use `Promise.withResolvers()` instead of `new Promise((resolve, reject) => ...)`.
- Prefer ES `#` private fields for new encapsulated state. Constructor parameter properties already exist in current code and are acceptable; do not churn unrelated access modifiers while porting.
- Prefer existing helpers and utilities over new ad-hoc code.
  Preserve Bun-first infrastructure changes already made in this repo:
  - Runtime is Bun (no Node entry points for the main CLI).
  - Package manager is Bun (no npm lockfiles).
  - Heavy Node APIs should not be introduced casually; current source still uses selected Node APIs (`node:crypto`, `node:readline`, synchronous `node:fs`, and `child_process`) where they fit provider, CLI, or process-control semantics.
  - Lightweight Node APIs (`os.homedir`, `os.tmpdir`, `fs.mkdtempSync`, `path.*`) are kept.
  - CLI shebangs use `bun` (not `node`, not `tsx`).
  - TypeScript packages generally use source files directly; `@reverse/natives` exports generated native bindings from `packages/natives/native`.
  - CI workflows run Bun for install/check/test.

## 8) Remove old compatibility layers

Do not add parallel implementations for APIs replaced by the native architecture. Preserve intentional extension compatibility adapters under `packages/coding-agent/src/extensibility/legacy-*.ts` and `plugins/legacy-pi-compat.ts`; removing them would break existing pi extensions.

- Migrate native callers to replacement APIs; delete obsolete internal implementations.
- Keep legacy extension imports behind the existing adapters instead of routing new native code through them.
- Do not keep `*_v2` or parallel versions.

## 9) Update docs and references

- Replace pi-mono repo links where appropriate.
- Update examples to use Bun and correct package scopes.
- Ensure README instructions still match the current repo behavior.

## 10) Validate the port

Run the checks that cover the port after changes:

- `bun check`
- Run the focused Bun test or smoke scenario that exercises the changed behavior.
- If dependencies changed, run `bun install --frozen-lockfile` after updating `bun.lock`.

If the repo already has failing checks unrelated to your changes, call that out.
Tests use Bun's runner (not Vitest), but do not substitute an indiscriminate project-wide `bun test` for targeted behavioral verification.

## 11) Protect improved features (regression trap list)

If you already improved behavior locally, treat those as **non‑negotiable**. Before porting, write down
the improvements and add explicit checks so they don’t get lost in the merge.

- **Freeze the expected behavior**: add a short “before/after” note for each improvement (inputs, outputs,
  defaults, edge cases). This prevents silent rollback.
- **Map old → new APIs**: if upstream renamed concepts (hooks → extensions, custom tools → tools, etc.),
  ensure every old entry point still wires through. One missed flag or export equals lost functionality.
- **Verify exports**: check `package.json` `exports`, public types, and barrel files. Upstream ports often
  forget to re-export local additions.
- **Cover non‑happy paths**: if you fixed error handling, timeouts, or fallback logic, add a test or at
  least a manual checklist that exercises those paths.
- **Check defaults and config merge order**: improvements often live in defaults. Confirm new defaults
  didn’t revert (e.g., new config precedence, disabled features, tool lists).
- **Audit env/shell behavior**: if you fixed execution or sandboxing, verify the new path still uses your
  sanitized env and does not reintroduce alias/function overrides.
- **Re-run targeted samples**: keep a minimal set of "known good" examples and run them after the port
  (CLI flags, extension registration, tool execution).

## 12) Detect and handle reworked code

Before porting a file, check if upstream significantly refactored it:

```bash
# Compare the file you're about to port against what you have locally
git diff HEAD upstream/main -- path/to/file.ts
```

If the diff shows the file was **reworked** (not just patched):

- New abstractions, renamed concepts, merged modules, changed data flow

Then you must **read the new implementation thoroughly** before porting. Blind merging of reworked code loses functionality because:

Interactive mode is split across `packages/coding-agent/src/modes/interactive-mode.ts`, `modes/controllers/`, and supporting modules. Shared TUI components now live in `packages/tui/src/` (including `chat/`, `overlays/`, and `status-line/`). Port changes into the implementing module rather than recreating components in coding-agent, and keep interactive-mode wiring in sync.

1. **Defaults change silently** - A new variable `defaultFoo = [a, b]` may replace an old `getAllFoo()` that returned `[a, b, c, d, e]`.

2. **API options get dropped** - When systems merge (e.g., `hooks` + `customTools` → `extensions`), old options may not wire through to the new implementation.

3. **Code paths go stale** - A renamed concept (e.g., `hookMessage` → `custom`) needs updates in every switch statement, type guard, and handler—not just the definition.

4. **Context/capabilities shrink** - Old APIs may have exposed `{ logger, typebox, pi }` that new APIs forgot to include.

### Semantic porting process

When upstream reworked a module:

1. **Read the old implementation** - Understand what it did, what options it accepted, what it exposed.

2. **Read the new implementation** - Understand the new abstractions and how they map to old behavior.

3. **Verify feature parity** - For each capability in the old code, confirm the new code preserves it or explicitly removes it.

4. **Grep for stragglers** - Search for old names/concepts that may have been missed in switch statements, handlers, UI components.

5. **Test the boundaries** - CLI flags, SDK options, event handlers, default values—these are where regressions hide.

### Quick checks

```bash
# Find all uses of an old concept that may need updating
rg "oldConceptName" --type ts

# Compare default values between versions
git show upstream/main:path/to/file.ts | rg "default|DEFAULT"

# Check if all enum/union values have handlers
rg "case \"" path/to/file.ts
```

## 13) Quick audit checklist

Use this as a final pass before you finish:

- [ ] Import extensions follow the local package convention (no blanket `.js` stripping)
- [ ] No newly introduced Node-only APIs unless they match an existing justified pattern
- [ ] All package scopes updated
- [ ] `package.json` scripts use Bun
- [ ] Prompts are `.md` text imports (no inline prompt strings)
- [ ] No internal/runtime `console.*` in coding-agent; CLI user-facing output is intentional
- [ ] Assets load via Bun embed/import patterns, or through an existing intentional generation pipeline
- [ ] Tests or checks run (or explicitly noted as blocked)
- [ ] No functionality regressions (see sections 11-12)

## 14) Commit message format

When committing a backport, follow the repo format `<type>(scope): <past-tense description>` and keep the commit
range in the title.

```
fix(coding-agent): backported pi-mono changes (<from>..<to>)

packages/<package>:
- <type>: <description>
- <type>: <description> (#<issue> by @<contributor>)

packages/<other-package>:
- <type>: <description>
```

**Example:**

```
fix(coding-agent): backported pi-mono changes (9f3eef65f..52532c7c0)

packages/ai:
- fix: handle "sensitive" stop reason from Anthropic API
- fix: normalize tool call IDs with special characters for Responses API
- fix: add overflow detection for Bedrock, MiniMax, Kimi providers
- fix: 429 status is rate limiting, not context overflow

packages/tui:
- fix: refactored autocomplete state tracking
- fix: file autocomplete should not trigger on empty text
- fix: configurable autocomplete max visible items
- fix: improved table column width calculation with word-aware wrapping

packages/coding-agent:
- fix: preserve external config.yml edits on save (#1046 by @nicobailonMD)
- fix: resolve macOS NFD and curly quote variants in file paths
```

**Rules:**

- Group changes by package
- Use conventional commit types (`fix`, `feat`, `refactor`, `perf`, `docs`)
- Include upstream issue/PR numbers and contributor attribution for external contributions
- The commit range in the title helps track sync points

## 15) Intentional Divergences

Our fork has architectural decisions that differ from upstream. **Do not port these upstream patterns:**

### UI Architecture

| Upstream                                    | Our Fork                                                            | Reason                                                                                                                                         |
| ------------------------------------------- | ------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `FooterDataProvider` class                  | `StatusLineComponent`                                               | Simpler, integrated status line                                                                                                                |
| `ctx.ui.setHeader()` / `ctx.ui.setFooter()` | No-op stubs in current extension contexts                           | Not currently wired to replace the TUI status/header UI                                                                                        |
| `ctx.ui.setEditorComponent()`               | Wired in interactive mode; no-op stubs in ACP/RPC/headless contexts | Custom editor replacement works in the interactive TUI; non-TUI runtimes keep stubs                                                            |
| `ctx.ui.addAutocompleteProvider()`          | Wired in interactive mode; no-op stubs in ACP/RPC/headless contexts | Factory wrapping matches upstream; reverse's editor has no custom `triggerCharacters`, so wrapped providers surface at the built-in trigger points |
| `InteractiveModeOptions` options object     | Positional constructor args (options type still exported)           | Keep constructor signature; update the type when upstream adds fields                                                                          |

### Component Naming

| Upstream                     | Our Fork                |
| ---------------------------- | ----------------------- |
| `extension-input.ts`         | `packages/tui/src/overlays/hook-input.ts` |
| `extension-selector.ts`      | `packages/tui/src/overlays/hook-selector.ts` |
| `ExtensionInputComponent`    | `HookInputComponent`    |
| `ExtensionSelectorComponent` | `HookSelectorComponent` |

### API Naming

| Upstream                                 | Our Fork                                 | Notes                                     |
| ---------------------------------------- | ---------------------------------------- | ----------------------------------------- |
| `sessionManager.appendSessionInfo(name)` | `await sessionManager.setSessionName(name, source?)` | Async; returns whether accepted; automatic titles cannot overwrite a user title |
| `sessionManager.getSessionName()`        | `sessionManager.getSessionName()`        | Same (we unified to match upstream's RPC) |
| `agent.sessionName` / `setSessionName()` | `agent.sessionName` / `setSessionName()` | Same                                      |

### File Consolidation

| Upstream                                           | Our Fork                                                  | Reason                                        |
| -------------------------------------------------- | --------------------------------------------------------- | --------------------------------------------- |
| `clipboard.ts` + `clipboard-image.ts` (tool files) | `packages/coding-agent/src/utils/clipboard.ts` backed by `@reverse/natives` | Native implementation with a small TS wrapper |

### Test Framework

| Upstream                  | Our Fork                      |
| ------------------------- | ----------------------------- |
| `vitest` with `vi.mock()` | `bun:test` (`vi`, `mock`, `spyOn`, and assertions from `bun:test`) |
| `node:test` assertions    | `expect()` matchers           |

### Tool Architecture

| Upstream                            | Our Fork                                                                                                      | Notes                                                     |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| `createTool(cwd: string, options?)` | `await createTools(session: ToolSession, toolNames?)` via `BUILTIN_TOOLS`/`HIDDEN_TOOLS` | Factories accept `ToolSession` and return `Tool`, `null`, or a promise |
| Per-tool `*Operations` interfaces   | Only current per-tool override interfaces remain (for example `GlobOperations` in `tools/glob.ts`); `FindOperations` survives only in the legacy shim (`src/extensibility/legacy-pi-coding-agent-shim.ts`) after the find→glob rename | Used for SSH/remote overrides where present               |
| Node.js `fs/promises` everywhere    | Bun file APIs for simple file writes/reads, `node:fs/promises` for dirs, selected sync `node:fs` where needed | Prefer Bun APIs when they simplify                        |

### Auth Storage

| Upstream                        | Our Fork                                    | Notes                                        |
| ------------------------------- | ------------------------------------------- | -------------------------------------------- |
| `proper-lockfile` + `auth.json` | Local `agent.db` (`bun:sqlite`) or `RemoteAuthCredentialStore` | Broker mode replaces local credential storage; runtime/config/env keys remain separate |
| Single credential per provider  | Usage-aware multi-account selection with priority/reserve policy | Preserve session affinity, plan/model access checks, blocks, and refresh single-flight/leases |

Native auth callers use namespaces on `AuthStorage`: `credentials`, `keys`,
`oauth`, `sessions`, `usage`, `health`, `limits`, `resets`, and `blocks`.
Implementations live in `packages/ai/src/auth/`; `auth-storage.ts` composes
them. Do not port upstream flat methods over this facade. See
[auth-broker-gateway.md](./auth-broker-gateway.md) for remote-store behavior.

### Extensions

| Upstream                                                               | Our Fork                                                                                                                                                                                                                                                                                     |
| ---------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `jiti` for TypeScript loading                                          | Bun loading through the existing `loadLegacyPiModule()` adapter (including legacy specifier rewriting)                                                                                                                                                                                                                                                                        |
| `pkg.pi` manifest field                                                | `pkg.reverse` preferred; fallback to `pkg.pi` remains                                                                                                                                                                                                                                            |
| `StringEnum` from `pi-ai`                                              | `Type.Enum` from `pi.typebox`, or `pi.arktype.enumerated(...)`; `pi-ai` no longer exports `StringEnum`                                                                                                                                                                                       |
| `formatSize` from `pi-coding-agent`                                    | `formatBytes` from `@reverse/utils`                                                                                                                                                                                                                                                      |
| Upstream resource/package/settings managers as the native architecture | Capability-based discovery (`loadCapability(...)`), session-scoped `Settings` instances, and `EventBus`; legacy extension imports of `DefaultResourceLoader`, `DefaultPackageManager`, and `SettingsManager` are compatibility shims in `legacy-pi-coding-agent-shim.ts`, not the native implementation |
| `SettingsManager.create(cwd)` returns a synchronous manager with `getGlobalSettings()`/`getProjectSettings()` | The shim's `SettingsManager.create()` is synchronous and resolves the active extension session's `Settings`, then a live instance matching `cwd`/`agentDir`, or an isolated fallback; `Settings` exposes `getGlobalSettings()`/`getProjectSettings()` that deep-clone the raw global/project layers so extensions can read their own namespaced keys (#10397) |

### Skip These Upstream Features

When porting, **skip** these files/features entirely:

- `footer-data-provider.ts` — we use StatusLineComponent
- `clipboard-image.ts` — image clipboard support is exposed through `packages/coding-agent/src/utils/clipboard.ts` backed by `@reverse/natives`
- GitHub workflow files — we have our own CI
- `models.generated.ts` — regenerate the local `packages/catalog/src/models.json` via `bun run gen:models`; provider/model/auth policy is authored in `packages/catalog/src/compat/rules/**/*.kdl`

### Features We Added (Preserve These)

These exist in our fork but not upstream. **Never overwrite:**

- `StatusLineComponent` in interactive mode
- Multi-credential auth with session affinity, usage-aware routing, and optional broker/gateway storage
- `@reverse/reversetype` schemas and their provider-boundary JSON Schema normalization ([reversetype-guide.md](./reversetype-guide.md))
- Capability-based discovery system (`defineCapability`, `registerProvider`, `loadCapability`, `skillCapability`, etc.)
- MCP/Exa/SSH integrations
- LSP writethrough for format-on-save
- Bash interception (`checkBashInterception`)
- Fuzzy path suggestions in read tool
