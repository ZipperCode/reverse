# Skills

Skills are file-backed capability packs discovered at startup and exposed to the model as:

- lightweight metadata in the system prompt (name + description)
- on-demand content via the `read` tool against `skill://...`
- optional interactive `/skill:<name>` commands

This document covers current runtime behavior in `packages/coding-agent/src/extensibility/skills.ts`, `packages/coding-agent/src/discovery/builtin.ts`, `packages/coding-agent/src/internal-urls/skill-protocol.ts`, and `packages/coding-agent/src/discovery/agents-md.ts`.

## What a skill is in this codebase

A discovered skill is represented as:

- `name`
- `description`
- `filePath` (the `SKILL.md` path)
- `baseDir` (skill directory)
- source metadata (`provider`, `level`, path)

The capability validator only requires `name` and `path`; individual providers impose additional frontmatter requirements. Matching quality depends on `description` being meaningful.

## Required layout and SKILL.md expectations

### Directory layout

For conventional provider roots (native/Claude/Codex/Agents/plugins), skills are discovered as **one level under `skills/`**:

- `<skills-root>/<skill-name>/SKILL.md`

Nested patterns like `<skills-root>/group/<skill>/SKILL.md` are not discovered recursively. The Claude-plugin provider also accepts manifest-declared skill directories containing `SKILL.md` directly, in addition to their immediate children. Agent Plugins packages use only the fixed `skills/<name>/SKILL.md` layout; registry-installed Skillshare packages have a root `SKILL.md`.

For `skills.customDirectories`, scanning uses the same non-recursive layout (`*/SKILL.md`).

```text
Provider-discovered layout (non-recursive under skills/):

<root>/skills/
  ├─ postgres/
  │   └─ SKILL.md      ✅ discovered
  ├─ pdf/
  │   └─ SKILL.md      ✅ discovered
  └─ team/
      └─ internal/
          └─ SKILL.md  ❌ not discovered by provider loaders

Custom-directory scanning is also non-recursive, so nested paths are ignored unless you point `customDirectories` at that nested parent.
```

### `SKILL.md` frontmatter

Supported frontmatter fields on the skill type:

- `name?: string`
- `description?: string`
- `globs?: string[]`
- `alwaysApply?: boolean`
- `hide?: boolean`
- `disableModelInvocation?: boolean` (Agent Skills equivalent of `hide`; normalized from kebab-case `disable-model-invocation`)
- additional keys are preserved as unknown metadata by conventional scanners
- `enabled: false` skips a skill in conventional scanners and Skillshare discovery

`globs` and `alwaysApply` are metadata here, not automatic skill-invocation controls. Agent Plugins packages use stricter Agent Skills validation instead of the permissive scanner: required name/description, directory-name agreement, valid naming, and a closed frontmatter field set. OMP-specific fields such as `hide` and `enabled` are not accepted there.

Current runtime behavior:

- `name` defaults to the skill directory name
- `description` is required for:
  - native `.omp` provider skill discovery (`requireDescription: true`)
  - `omp-plugins` extension-package skills and the `github` provider (`.github/skills/`), which also pass `requireDescription: true`
  - `skills.customDirectories` scans via `scanSkillsFromDir` in `src/discovery/helpers.ts` (non-recursive)
- the claude/codex/agents/opencode/claude-plugins providers can load skills without description
- `agent-plugins` validates required `name` and `description` against the Agent Skills specification

## Discovery pipeline

`loadSkills()` in `packages/coding-agent/src/extensibility/skills.ts` does three passes:

1. **Capability providers** via `loadCapability("skills")` (the managed/auto-learn provider's skills are skipped here and handled in pass 3)
2. **Custom directories** via `scanSkillsFromDir(..., { requireDescription: true })` (one-level directory enumeration). A custom-directory skill overrides a same-named default provider skill; the displaced provider skill stays reachable under its namespaced name unless its body is identical.
3. **Managed (auto-learn) skills** (`omp-managed` provider) resolved dead-last, so any same-named enabled authored skill from a provider or custom directory takes precedence

If `skills.enabled` is `false`, discovery returns no skills.

### Built-in skill providers and precedence

Provider ordering is priority-first (higher wins), then registration order for ties.

Current registered skill providers:

1. `native` (priority 100) — `.omp` user/project skills via `src/discovery/builtin.ts`
2. `skillshare` (priority 95) — packages pinned in project `.omp/skills.lock.json` or the user agent directory's `skills.lock.json`, loaded from the Skillshare store; authored skills still outrank these on name collisions
3. `omp-plugins` (priority 90) — `skills/` bundled next to extension packages loaded through `extensions:`, `--extension`/`-e`, or installed plugins under `~/.omp/plugins/node_modules`
4. `claude` (priority 80)
5. `agent-plugins` (priority 75) — portable packages with a standard root `plugin.json`; conventional plugin providers defer their skills/MCP discovery to this provider
6. priority 70 group (in registration order):
   - `claude-plugins`
   - `agents`
   - `codex`
7. `opencode` (priority 55)
8. `github` (priority 30) — `.github/skills/<name>/SKILL.md` (GitHub Agent Skills layout, project-only)
9. `omp-managed` (priority 5) — auto-learn skills under `~/.omp/agent/managed-skills`, registered in `src/discovery/builtin.ts` and discovered unconditionally (only writing/nudging is gated by `autolearn.enabled`); always defers to a same-named authored skill
10. `builtin-skills` (priority 1) — the six reverse skills (`reverse-lab`, `reverse-tool-guide`, `android-reverse`, `windows-reverse`, `web-protocol-reverse`, `native-binary-reverse`) shipped inside the package under `src/discovery/builtin-skills/`. Files are imported with `{ type: "file" }`, so they exist in npm/source installs and are embedded in the compiled binary. The repository-root `.agents/skills/` copies stay for project discovery; a test enforces byte equality and identical copies deduplicate at collision resolution.

Capability dedup key is skill name; the first item with a given name wins in the deduped `items` view. `loadSkills()` resolves same-name collisions itself (see "Collision and duplicate handling"). An authored project/user skill outranks `builtin-skills`, so bundling does not shadow local overrides.

### Source toggles and filtering

`loadSkills()` applies these controls:

- source toggles: `enableCodexUser`, `enableClaudeUser`, `enableClaudeProject`, `enablePiUser`, `enablePiProject`, `enableAgentsUser`, `enableAgentsProject`
- `disabledExtensions` entries with `skill:<name>`
- `ignoredSkills` (exclude; glob patterns)
- `includeSkills` (include allowlist; glob patterns; empty means include all)

Filter order is:

1. not disabled by `disabledExtensions`
2. source enabled
3. not ignored
4. included (if include list present)

The `agents` provider (`.agent[s]/skills`) has its own `enableAgentsUser`/`enableAgentsProject` toggles — disabling Claude/Codex/Pi does **not** turn it off. Foreign user-level providers are opt-in through `enabledProviders`; their project roots still load by default. Native OMP sources and marketplace plugins registered under `~/.omp/plugins` also load by default. For `claude-plugins`, the opt-in controls only plugins from Claude Code's own user registry.

### Collision and duplicate handling

- Capability dedup keeps the first skill per name (highest-precedence provider) for the deduped `items` view; `loadSkills()` works from the pre-dedup superset so lower-precedence copies can still be examined.
- `extensibility/skills.ts` then:
  - de-duplicates identical files by `realpath` (symlink-safe)
  - drops a later same-named skill silently when its body is identical and its parsed frontmatter is deeply equal to a loaded one (the same skill installed twice, e.g. a plugin copy mirrored into `~/.agents/skills`). When the incoming skill outranks the bare holder (below), the identical copies it supersedes (the bare holder and any namespaced aliases) are dropped instead, so an override never re-admits its own duplicate
  - when same-named skills differ, the higher-precedence skill keeps the bare name and every other variant receives a `<namespace>/<name>` suffix, with collision warnings naming the paths. Precedence: an authored skill outranks a registry-installed package (the `skillshare` provider, `omp skill install`); a custom-directory skill outranks a provider skill (#7190); otherwise whichever was admitted first — provider-priority order for providers, array order within `skills.customDirectories` for custom directories — keeps the bare name. The namespace is the plugin identity from provider metadata when the provider tracks one (every registry-backed provider supplies one: `claude-plugins` and `agent-plugins` use the plugin name, `omp-plugins` the extension package name, `skillshare` the package name — so an installed plugin namespaces by its own name rather than its cache path's version segment, and the namespace survives plugin updates); otherwise the directory owning the skill's `skills/` tree, or the skill root's directory name, falling back to the provider id for dotted homes such as `~/.claude/skills`. A namespaced slot that is itself already taken by a differing skill gets a `~2`, `~3`, … suffix; no differing skill is dropped without a warning.
  - rejects a raw frontmatter `name` containing `/` or `\` (with a warning) for every provider and custom directory: the separator is reserved for the namespaced form and for `skill://<name>/<path>` resolution, so a raw name cannot claim a namespaced address
  - keeps the convenience `loadSkillsFromDir({ dir, source })` API as a thin adapter over `scanSkillsFromDir`
- Namespaced skills resolve through `skill://<namespace>/<name>[/<path>]` and the `/skill:<namespace>/<name>` token, both leading and mid-prompt (a mid-prompt token accepts exactly one `/`; deeper paths are left as prose). Because skill names never contain `/`, an exact `<host>/<first segment>` match is unambiguous and takes precedence over reading that segment as a path relative to a bare skill of the same name as the namespace.
- Custom-directory skills are merged after provider skills and outrank a same-named default-path provider skill regardless of admission order (#7190): the custom-directory skill keeps the bare name, and the provider skill is re-admitted under its namespaced name (suffixed if that slot is taken) when it differs or dropped when it is identical. Among two custom directories, the first one in `skills.customDirectories` keeps the bare name and the other is namespaced.
- `disabledExtensions` (`skill:<name>`) and `skills.ignoredSkills` are applied to both the raw and the final name, so a namespaced alias cannot bypass an exclusion. `skills.includeSkills` is applied to the final listing only, after every name is resolved, so `second/*` selects a namespaced skill even though the bare skill it collided with is not itself included.

## Runtime usage behavior

### System prompt exposure

System prompt construction (`src/system-prompt.ts`) uses discovered skills as follows:

- if an active tool declares `readsSkillUris: true`:
  - include the discovered skills list, excluding hidden skills
  - mounted `xd://` tools count when their capability metadata is projected
- otherwise:
  - omit the discovered list

When no tool metadata is supplied, the prompt builder uses the presence of `read` as a compatibility fallback.

`hide: true` does not disable the skill. Hidden skills are still loaded and remain reachable through `skill://<name>` and `/skill:<name>` when skill commands are enabled.

Task tool subagents receive the session's discovered/provided skills list via normal session creation; there is no per-task skill pinning override.

### Interactive `/skill:<name>` commands

If `skills.enableSkillCommands` is true, interactive mode registers one slash command per discovered skill.

`/skill:<name> [args]` behavior:

- recognizes the traditional leading form and a whitespace-delimited `/skill:<name>` token embedded in ordinary prose
- for an embedded token, removes the token and passes the surrounding prose as arguments
- does not treat embedded tokens as invocations when the draft starts with another slash command or a local bash/Python execution sigil
- reads the skill file directly from `filePath`
- strips frontmatter
- wraps the body with skill name, base directory, and optional user arguments, then injects it as a custom message
- delivery mode follows the **submission keybinding**:
  - **Enter** → invokes the skill on the `steer` queue while streaming (matches free-text Enter, which also steers), or as a normal idle prompt when the agent is not streaming
  - **Ctrl+Q / Ctrl+Enter** (default `app.message.followUp` bindings) → invokes the skill on the `followUp` queue while streaming, or as a normal idle prompt when the agent is not streaming

There is no flag, mode-selector, or frontmatter knob to override delivery mode — the keybinding _is_ the choice, identical to free-text routing during streaming. Both submission paths dispatch through `#invokeSkillCommand` in `input-controller.ts`, which delegates to `invokeSkillCommandFromText` in `src/modes/skill-command.ts`.

Invoked skill content is identified by invocation kind, each with its own prompt template (in `src/prompts/skills/`, rendered by `buildSkillPromptMessage` in `src/extensibility/skills.ts`):

- **User-invoked** (`user-invocation.md`, used by `/skill:<name>`): the message opens by announcing that the user invoked the skill, embeds the skill body, and appends the skill directory (`[Skill directory: <baseDir>]`) with instructions to resolve the skill's relative paths (scripts, templates) against it, plus optional `User: <args>`.
- **Autoloaded** (`autoload.md`): a minimal provenance-only format — body followed by `Skill: <path>` and optional `User: <args>` — used when subagents auto-inject skills declared via the `autoloadSkills` agent frontmatter field; these hidden messages must not claim the user invoked them.

## `skill://` URL behavior

`src/internal-urls/skill-protocol.ts` supports:

- `skill://<name>` → resolves to that skill's `SKILL.md` for `read`; in `bash` it is the skill directory (instructions at `skill://<name>/SKILL.md`), and `realpath`/`readlink` print the physical path
- `skill://<name>/<relative-path>` → resolves inside that skill directory

```text
skill:// URL resolution

skill://pdf
  -> <pdf-base>/SKILL.md

skill://pdf/references/tables.md
  -> <pdf-base>/references/tables.md

Guards:
- reject absolute paths
- reject `..` traversal
- reject any resolved path escaping <pdf-base>
```

Resolution details:

- skill name must match exactly
- relative paths are URL-decoded
- absolute paths are rejected
- path traversal (`..`) is rejected
- resolved path must remain lexically within `baseDir`
- Agent Plugins and Skillshare skills also realpath-check containment within their package root, preventing symlink escapes; symlinks to another location inside that package are allowed
- directories return directory listings
- missing files return an explicit `File not found` error

Content type:

- Markdown paths => `text/markdown`
- `.json` => `application/json`
- other files => `text/plain`

No fallback search is performed for missing assets.

MCP-advertised skills:

- When no loaded skill owns the name in a `skill://` URL, `read` serves the resource an MCP server advertises under exactly that URI (for example Figma's `skill://figma/figma-use/SKILL.md`), like `mcp://skill://…` but with line selectors. Ownership is decided on the normalized URL as above, so a loaded bare or namespaced skill always wins; URI templates are matched only through an explicit `mcp://`.
- The read waits for MCP servers that are still connecting or listing their resources, exactly as an `mcp://` read does, before reporting `Unknown skill`; the wait is bounded by the MCP connect/request timeouts and ends when the read is cancelled.
- Actions that need a local file (`%load`, plan-mode write checks, the `:img` selector) report `Unknown skill` without contacting MCP.
- MCP-served text keeps `read`'s normal result limits; only local skill files read whole.
- `omp read` starts MCP servers only when a read reaches an MCP resource, so reading a local skill never spawns them.

## Declaring external tool dependencies

Skills can declare the external tools they expect on the machine running `reverse`:

```yaml
---
name: android-reverse
description: Android APK and native library analysis.
metadata:
  requires: jadx
  requiresOptional: apktool, adb, frida
---
```

- `metadata.requires` lists tools the skill needs; `metadata.requiresOptional` lists tools it can use when present.
- Values are comma/whitespace-separated strings (or a string list in reverse-local skills). Ids are lowercase.
- `metadata` is the portable location because the Agent Skills schema is closed for plugin skills. Top-level `requires` / `requiresOptional` are accepted only for skills outside that schema.

Dependency checking is read-only and local:

- Tools are resolved through `$PATH` plus catalog-owned directories (Android SDK, Homebrew, Python user scripts, IDA install locations, etc.).
- The built-in catalog in `packages/coding-agent/src/extensibility/skill-tool-catalog.ts` owns all install hints. A declared id that is not in the catalog is still probed as a command name, but it never produces an install hint.
- Nothing is installed, downloaded, or executed automatically. Missing tools only produce an advisory notice.
- A present tool is silent; a missing optional tool is silent as well.

The notice appears when the skill's instruction file is loaded:

- `read skill://<name>` and `read skill://<name>/SKILL.md`
- `/skill:<name>`
- autoloaded subagent skills (`autoloadSkills`)

It is prepended to the instruction text only when a required tool is missing. Subpath reads such as `skill://<name>/references/notes.md` are returned unchanged, as are `:raw` reads.

Use the CLI to inspect dependencies for a directory:

```sh
reverse skill check
reverse skill check ./my-project --json
```

The command exits non-zero only when a required tool is missing; missing optional tools never fail it. JSON output includes each requirement's `id`, `optional`, `foundPath`, and `hint`.

Skills are still discovered and loaded when a required tool is absent: the dependency notice is guidance, not a gate. Skills should describe a fallback path for optional tools and treat `requires` as "install this before relying on the primary workflow". Unknown tool ids are treated as unsupported by the catalog: they can be probed but have no trusted installation guidance.

## MCP helper services

Optional MCP servers live in a separate trusted catalog, `packages/coding-agent/src/extensibility/mcp-service-catalog.ts`, because they are not PATH binaries. Each entry owns:

- prerequisite catalog ids (`requires`), which are checked with the same read-only resolver as skill dependencies;
- trusted install methods (package manager argv or manual-only instructions);
- a server config template, server name, transport, and start command;
- the configuration path (`.reverse/mcp.json` for a project, `~/.reverse/agent/mcp.json` for the user; `.rva` fallback supported);
- a structured usage guide (canonical operation, when to use, output limits, fallback, examples).

`reverse setup reverse --json` (or `rva setup reverse --json`) reports them under `services`, separate from `tools`, with three independent states:

- `prerequisitesReady` (and the backward-compatible alias `ready`) — the prerequisite CLI tools were found; never means configured or connected.
- `configured` / `configuredScopes` / `enabled` — a read-only probe for an `mcpServers[serverName]` entry in the resolved project and user config files. `enabled` is `null` when unconfigured and reflects `enabled`/`disabledServers`/`enabledServers` when configured.
- `connection` — always `"unknown"`; inspection never starts a server or performs an MCP handshake.

`configPaths.project` and `configPaths.user` are resolved with `getMCPConfigPath` from the running installation (not the catalog's display hint). A service is never reported with a `foundPath`, and inspection never writes `mcp.json`. `reverse setup reverse <service-id>` (or `rva setup reverse <service-id>`) prints the resolved paths, configured scopes, start command, config snippet, prerequisites, risk notes, and manual fallback. Automated installs remain limited to catalog argv and require explicit confirmation in the interactive panel.

The `reverse-tool-guide` skill exposes the same guidance on demand:

- `skill://reverse-tool-guide/references/cli-tools.md` — canonical CLI commands and fallback tiers.
- `skill://reverse-tool-guide/references/mcp-services.md` — MCP prerequisites, snippets, and canonical operations.

Skills and MCP servers cannot inject installation argv: only the trusted catalog can supply a command, and non-interactive `--check` / `--json` modes never execute one.


## Skills vs AGENTS.md, commands, tools, hooks

### Skills vs AGENTS.md

- **Skills**: named, optional capability packs selected by task context or explicitly requested
- **AGENTS.md/context files**: persistent instruction files loaded as context-file capability and merged by level/depth rules

`src/discovery/agents-md.ts` walks ancestor directories from `cwd` to discover standalone `AGENTS.md` files. For repositories nested under the user's home directory, it continues through enclosing workspace directories up to but not including the home directory. With no repository root under home, the home boundary remains included. Otherwise it stops at the repository root, or at the filesystem root when no repository root is known outside home. Files in hidden owner directories are skipped.

### Skills vs slash commands

- **Skills**: model-readable knowledge/workflow content
- **Slash commands**: user-invoked command entry points
- `/skill:<name>` is a convenience wrapper that injects skill text; it does not change skill discovery semantics

### Skills vs custom tools

- **Skills**: documentation/workflow content loaded through prompt context and `read`
- **Custom tools**: executable tool APIs callable by the model with schemas and runtime side effects

### Skills vs hooks

- **Skills**: passive content
- **Hooks**: event-driven runtime interceptors that can block/modify behavior during execution

## Practical authoring guidance tied to discovery logic

- Put each skill in its own directory: `<skills-root>/<skill-name>/SKILL.md`
- Always include explicit `name` and `description` frontmatter
- Keep referenced assets under the same skill directory and access with `skill://<name>/...`
- For nested taxonomy (`team/domain/skill`), point `skills.customDirectories` to the nested parent directory; scanning itself remains non-recursive
- On a name collision, the higher-precedence skill keeps the bare name; identical copies collapse, and differing copies remain reachable under a namespace.
