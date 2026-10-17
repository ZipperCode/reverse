# rva

`rva` is an independent terminal coding agent built from an upstream source snapshot of oh-my-pi, developed in repository `https://github.com/ZipperCode/rev`.

## Architecture & Capabilities

`rva` runs as a fully local, self-contained terminal coding agent:

- **Local Execution**: Tools (read, bash, edit, write, grep, glob, ast_grep, ast_edit, lsp, etc.), session management, subagents, and memory backends run locally without dependency on external hosted coordination or relay infrastructure.
- **Provider Access**: Model provider access (Anthropic, OpenAI, Google, DeepSeek, local inference via Ollama / llama.cpp / vLLM, and compatible endpoints) with native compaction and secret obfuscation.
- **Voice & Realtime**: Integrated voice/realtime support (`src/live/`) connecting directly to supported audio/realtime providers.
- **Local Recording & Playback**: Terminal session recording via `/record` and playback via `rva play` using `.ompcast` captures stored locally under temporary recordings (`rva-recordings`).
- **HTML Export**: Standalone session export via `rva --export <session.jsonl> [output.html]` and the `/export` slash command with self-contained inlined React tool views.
- **Extensibility & Plugins**: Full support for local plugin loading and linking via `rva install <path>` and `rva plugin` commands.
- **Local Skills**: Local skill discovery (`rva skill list [dir] [--json]`), `manage_skill`, and skill store resolution via `skills.lock.json`.

All external hosted coordination services (collab relays, live screen broadcasting, cloud clip upload, remote skillshare registry, and centralized auto-QA reporting) have been completely removed.

## Supported Local Workflows

- **Development Launcher**: `sh packages/coding-agent/scripts/rva` (or `bun run dev` / `bun run rva`) restores the launch working directory via preload shims without bunfig pollution.
- **Compiled Standalone Binary**: `packages/coding-agent/dist/rva` provides a self-contained executable with embedded native bindings and ad-hoc code signature.
- **Single-Turn Execution**: `rva -p "read src/index.ts"` executes prompt and tool calls in print mode.
- **Multi-Turn Resumption**: `rva -p --continue "summarize"` rehydrates the prior session's user, tool, and assistant history.
- **Interactive Terminal (TUI)**: `rva` launches the full interactive workspace with prompt composer, live status line, and `/new` session switching.
- **Terminal Recording & Playback**: `/record` starts and stops local session captures stored in `$TMPDIR/rva-recordings/*.ompcast`; `rva play <recording> --speed 10 --idle-limit 0.1` provides terminal replay without network access.
- **Session HTML Export**: `rva --export <session.jsonl> [output.html]` generates standalone self-contained HTML transcripts with inlined React tool views.
- **Local Skills & Plugins**: `rva skill list [dir] [--json]` discovers local `.rva/skills`; `rva install <local-plugin-path>` links development plugins into the isolated user plugin store.
- **Configuration & Localization (i18n)**: Manage settings via `rva config [list|get|set|reset]`. Full Chinese localization (`zh-CN`) is available for configuration labels, descriptions, group headers, and CLI help, configurable via `rva config set language zh-CN`, in the interactive `/settings` panel (Appearance → Display → Language), or via the `RVA_LANG=zh-CN` environment override, while keeping all setting identifiers, enum values, and JSON machine output canonical.

## Verification Evidence

A clean-room, zero-external-credential loopback smoke harness verified both the development launcher (`scripts/rva`) and compiled standalone binary (`dist/rva`):

1. **CLI Baseline**: `--version`, `--help`, `stats --help`, and `--smoke-test` exit 0. Help tables confirm all 7 excised commands (`collab`, `join`, `share`, `stream`, `clip`, `grievances`, `update`) are removed from command listings.
2. **Relative Path Tool Execution**: `read hello.txt` executed the native `read` tool against cwd fixtures, returned expected content through local Anthropic Messages SSE streaming, printed `RVA_SMOKE_OK`, and wrote durable JSONL session entries.
3. **Session Continuation**: `--continue` replayed exact prior turns (user message, tool use, tool result, assistant output, follow-up prompt) over loopback SSE and returned `RVA_RESUME_OK`.
4. **Excised Command Enforcement**: All 7 removed commands fail fast with exit code 1, print rejection guidance, and make zero network requests.
5. **Isolated Extensibility**: `rva skill list --json` returned project fixture skills; `rva install` linked fixture packages strictly into isolated test environments without host leakage.
6. **PTY Terminal & Recording**: Interactive TUI launched under a real Darwin PTY, processed interactive turns, switched sessions (`/new`), recorded screen sessions (`/record`), and replayed recorded `.ompcast` files locally via `rva play` with zero remote calls.
7. **Standalone HTML Export**: Headless Chrome (v155) loaded exported session HTML via Chrome DevTools Protocol (CDP); DOM inspection confirmed chat messages and tool outputs rendered offline, and network interception verified zero outgoing requests to share, gist, or remote services.

> **Provider Notes**: Verification was conducted using an offline loopback provider harness; remote providers require valid user-configured API credentials. Local Apple Foundation Models are unavailable on this machine due to upstream native build constraints requiring Swift 6.4 / macOS 27 SDK; the feature implementation remains intact in source.

## Building Locally

### Prerequisites

- [Bun](https://bun.sh) >= 1.3.14
- Python >= 3.10 (required for eval tool schema inference and full test runner; e.g. via Homebrew `/opt/homebrew/opt/python@3.12/libexec/bin` on macOS)
- Rust / Cargo toolchain
- Ninja and pkg-config for native bindings

### Testing

```sh
PATH="/opt/homebrew/opt/python@3.12/libexec/bin:$PATH" bun run test:ts
```
### Build Steps

```sh
bun install
bun run gen:tool-views
bun run build:native
bun run build
```

The resulting standalone executable binary is built at `packages/coding-agent/dist/rva`.
## License

MIT License. See [LICENSE](./LICENSE) and [THIRD-PARTY-NOTICES.txt](./THIRD-PARTY-NOTICES.txt) for original copyright notices and third-party dependency disclosures.
