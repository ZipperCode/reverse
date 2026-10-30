# reverse

`reverse` is an independent terminal reverse-engineering and coding agent built from an upstream source snapshot of oh-my-pi, developed in repository `https://github.com/ZipperCode/rev`.

reverse 基于 omp 改造，版本跟随 omp 稳定版迭代。当前同步目标为 [oh-my-pi 18.14.0](https://github.com/can1357/oh-my-pi/releases/tag/v18.14.0)，同步上游功能与修复，同时保留 reverse 的逆向能力、独立配置和中文设置。升级基线与验证流程见[上游同步指南](docs/porting-from-pi-mono.md#reverse--oh-my-pi-release-tracking)。源码开发使用 Bun 1.4.4；升级后重新构建原生模块与可执行文件。

## Quickstart & Installation

### Is npm required?
**No.** `reverse` does not require `npm` or Node.js. It is packaged as a standalone compiled executable containing embedded Bun bytecode and pre-compiled native bindings.

---

### For End Users: Installing Standalone Binary

Once standalone binaries are released, download the executable for your platform. **No Bun, Node.js, or npm is required on the user machine.**

#### macOS & Linux
```sh
# 1. Create target user directory
mkdir -p ~/.local/bin

# 2. Preserve any existing binary before installing (avoid accidental overwrite)
test ! -e ~/.local/bin/reverse || mv ~/.local/bin/reverse ~/.local/bin/reverse.bak.$(date +%s)

# 3. Install binary with executable permissions
install -m 755 ./reverse-darwin-arm64 ~/.local/bin/reverse  # or reverse-linux-x64 / reverse-darwin-x64

# 4. Verify version and run setup
~/.local/bin/reverse --version
~/.local/bin/reverse setup
```

#### Windows (PowerShell)
```powershell
# 1. Create target directory
$binDir = Join-Path $HOME ".local\bin"
if (!(Test-Path $binDir)) { New-Item -ItemType Directory -Path $binDir | Out-Null }

# 2. Preserve any existing binary
$target = Join-Path $binDir "reverse.exe"
if (Test-Path $target) { Move-Item -Path $target -Destination "$target.bak.$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())" }

# 3. Copy binary to destination
Copy-Item -Path .\reverse-windows-x64.exe -Destination $target

# 4. Verify version and run setup
& "$target" --version
& "$target" setup
```

Ensure `~/.local/bin` (or `%USERPROFILE%\.local\bin`) is in your `PATH`.

#### Release Assets (When Published)
Standalone release assets will be published to the GitHub Releases page (`https://github.com/ZipperCode/rev/releases`) when a release is tagged:

| Platform / Architecture | Asset Name |
|---|---|
| macOS (Apple Silicon, arm64) | `reverse-darwin-arm64` |
| macOS (Intel, x64) | `reverse-darwin-x64` |
| Linux (x86_64) | `reverse-linux-x64` |
| Linux (arm64 / aarch64) | `reverse-linux-arm64` |
| Windows (x86_64) | `reverse-windows-x64.exe` |

*(Note: Releases are not yet published to GitHub Releases; download assets will become available upon release publication. Cryptographic signatures and release checksums will accompany official release tags).*

---

### For Developers: Building from Source & Dev Helpers

If you are developing or building from this repository, the development toolchain is required:

#### Prerequisites
- [Bun](https://bun.sh) 1.4.4 (development/package-manager pin; standalone binaries embed their runtime)
- Python >= 3.10 (required for eval engine and test runner)
- Rust / Cargo toolchain (for native crates `crates/*`)
- Ninja and pkg-config for native bindings

#### Build Steps
```sh
# 1. Install workspace dependencies
bun install

# 2. Generate the HTML export viewer
bun run gen:export-viewer

# 3. Build native addons (pi_natives)
bun run build:native

# 4. Compile standalone reverse binary
bun run build
```

The resulting standalone executable is output to:
- Unix: `packages/coding-agent/dist/reverse`
- Windows: `packages/coding-agent/dist/reverse.exe`

Cross-compilation for other platforms:
```sh
CROSS_TARGET=linux-x64 bun run build
# Outputs to packages/coding-agent/dist/reverse-linux-x64
```

#### Developer Local Install Helper
For repository developers with Bun installed, a convenience installer script is available to test local installations:

```sh
# Install built binary into ~/.local/bin
bun run install:local

# Or install to a specific testing directory
bun run install:local --bin-dir /tmp/test-bin

# Inspect without making changes (dry-run)
bun run install:local --dry-run

# Check installed binary identity and PATH status
bun run install:local --check

# Uninstall
bun run uninstall:local
```

Windows 重装会先暂存源程序，再将旧目标改名后原子替换，不强制结束正在运行的会话；`--binary` 与安装目标为同一路径也可重装。旧会话继续使用旧文件，重新启动后使用新版。默认保留旧程序备份；指定 `--no-backup` 时，为避开运行中文件锁，仍可能留下 `.retired.*` 文件。

> **Note on Binary Validation**: The `--binary` validator in `install:local` performs a local identity sanity check by running `<binary> --version` to verify the output matches the expected `reverse/` identifier before copying. It is an identity sanity guard, not a cryptographic authenticity or integrity verification (cryptographic signatures and release checksums belong to the official release pipeline).

#### Run Tests
```sh
PATH="/opt/homebrew/opt/python@3.12/libexec/bin:$PATH" bun run test:ts
```

---

## Architecture & Capabilities

`reverse` runs as a fully local, self-contained terminal reverse-engineering and coding agent:

- **Local Execution**: Tools (read, bash, edit, write, grep, glob, ast_grep, ast_edit, lsp, etc.), session management, subagents, and memory backends run locally without dependency on external hosted coordination or relay infrastructure.
- **Provider Access**: Model provider access (Anthropic, OpenAI, Google, DeepSeek, local inference via Ollama / llama.cpp / vLLM, and compatible endpoints) with native compaction and secret obfuscation.
- **Voice & Realtime**: Integrated voice/realtime support (`src/live/`) connecting directly to supported audio/realtime providers.
- **Local Recording & Playback**: Terminal session recording via `/record` and playback via `reverse play` using `.reversecast` captures stored locally under temporary recordings (`reverse-recordings`).
- **HTML Export**: Standalone session export via `reverse --export <session.jsonl> [output.html]` and the `/export` slash command with self-contained inlined React tool views.
- **Extensibility & Plugins**: Full support for local plugin loading and linking via `reverse install <path>` and `reverse plugin` commands.
- **Local Skills**: Local skill discovery (`reverse skill list [dir] [--json]`), `manage_skill`, and skill store resolution via `skills.lock.json`.

All external hosted coordination services (collab relays, live screen broadcasting, cloud clip upload, remote skillshare registry, and centralized auto-QA reporting) have been completely removed.

## Supported Local Workflows

- **Development Launcher**: `sh packages/coding-agent/scripts/reverse` (or `bun run dev` / `bun run reverse`) restores the launch working directory via preload shims without bunfig pollution.
- **Compiled Standalone Binary**: `packages/coding-agent/dist/reverse` provides a self-contained executable with embedded native bindings and ad-hoc code signature.
- **Single-Turn Execution**: `reverse -p "read src/index.ts"` executes prompt and tool calls in print mode.
- **Multi-Turn Resumption**: `reverse -p --continue "summarize"` rehydrates the prior session's user, tool, and assistant history.
- **Interactive Terminal (TUI)**: `reverse` launches the full interactive workspace with prompt composer, live status line, and `/new` session switching.
- **Terminal Recording & Playback**: `/record` starts and stops local session captures stored in `$TMPDIR/reverse-recordings/*.reversecast`; `reverse play <recording> --speed 10 --idle-limit 0.1` provides terminal replay without network access.
- **Session HTML Export**: `reverse --export <session.jsonl> [output.html]` generates standalone self-contained HTML transcripts with inlined React tool views.
- **Local Skills & Plugins**: `reverse skill list [dir] [--json]` discovers local `.reverse/skills`; `reverse install <local-plugin-path>` links development plugins into the isolated user plugin store.
- **Configuration & Localization (i18n)**: Manage settings via `reverse config [list|get|set|reset]`. Full Chinese localization (`zh-CN`) is available for configuration labels, descriptions, group headers, and CLI help, configurable via `reverse config set language zh-CN`, in the interactive `/settings` panel (Appearance → Display → Language), or via the `REVERSE_LANG=zh-CN` environment override, while keeping all setting identifiers, enum values, and JSON machine output canonical. No migration promise is made for legacy aliases.

The canonical contracts are `REVERSE_*` environment variables, `.reverse` configuration roots, `reverse://` documentation URLs, `.reverse-plugin` native plugin manifests, and `@reverse/reversetype` schemas. Recordings use `.reversecast` with a `reversecast` header. Optional SQL session storage defaults to `reverse_session_files`; existing recordings and SQL databases are not automatically migrated.

## Verification Evidence

A clean-room, zero-external-credential loopback smoke harness verified both the development launcher (`packages/coding-agent/scripts/reverse`) and compiled standalone binary (`dist/reverse`):

1. **CLI Baseline**: `--version`, `--help`, `stats --help`, and `--smoke-test` exit 0. Help tables confirm all 7 excised commands (`collab`, `join`, `share`, `stream`, `clip`, `grievances`, `update`) are removed from command listings.
2. **Relative Path Tool Execution**: `read hello.txt` executed the native `read` tool against cwd fixtures, returned expected content through local Anthropic Messages SSE streaming, printed `REVERSE_SMOKE_OK`, and wrote durable JSONL session entries.
3. **Session Continuation**: `--continue` replayed exact prior turns (user message, tool use, tool result, assistant output, follow-up prompt) over loopback SSE and returned `REVERSE_RESUME_OK`.
4. **Excised Command Enforcement**: All 7 removed commands fail fast with exit code 1, print rejection guidance, and make zero network requests.
5. **Isolated Extensibility**: `reverse skill list --json` returned project fixture skills; `reverse install` linked fixture packages strictly into isolated test environments without host leakage.
6. **PTY Terminal & Recording**: Interactive TUI launched under a real Darwin PTY, processed interactive turns, switched sessions (`/new`), recorded screen sessions (`/record`), and replayed recorded `.reversecast` files locally via `reverse play` with zero remote calls.
7. **Standalone HTML Export**: Headless Chrome (v155) loaded exported session HTML via Chrome DevTools Protocol (CDP); DOM inspection confirmed chat messages and tool outputs rendered offline, and network interception verified zero outgoing requests to share, gist, or remote services.

> **Provider Notes**: Verification was conducted using an offline loopback provider harness; remote providers require valid user-configured API credentials. Local Apple Foundation Models are unavailable on this machine due to upstream native build constraints requiring Swift 6.4 / macOS 27 SDK; the feature implementation remains intact in source.

## License

MIT License. See [LICENSE](./LICENSE), [CLI third-party notices](./packages/coding-agent/THIRD-PARTY-NOTICES.txt), and [native third-party notices](./packages/natives/THIRD-PARTY-NOTICES.txt) for original copyright notices and third-party dependency disclosures.
