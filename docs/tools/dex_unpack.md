# dex_unpack

Runtime DEX memory extraction and post-dump structural census using external unpacking engines (frida-dexdump).

## Source

- Tool: `packages/coding-agent/src/tools/dex-unpack.ts`
- Resolver: `packages/coding-agent/src/extensibility/protection-toolchain.ts`
- Model guidance: `packages/coding-agent/src/prompts/tools/dex-unpack.md`

## Dependencies

- Host CLI: `frida-dexdump` (GPL-3.0, hluwa/frida-dexdump). Resolved from PATH or managed virtual environment.
- Installation: Run `reverse setup reverse frida-dexdump --execute` to install the toolchain.
- Android device: Physical USB device or emulator with running `frida-server`.

## Actions

| Action | Inputs | Result |
| --- | --- | --- |
| `status` | optional `backend` | Host toolchain installation check, binary path, and backend readiness |
| `dump` | `device`, `package` or `pid`, optional `spawn`, `deep_search`, `out_dir` | Extracted memory DEX files, header checksum validation, and incomplete-method census |

## Constraints & Safety Guarantees

1. **Explicit Target Policy**:
   - `device` (or explicit device ID / serial) is mandatory. Device-implicit dumping is disallowed.
   - Either `package` or `pid` is mandatory. Foreground-implicit dumping (`-FU`) is explicitly disallowed to prevent dumping the wrong application or ambient launcher process.
2. **Controlled Invocation**:
   - `spawn: true` spawns the application via Frida (`-f <package>`).
   - `spawn: false` (default) attaches to the existing running process (`-n <package>` or `-p <pid>`).
   - `deep_search: true` passes `-d` to scan all process memory ranges for DEX headers.
3. **Subprocess Ownership & Isolation**:
   - Dumps are stored in an isolated private staging directory.
   - Child processes are tracked and cleanly terminated on timeout or abort signal using process tree killing.
4. **Structural Census & Handoff**:
   - Every dumped `.dex` file is validated for DEX magic (`dex\n035` through `039`), declared vs actual file size, Adler-32 checksum, and SHA-1 signature.
   - Method bodies are surveyed for `code_off == 0` or 1-instruction stubs.
   - Returns `incomplete_method_boundary` and suggests next steps (`dex_repair`, `dex_patch`, or `android_package_inspect`).

## Example

```typescript
// Check if frida-dexdump is ready
dex_unpack({
  action: "status"
});

// Dump DEX from a running app
dex_unpack({
  action: "dump",
  device: "emulator-5554",
  package: "com.example.targetapp",
  deep_search: true,
  out_dir: "artifacts/unpacked_dex"
});
```
