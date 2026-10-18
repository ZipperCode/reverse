# frida

> Dynamic instrumentation toolkit: execute custom scripts, runtime hooks, process spawning/attaching, device discovery, process listing, and module inspection against local, USB, or remote targets.

## Source

- Entry: `packages/coding-agent/src/tools/frida.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/frida.md`
- Dependency detector: `packages/coding-agent/src/extensibility/skill-requirements.ts` (`frida` descriptor in `skill-tool-catalog.ts`)

## Capabilities

The unified `frida` tool provides open dynamic instrumentation without artificial safety restrictions or tiered approvals:

- **Custom JavaScript execution**: Inline `script` or file `script_path` with full access to `Interceptor.attach`, `Java.perform`, `Java.use(...).method.implementation = ...`, `ObjC.classes`, and `Memory.read*`/`Memory.write*`.
- **Target selection**: Attach to running processes by PID (`pid`) or name (`process`), or launch new processes via `spawn`.
- **Transport modes**: Local system (default), USB/emulator (`usb`), specific device ID (`device`), or remote frida-server host (`host`).
- **Script arguments**: Pass JSON parameters to scripts via `script_args` (`-P` / `--parameters JSON`).
- **Quick reconnaissance actions**:
   - `action: "devices"`: List attached USB, local, and remote devices (`frida-ls-devices`).
   - `action: "ps"`: List running processes (`frida-ps`), with optional `filter` and `applications: true`.
   - `action: "modules"` (or `"inspect"`): Enumerate loaded modules in the target process.
   - `action: "trace"`: Trace module loading (`module_load`) or exported symbols (`exports`).
- **CLI pass-through**: Pass raw CLI arguments via `cli_args` (e.g. `["--runtime=v8", "--realm=native"]`).
- **Engineering controls**: Execution timeout (`timeout`), output bounding (`max_bytes`), abort signal integration, and session artifact storage (`to_artifact`).

## Inputs

| Field          | Type                                                   | Required    | Description                                                                                                                                    |
| -------------- | ------------------------------------------------------ | ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `action`       | `exec \| devices \| ps \| modules \| inspect \| trace` | No          | Action to perform. Defaults to `exec` when `script`, `script_path`, or `spawn` is provided.                                                    |
| `script`       | `string`                                               | Conditional | Inline Frida JavaScript source code. Mutually exclusive with `script_path`.                                                                    |
| `script_path`  | `string`                                               | Conditional | Local path to Frida JavaScript file. Mutually exclusive with `script`.                                                                         |
| `pid`          | integer `>= 1`                                         | Conditional | Target process ID to attach to or inspect.                                                                                                     |
| `process`      | `string`                                               | Conditional | Target process name or package identifier to attach to or inspect.                                                                             |
| `spawn`        | `string`                                               | Conditional | Target binary path or package name to spawn as a new process.                                                                                  |
| `usb`          | `boolean`                                              | No          | Target USB device/emulator (passes `-U`).                                                                                                      |
| `device`       | `string`                                               | No          | Target device identifier or serial (passes `-D <device>`).                                                                                     |
| `host`         | `string`                                               | No          | Target remote frida-server host (e.g. `192.168.1.5:27042`, passes `-H <host>`).                                                                |
| `script_args`  | `unknown`                                              | No          | Optional arguments passed to script via `-P` / `--parameters JSON`.                                                                            |
| `no_pause`     | `boolean`                                              | No          | For spawn: automatically start main thread (defaults to `true`; `false` keeps paused).                                                         |
| `filter`       | `string`                                               | No          | Text filter applied to process listing, module listing, or trace events.                                                                       |
| `applications` | `boolean`                                              | No          | For action `ps`: list only installed application processes (`-a`).                                                                             |
| `module`       | `string`                                               | No          | Target module name for trace template `exports` or module filtering.                                                                           |
| `template`     | `string`                                               | No          | Built-in trace template (`module_load`, `exports`) or custom template name. Custom scripts can also be supplied via `script` or `script_path`. |
| `max_events`   | integer `>= 1`                                         | No          | Maximum trace events captured or displayed in trace summary (default 100, no artificial limit).                                                |
| `cli_args`     | `string[] \| string`                                   | No          | Extra raw CLI arguments passed directly to the command (e.g. `["--runtime=v8"]`).                                                              |
| `timeout`      | number `>= 1`                                          | No          | Execution watchdog timeout in seconds (default 30, no artificial limit; bounded only by runtime/session resources).                            |
| `max_bytes`    | integer `>= 1`                                         | No          | Output cap in bytes (default 256 KiB, no artificial limit; bounded only by runtime/session resources; use `to_artifact` for full persistence). |
| `to_artifact`  | `boolean`                                              | No          | Save full execution output and script metadata to session artifact.                                                                            |

## Approval Behavior

`frida` does not declare artificial action-level approval tiers (such as read vs exec discrimination). Approval policy is governed uniformly by the runtime environment's standard tool approval configuration (`tools.approvalMode` / `tools.approval.frida`), without tool-level artificial gates or action-specific hurdles.

## Structured Statuses

- `ok`: Successful execution or observation.
- `missing_dependency`: Frida tools are absent; returns platform installation hint and fallback options.
- `device_unauthorized`: Device debugging unauthorized.
- `device_offline`: Target device is offline.
- `device_not_found`: Target device was not found.
- `device_required`: Multiple devices attached without selection.
- `device_unavailable`: Unable to connect to target frida-server.
- `version_mismatch`: Frida client and target frida-server major version mismatch.
- `timeout`: Execution timed out.
- `error`: Subprocess non-zero exit code or execution error.
