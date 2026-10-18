# adb_observe

> Read-only Android device observation over fixed `adb` commands: device discovery, installed packages, running processes, bounded logcat, system properties, and screenshots saved as artifacts.

## Source
- Entry: `packages/coding-agent/src/tools/adb-observe.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/adb-observe.md`
- Dependency detector: `packages/coding-agent/src/extensibility/skill-requirements.ts` (`adb` descriptor in `skill-tool-catalog.ts`)

## Actions and argv
The tool builds argv itself; no arbitrary adb command, shell command, install, push, pull, or reboot is accepted.

| Action | argv (after the adb binary) | Notes |
| --- | --- | --- |
| `devices` | `devices -l` | Lists every attached device; `serial` is rejected. |
| `packages` | `-s <serial> shell pm list packages -f` | Optional `package` filters output locally to `=<package>`. |
| `processes` | `-s <serial> shell ps -A -o PID,USER,NAME` | Optional `package` filters output lines locally. |
| `logcat` | `-s <serial> logcat -d -v threadtime -t <lines> [-s <filter>]` | `lines` default 200, max 2000. |
| `props` | `-s <serial> shell getprop` | Optional `filter` matches property-key prefixes locally. |
| `screencap` | `-s <serial> exec-out screencap -p` | Raw PNG bytes are written to an artifact. |

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `action` | `devices \| packages \| processes \| logcat \| props \| screencap` | Yes | Observation to perform. |
| `serial` | `string` | conditional | Target serial (e.g. `emulator-5554`, `192.168.1.5:5555`). Optional with one attached device; required with several. Must match `^[A-Za-z0-9._:-]{1,128}$`. |
| `package` | `string` | No | Dotted Android application id filter for `packages`/`processes`; rejected for other actions. |
| `filter` | `string` | No | `logcat`: one `TAG[:VDIWEF]`; `props`: property key/prefix. Rejected for other actions. |
| `lines` | integer `1..2000` | No | logcat trailing-line limit (default 200); rejected for other actions. |
| `timeout` | number `>= 1` | No | Execution timeout seconds (default 30, clamped to 120). |
| `max_bytes` | integer `>= 1` | No | Output cap (default 262144, max 4194304; screencap default 16777216, max 67108864). |

## Outputs
- Text: action header with serial and captured bytes, then the observed content (or a status notice).
- `details.status`: `ok`, `missing_dependency`, `device_required`, `device_not_found`, `device_unauthorized`, `device_offline`, `device_unavailable`, or `error`.
- `details.devices`: parsed `{ serial, state, details? }` entries from `adb devices -l`.
- `details.artifactId` / `artifactPath` / `bytes`: screencap artifact id (`artifact://<id>`), absolute path, and raw PNG size. Image bytes are never placed in the text output.
- `details.truncated`: true when stdout reached `max_bytes`.
- `details.error`: short stderr excerpt for partially successful runs, or the failure reason.

## Flow
1. Validate `action`-specific parameters: `package`, `filter`, `lines`, `serial`, `timeout`, `max_bytes`. Invalid or inapplicable fields throw `ToolError`.
2. Resolve `adb` through the skill tool catalog. Missing installs return `status: "missing_dependency"` with the platform install hint, manual URL, and suggested fallbacks; no fallback is executed.
3. For non-`devices` actions, run `adb devices -l` first and parse the device table. Select `serial`; with zero or several attached devices return `device_required`/`device_not_found`; unauthorized/offline/other states return their structured status.
4. Execute the fixed argv with piped stdout/stderr, `stdin: "ignore"`, timeout, abort-signal cancellation, and output cap.
5. For text actions, decode and locally apply `package`/`filter`; for screencap, write raw bytes to a session artifact and return its id and path.

## Limits & Caps
- `DEFAULT_TIMEOUT_SECONDS = 30`, `MAX_TIMEOUT_SECONDS = 120`.
- `DEFAULT_MAX_BYTES = 256 KiB`, `MAX_OUTPUT_BYTES = 4 MiB`.
- `DEFAULT_SCREENCAP_MAX_BYTES = 16 MiB`, `MAX_SCREENCAP_BYTES = 64 MiB`.
- `DEFAULT_LOGCAT_LINES = 200`, `MAX_LOGCAT_LINES = 2000`.
- Truncated screencap output is discarded rather than saving a corrupt PNG.

## Side Effects
- Strictly read-only toward the device: no install, uninstall, push, pull, reboot, settings change, or UI input.
- `screencap` writes one PNG into the session artifact directory.
- Spawns the `adb` binary as an isolated external process; no shell interpolation.
