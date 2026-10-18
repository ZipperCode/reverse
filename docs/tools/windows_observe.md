# windows_observe

> Offline, read-only Windows API trace and capture analysis over existing ETW, API Monitor, or structured JSON/NDJSON files: inspect, page, search, and export redacted API events.

## Source
- Entry: `packages/coding-agent/src/tools/windows-observe.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/windows-observe.md`
- Tests: `packages/coding-agent/test/tools/windows-observe.test.ts`

## Scope and safety
- Reads local files only. Rejects URLs (`scheme://`) and remote UNC paths (`\\server\share`).
- Never connects to or controls live targets, injects DLLs, executes scripts or commands, or replays API calls.
- Original capture files are strictly read-only; exports are written to dedicated session artifacts.
- Credentials and tokens are redacted: sensitive parameter keys (`password`, `token`, `secret`, `api_key`, `credential`, `private_key`, `session`, `ticket`, `hash`, etc.), `Bearer` tokens, and JWT strings are replaced with `[redacted]`.
- Output is bounded by pagination and byte caps.

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `action` | `inspect \| list \| search \| export` | Yes | Analysis mode. |
| `path` | `string` | Yes | Local capture file resolved against session cwd. URLs and remote shares are rejected. |
| `format` | `auto \| json \| ndjson \| api_monitor \| etw` | No | Capture format override; default `auto`. |
| `pid` | integer | No | Filter by process ID. |
| `tid` | integer | No | Filter by thread ID. |
| `module` | `string` | No | Case-insensitive substring filter on module / DLL name. |
| `api` | `string` | No | Case-insensitive substring filter on API function name. |
| `category` | `string` | No | Filter by category: `file`, `registry`, `process`, `memory`, `network`, `crypto`, `sync`, `security`, `other`. |
| `direction` | `call \| return \| in \| out \| both` | No | Filter by call direction. |
| `filter` | `string` | `search` | Substring or regex filter over API, module, parameters, result, process name; required for `search`. |
| `regex` | `boolean` | No | Treat `filter` as a regular expression; requires `filter`. |
| `start_time` | `string` | No | Timestamp lower bound (ISO string or epoch ms). |
| `end_time` | `string` | No | Timestamp upper bound (ISO string or epoch ms). |
| `offset` | integer `>= 0` | No | Zero-based event offset after filtering. Default 0. |
| `limit` | integer `>= 1` | No | `list`/`search` default 50 (max 500); `export` default 1000 (max 5000). |
| `max_bytes` | integer `>= 1024` | No | Rendered text cap for `inspect`/`list`/`search` (default 256 KiB, max 4 MiB); artifact cap for `export` (default 1 MiB, max 16 MiB). |
| `export_format` | `json \| ndjson` | No | `export` only; default `json`. |

`inspect` accepts no event filters, `offset`, or `limit`.

## Supported capture formats
- **Structured JSON** (`format: "json"`): `{ "events": [...] }`, `{ "calls": [...] }`, `{ "apis": [...] }`, or top-level array of event objects.
- **Structured NDJSON** (`format: "ndjson"`): one JSON event object per line.
- **API Monitor JSON** (`format: "api_monitor"`): `{ "Calls": [...] }` or array of API Monitor call records with `Module`, `API`, `Parameters`, `ReturnValue`/`Result`, `Time`.
- **ETW JSON** (`format: "etw"`): Microsoft-Windows-Kernel-* provider events or records with `System` (`Provider`, `ProcessID`, `ThreadID`, `TimeCreated`) and `EventData`.

Event records carry `index`, `timestamp`, `pid`, `tid`, `processName`, `module`, `api`, `direction`, `category`, `parameters`, `paramSummary`, `result`, `duration`, and `redacted`.

## Actions
- **inspect**: format, file size, total events, time range, process summary (PID + image + counts), module counts, category counts, top APIs, and redaction total.
- **list**: paged event summaries with timestamp, PID/TID, module!api, category/direction, parameter summary, result, duration, and redaction tags.
- **search**: same output as `list`, requiring `filter`.
- **export**: writes matching events to a session artifact as JSON array or NDJSON, with redacted parameters and summaries, capped at `max_bytes`.

## Limits
- Capture files above 128 MiB are rejected.
- Parsing stops after 200,000 events and marks `truncated`.
- Rendered text and exported artifacts respect `max_bytes`.

## Error statuses
`not_found`, `not_a_file`, `unreadable`, `empty`, `file_too_large`, `invalid_format`, `artifact_unavailable`, and `error`.
