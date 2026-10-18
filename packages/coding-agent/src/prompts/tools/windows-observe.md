Offline, read-only Windows API trace and capture analysis over an existing trace file on disk. It never injects into or controls processes, executes scripts or commands, replays API calls, or connects to remote paths. If no capture exists, obtain an ETW, API Monitor, or JSON/NDJSON recording in an authorized laboratory environment first.

Supported inputs (auto-detected, or force with `format`):
- Structured JSON: `{ "events": [...] }`, `{ "calls": [...] }`, `{ "apis": [...] }`, a top-level array of event objects, or API Monitor JSON exports (`{ "Calls": [...] }`).
- Structured NDJSON: one JSON event object per line (ETW / API Monitor / JSON trace streams).
- ETW JSON/NDJSON: Microsoft-Windows-Kernel-* provider events or event records carrying System/EventData.

Event fields accept standard names and common aliases: `timestamp`/`time`/`TimeCreated`, `pid`/`ProcessId`, `tid`/`ThreadId`, `processName`/`ImageName`, `module`/`dll`/`Provider`, `api`/`function`/`EventName`, `direction` (`call`/`return`), `category` (`file`/`registry`/`process`/`memory`/`network`/`crypto`/`sync`/`security`/`other`), `parameters`/`args`/`EventData`, `result`/`returnValue`/`status`, and `duration`/`durationMs`.

Actions:
- `inspect`: format, total events, unique processes (PID + image), module counts, category counts, top APIs, time range, and redaction totals. Does not accept filters or paging.
- `list`: paged API call events (`offset`, `limit`) after optional filters (`pid`, `tid`, `module`, `api`, `category`, `direction`, `start_time`, `end_time`, `filter`, `regex`). Each event reports timestamp, pid/tid, module!api, category/direction, parameter summary, return result, duration, and redaction flags.
- `search`: same paging and filters, but requires `filter`; matches against api, module, category, parameter summary, return result, and process name. Set `regex: true` for a regular expression match (case-insensitive).
- `export`: writes matching events to a session artifact as `json` (default) or `ndjson`, with redacted parameters and summaries. `max_bytes` caps the artifact; when reached, later events are omitted and reported.

Inputs:
- `path`: local capture file resolved against session cwd. URLs, remote shares, and sockets are rejected.
- `pid` / `tid`: process ID / thread ID integer filter.
- `module`: case-insensitive substring on module / DLL name (e.g. `kernel32.dll`, `advapi32`).
- `api`: case-insensitive substring on function name (e.g. `CreateFileW`, `RegOpenKey`).
- `category`: `file`, `registry`, `process`, `memory`, `network`, `crypto`, `sync`, `security`, or `other`.
- `direction`: `call` (in/entry), `return` (out/exit), or `both`.
- `start_time` / `end_time`: ISO timestamp or epoch time lower/upper bound.
- `offset`: default 0; `limit`: default 50 (max 500), or 1000 for `export` (max 5000).
- `max_bytes`: rendered text cap (default 256 KiB, max 4 MiB) or artifact cap (default 1 MiB, max 16 MiB). Captures above 128 MiB are rejected; split or pre-filter them.

Redaction:
- Sensitive parameter keys (`password`, `token`, `secret`, `api_key`, `credential`, `private_key`, `session`, `ticket`, `hash`, ...) and patterns (`Bearer ...`, JWTs) have their values replaced with `[redacted]`.
- Parameter summaries and exported artifacts preserve structural schema while censoring sensitive credentials.

<examples>
```
windows_observe(action: "inspect", path: "artifacts/trace.json")
windows_observe(action: "list", path: "artifacts/trace.ndjson", pid: 1420, category: "registry", limit: 20)
windows_observe(action: "search", path: "artifacts/trace.json", filter: "RegOpenKey", regex: false, offset: 0, limit: 50)
windows_observe(action: "export", path: "artifacts/trace.json", module: "kernel32.dll", export_format: "ndjson", max_bytes: 2097152)
```
</examples>
