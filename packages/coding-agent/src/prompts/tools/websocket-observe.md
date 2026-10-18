Offline, read-only WebSocket frame analysis over a capture file you already have on disk. It never opens a socket, connects to a target, records live traffic, replays frames, or executes scripts. If no capture exists, obtain a HAR/NDJSON recording through the browser tooling or an authorized proxy first.

Supported inputs (auto-detected, or force with `format`):
- HAR 1.2 entries that carry `request.url` (`ws://` / `wss://`) and `_webSocketMessages` (Chrome DevTools export). Entries without messages still count as connections.
- Structured JSON: `{ "websockets": [{ "url": "...", "frames": [...] }] }`, `{ "connections": [...] }`, `{ "frames": [...] }`, `{ "messages": [...] }`, a top-level array of connections or frames, or a single connection object.
- CDP NDJSON: one `Network.webSocketCreated`, `Network.webSocketWillSendHandshakeRequest`, `Network.webSocketFrameSent`, or `Network.webSocketFrameReceived` event per line, with `params.requestId` and `params.response.{opcode,payloadData}`.

Frame fields accept common aliases: `direction`/`type`, `timestamp`/`time`/`ts`, `opcode`/`opCode`, `payload`/`payloadData`/`data`/`message`/`text`, and `url`/`requestUrl`/`webSocketUrl`.

Actions:
- `inspect`: format, connections, frame totals by direction and opcode, time range, redaction count, and one line per connection. Does not accept filters or paging.
- `list`: paged frame summaries (`offset`, `limit`) after optional `url`, `filter`, `direction`, and `opcode` filters. Each frame reports direction, opcode, payload type, byte size, timestamp, a bounded preview, and whether redaction or preview truncation applied.
- `search`: same paging and filters, but requires `filter`; matches the payload and URL. Set `regex: true` for a JavaScript regular expression (case-insensitive).
- `export`: writes the matching page to a session artifact as `json` (default) or `ndjson`, with full redacted payloads. `max_bytes` caps the artifact; when reached, payloads are shortened or later frames are omitted and reported.

Inputs:
- `path` is a local file resolved against the session cwd. URLs, sockets, and inline payloads are rejected.
- `url` is a case-insensitive substring match on the connection URL. `direction` is `in` (server→client) or `out` (client→server). `opcode` is 0–15.
- `offset` default 0; `limit` default 50 (max 500), or 1000 for `export` (max 5000).
- `max_bytes` caps rendered text (default 256 KiB, max 4 MiB) or the exported artifact (default 1 MiB, max 16 MiB). Captures above 128 MiB are rejected; split or pre-filter them.

Credentials:
- URLs have userinfo and sensitive query values (`token`, `access_token`, `api_key`, `signature`, `session`, …) replaced with `[redacted]`.
- Text payloads are redacted for sensitive JSON keys, key/value pairs, `Authorization` bearer/basic values, and JWT-shaped strings. Binary payloads are reported as `<binary payload, N bytes>` and are never decoded into the transcript.
- `redacted: true` marks a frame whose URL or payload changed; `redactions` counts replacements. The artifact keeps the same redaction: treat it as sanitized evidence, not a credential store.

Output limits:
- Frame previews keep 400 characters; `previewTruncated` marks a shortened view. Use `export` when the full (redacted) payload is needed.
- Malformed or unrecognized files return `status: "invalid_format"`; a missing file returns `status: "not_found"`. Both name the expected shapes instead of guessing. This tool does not repair or partially parse corrupt captures.

<examples>
```
websocket_observe(action: "inspect", path: "artifacts/session.har")
websocket_observe(action: "list", path: "artifacts/session.har", url: "wss://api.example.com/ws", direction: "in", limit: 20)
websocket_observe(action: "search", path: "artifacts/cdp.ndjson", filter: "subscribe", regex: false, offset: 0, limit: 50)
websocket_observe(action: "export", path: "artifacts/session.har", filter: "auth", export_format: "ndjson", max_bytes: 2097152)
```
</examples>
