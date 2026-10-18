# websocket_observe

> Offline, read-only WebSocket frame analysis over existing HAR or structured capture files: inspect, page, search, and export redacted frames.

## Source
- Entry: `packages/coding-agent/src/tools/websocket-observe.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/websocket-observe.md`
- Tests: `packages/coding-agent/test/tools/websocket-observe.test.ts`

## Scope and safety
- Reads a local file only. Rejects `scheme://` paths and never connects to a WebSocket, records live traffic, replays frames, or runs scripts.
- There is no live-capture action: when no capture exists, use the browser relay/HAR export or an authorized proxy to produce one first.
- Original captures are read-only; exports are written to the session artifact directory.
- Credentials are redacted in every output: URL userinfo, sensitive query values (`token`, `access_token`, `api_key`, `signature`, `session`, …), sensitive JSON keys, textual key/value pairs, `Bearer`/`Basic`/`Digest` values, and JWT-shaped strings. Binary frames are summarized by size and never decoded into the transcript or artifact payload text.
- Redaction changes payload text; exported artifacts are sanitized evidence, not a credential store.

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `action` | `inspect \| list \| search \| export` | Yes | Analysis mode. |
| `path` | `string` | Yes | Local capture file, resolved against the session cwd. URLs are rejected. |
| `format` | `auto \| har \| json \| ndjson` | No | Capture format override; default `auto`. |
| `url` | `string` | No | Case-insensitive substring filter on the connection URL (`list`/`search`/`export`). |
| `filter` | `string` | `search` | Case-insensitive substring over payload + URL; optional for `list`/`export`; required for `search`. |
| `regex` | `boolean` | No | Interpret `filter` as a JavaScript regular expression; requires `filter`. |
| `direction` | `in \| out` | No | Keep inbound (server→client) or outbound frames. |
| `opcode` | integer `0..15` | No | Keep frames with this opcode. |
| `offset` | integer `>= 0` | No | Zero-based frame offset after filtering. Default 0. |
| `limit` | integer `>= 1` | No | `list`/`search` default 50 (max 500); `export` default 1000 (max 5000). |
| `max_bytes` | integer `>= 1024` | No | Rendered-text cap for `inspect`/`list`/`search` (default 256 KiB, max 4 MiB); artifact cap for `export` (default 1 MiB, max 16 MiB). |
| `export_format` | `json \| ndjson` | No | `export` only; default `json`. |

`inspect` accepts no frame filters, `offset`, or `limit`.

## Supported capture formats
- **HAR 1.2** (`format: "har"`): entries with `request.url` matching `ws://`/`wss://`, `_resourceType: "websocket"`, or `_webSocketMessages`. Each entry is a connection; `_webSocketMessages[]` entries supply `type` (`send`/`receive`), `time`, `opcode`, and `data`.
- **Structured JSON** (`format: "json"`): `{websockets|connections|sockets|captures: [...]}`, `{frames|messages|events: [...]}`, a top-level array of connections or frames, or one connection object. Connection objects accept `url`/`requestUrl`/`webSocketUrl` and `frames`/`messages`/`events`. Frame fields accept `direction`/`type`, `timestamp`/`time`/`ts`, `opcode`/`opCode`, `payload`/`payloadData`/`data`/`message`/`text`, and `encoding` (`base64` marks binary).
- **CDP NDJSON** (`format: "ndjson"`): one JSON event per line. `Network.webSocketCreated` and `Network.webSocketWillSendHandshakeRequest` establish the connection URL; `Network.webSocketFrameSent` / `Network.webSocketFrameReceived` supply `params.response.opcode` and `params.response.payloadData`.

Frame output records carry `index`, `connection`, redacted `url`, `direction`, optional `timestamp`/ISO `time`, `opcode`/`opcodeName`, `encoding`, `payloadType` (`json`/`text`/`empty`/`binary`), original `bytes`, a 400-character `preview`, `previewTruncated`, and `redacted`.

## Actions
- **inspect**: format, file size, connection/frame totals, in/out split, opcode histogram, time range, redaction count, and one line per connection (up to 200).
- **list**: paged frame summaries after optional filters.
- **search**: same output as `list`, requiring `filter`; matching runs over the unredacted raw payload and URL, while rendered output stays redacted.
- **export**: writes the selected page to an artifact as a JSON array or NDJSON. Payloads are redacted and full-size (subject to `max_bytes`). When the cap is reached, the first frame's payload is shortened, then later frames are omitted; `truncated`, `payloadsTruncated`, and `hasMore` report what happened.

## Limits
- Capture files above 128 MiB are rejected.
- Parsing stops after 200,000 frames and sets `truncated`.
- Rendered text is capped by `max_bytes` with a truncation footer.
- Connection lines in `inspect` are capped at 200; use filters and paging for larger captures.

## Error statuses
`not_found`, `not_a_file`, `unreadable`, `empty`, `file_too_large`, `invalid_format`, `artifact_unavailable`, and `error`. Malformed or unrecognized captures are reported, never partially repaired.

## Flow
1. Validate action-specific arguments; reject URL paths and unsupported combinations.
2. Resolve the path with `resolveReadPath()`, stat it, reject special files and oversized captures.
3. Read UTF-8, strip a BOM, then parse: HAR → structured JSON → CDP NDJSON (auto-detection), or the forced `format`.
4. Build frames with direction/opcode normalization, payload size/type, timestamp ISO conversion, and redaction.
5. Apply filters and paging; render bounded text or write the sanitized export artifact.

## Examples
```json
{"action":"inspect","path":"artifacts/session.har"}
{"action":"list","path":"artifacts/session.har","url":"wss://api.example.com/ws","direction":"in","limit":20}
{"action":"search","path":"artifacts/cdp.ndjson","filter":"subscribe","offset":0,"limit":50}
{"action":"export","path":"artifacts/session.har","filter":"auth","export_format":"ndjson","max_bytes":2097152}
```
