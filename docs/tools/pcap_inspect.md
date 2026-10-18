# pcap_inspect

> Native offline read-only PCAP and PCAPNG network capture analysis without live packet capture or network replay.

## Source
- Entry: `packages/coding-agent/src/tools/pcap-inspect.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/pcap-inspect.md`

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `action` | `"info" \| "list" \| "endpoints" \| "conversations" \| "dns"` | Yes | `info` catalogs file format & protocol counts; `list` returns bounded packet summaries; `endpoints` aggregates IP stats; `conversations` groups 2-party flows; `dns` decodes queries & answers. |
| `path` | `string` | Yes | Path to target `.pcap` or `.pcapng` capture file. |
| `protocol` | `string` | No | Filter by protocol name (e.g. `"tcp"`, `"udp"`, `"tls"`, `"http"`, `"dns"`, `"icmp"`, `"arp"`). |
| `ip` | `string` | No | Filter by IP address (matches either source or destination). |
| `port` | `number` (1..65535) | No | Filter by TCP or UDP port (matches source or destination). |
| `packet_number` | `number >= 1` | No | 1-based packet index to inspect in detail with layer headers and hex dump. |
| `limit` | `number >= 1` | No | Maximum packet or item summaries to return (default 50, max 500). |
| `offset` | `number >= 0` | No | Pagination offset (default 0). |
| `max_bytes` | `number >= 1` | No | Maximum capture file bytes to read (default 50MB, max 200MB). |

## Capabilities & Analysis
- **Classic PCAP & PCAPNG Parsing**:
  - Pure TypeScript/JavaScript binary parser requiring no native compilation or external binaries.
  - Automatically identifies classic PCAP (magic `0xa1b2c3d4`, `0xa1b23c4d`, and byte-swapped counterparts) and PCAP Next Generation (`0x0a0d0d0a` SHB, IDB, EPB, SPB blocks).
  - Handles little-endian and big-endian captures, microsecond and nanosecond timestamps.
  - Decodes link-layer framing for Ethernet (DLT 1, including 802.1Q VLAN), Linux Cooked Capture v1 & v2 (DLT 113, DLT 276), BSD Loopback (DLT 0), and Raw IP (DLT 12, 101).
- **Network & Transport Protocol Dissection**:
  - IPv4: header length, total length, flags, TTL, protocol, source & destination IP.
  - IPv6: version, payload length, next header, source & destination IPv6 addresses.
  - ARP: opcode (request/reply), sender & target IP and MAC addresses.
  - TCP: source & destination ports, sequence and ACK numbers, window size, flags (SYN, ACK, FIN, RST, PSH, URG), and options.
  - UDP: source & destination ports, datagram length, payload length.
  - ICMP & ICMPv6: type, code, echo request/reply identification.
- **Application Protocol Forensics**:
  - **TLS / HTTPS**: Parses TLS record layer and ClientHello handshake; extracts Server Name Indication (SNI) hostnames without decryption.
  - **HTTP**: Detects HTTP methods (GET, POST, PUT, DELETE, etc.) and response status codes; extracts paths and Host headers.
  - **DNS**: Decodes transaction ID, QR flag, query domain names, record types (A, AAAA, CNAME, TXT, etc.), and response addresses.
- **Detailed Single-Packet Decode**:
  - When `packet_number` is supplied, dissects link, network, transport, and application layers in detail, including bounded hex/ASCII previews of the packet payload.
- **Traffic Summaries & Aggregation**:
  - `endpoints`: Aggregates traffic per IP address (packets sent/received, bytes sent/received, ports, and observed hostnames).
  - `conversations`: Groups 2-party communication pairs (IP A <-> IP B) with directional packet and byte statistics.

## Limits & Caps
- `DEFAULT_LIMIT = 50`, `MAX_LIMIT = 500`: List outputs and aggregations are bounded to avoid excessive context consumption.
- `DEFAULT_MAX_BYTES = 50 MiB`, `HARD_MAX_BYTES = 200 MiB`: Caps maximum capture file size.
- Payload hex previews are bounded to 512 bytes per packet.

## Side Effects
- Strictly read-only and offline.
- Never performs live packet capture, network socket binding, or packet replay.

## Tool Attributes
- `approval`: `"read"`
- `loadMode`: `"discoverable"`
- `strict`: `true`
