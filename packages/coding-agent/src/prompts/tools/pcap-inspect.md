Native offline read-only PCAP and PCAPNG network capture analysis without live packet capture or network replay.

Capabilities:
- **Capture Metadata (`info`)**:
  - Identifies capture format (classic PCAP vs. PCAPNG), byte order (little vs. big endian), timestamp resolution (microsecond vs. nanosecond), snaplen, and link-layer type (Ethernet, Linux Cooked, Raw IP, Loopback).
  - Calculates capture duration (start/end timestamps, elapsed seconds) and total packet count.
  - Profiles protocol breakdown (TCP, UDP, TLS, HTTP, DNS, ICMP, ARP) and top IP endpoints.
  - Catalogs PCAPNG interfaces and metadata options (OS, hardware, user application comments).
- **Packet Listing & Filtering (`list`)**:
  - Displays Wireshark-like bounded summaries: packet number, relative timestamp, source, destination, protocol, length, and informative description.
  - Filters by `protocol` (e.g. `tcp`, `udp`, `tls`, `http`, `dns`, `icmp`, `arp`), `ip` address, and `port`.
  - Paged with `limit` (default 50, max 500) and `offset` for context budget control.
- **Detailed Packet Decode (`packet_number`)**:
  - Provides deep header dissection for a specific packet (Link Layer, IP, TCP/UDP/ICMP, and Application Layer).
  - Bounded hex and ASCII payload preview.
- **Endpoint Aggregation (`endpoints`)**:
  - Catalogs unique IP endpoints with packets sent/received, bytes sent/received, observed ports, and resolved hostnames (TLS SNI or DNS).
- **Conversations & Flows (`conversations`)**:
  - Groups packets into 2-party bidirectional network conversations with traffic volume and packet counts.
- **DNS Forensic Extraction (`dns`)**:
  - Decodes DNS queries and response answers (domain names, query record types like A/AAAA/CNAME, and resolved IP addresses).

Inputs:
- `action`: `"info"`, `"list"`, `"endpoints"`, `"conversations"`, or `"dns"`.
- `path`: Path to target `.pcap` or `.pcapng` capture file.
- `protocol`: Optional protocol filter (`"tcp"`, `"udp"`, `"tls"`, `"http"`, `"dns"`, `"icmp"`, `"arp"`).
- `ip`: Optional IP address filter (matches source or destination).
- `port`: Optional port filter (matches source or destination port).
- `packet_number`: Optional 1-based packet index for detailed packet inspection.
- `limit`: Maximum items to return (default 50, max 500).
- `offset`: Pagination offset (default 0).
- `max_bytes`: Maximum capture file bytes to read (default 50MB, max 200MB).

<examples>
```
pcap_inspect(action: "info", path: "traffic.pcap")
pcap_inspect(action: "list", path: "capture.pcapng", protocol: "http", limit: 20)
pcap_inspect(action: "list", path: "capture.pcap", ip: "192.168.1.100", port: 443)
pcap_inspect(action: "list", path: "capture.pcap", packet_number: 14)
pcap_inspect(action: "endpoints", path: "traffic.pcapng")
pcap_inspect(action: "conversations", path: "traffic.pcap")
pcap_inspect(action: "dns", path: "traffic.pcapng")
```
</examples>
