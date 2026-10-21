import * as fs from "node:fs/promises";
import type { Stats } from "node:fs";
import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import { type } from "@reverse/reversetype";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { formatBytes, prompt } from "@reverse/utils";
import type { ToolSession } from "./index";
import { resolveReadPath } from "./path-utils";
import { throwIfAborted } from "./tool-errors";
import pcapInspectDescription from "../prompts/tools/pcap-inspect.md" with { type: "text" };

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 500;
const DEFAULT_MAX_BYTES = 50 * 1024 * 1024; // 50MB
const HARD_MAX_BYTES = 200 * 1024 * 1024; // 200MB

// ============================================================================
// Parameter Schema
// ============================================================================

const pcapInspectSchema = type({
	action: type
		.enumerated("info", "list", "endpoints", "conversations", "dns")
		.describe(
			"Inspection action: info (file format, packet count, duration, protocol counts, top endpoints), list (packet index, timestamp, src/dst, protocol, length, summary), endpoints (IP addresses, traffic stats, ports), conversations (bidirectional 2-party network flows), or dns (DNS queries and responses)",
		),
	path: type("string").describe("Path to target .pcap or .pcapng network capture file"),
	"protocol?": type("string").describe(
		"Filter by protocol name (e.g. 'tcp', 'udp', 'dns', 'http', 'tls', 'icmp', 'arp')",
	),
	"ip?": type("string").describe("Filter by IP address (matches either source or destination IP)"),
	"port?": type("number.integer >= 1").describe(
		"Filter by TCP/UDP port (1 through 65535; matches either source or destination port)",
	),
	"packet_number?": type("number.integer >= 1").describe(
		"1-based packet index for detailed header and payload inspection",
	),
	"limit?": type("number.integer >= 1").describe("Maximum packet or item summaries to return (default 50, max 500)"),
	"offset?": type("number.integer >= 0").describe("Pagination offset (default 0)"),
	"max_bytes?": type("number.integer >= 1").describe(
		"Maximum capture file size in bytes to read (default 50MB, max 200MB)",
	),
});

export type PcapInspectParams = typeof pcapInspectSchema.infer;
export type PcapInspectAction = PcapInspectParams["action"];

// ============================================================================
// Internal Data Models
// ============================================================================

export interface DecodedDnsRecord {
	domain: string;
	type: string;
	class?: string;
	ttl?: number;
	data?: string;
}

export interface DecodedDnsMessage {
	id: number;
	qr: "query" | "response";
	opcode: number;
	rcode: string;
	questions: DecodedDnsRecord[];
	answers: DecodedDnsRecord[];
}

export interface DecodedPacket {
	index: number; // 1-based
	timestampSec: number; // UNIX epoch float
	timestampIso: string;
	relativeSeconds: number; // from first packet
	capturedLength: number;
	originalLength: number;
	interfaceId?: number;
	linkType: number;
	linkTypeName: string;
	srcMac?: string;
	dstMac?: string;
	networkProtocol?: "IPv4" | "IPv6" | "ARP" | "Other";
	srcIp?: string;
	dstIp?: string;
	transportProtocol?: "TCP" | "UDP" | "ICMP" | "ICMPv6" | "Other";
	srcPort?: number;
	dstPort?: number;
	applicationProtocol?: string;
	summary: string;
	tcpFlags?: string[];
	tlsSni?: string;
	httpMethod?: string;
	httpPath?: string;
	dns?: DecodedDnsMessage;
	payloadPreview?: {
		bytes: number;
		hex: string;
		ascii: string;
	};
}

export interface PcapInterfaceInfo {
	id: number;
	linkType: number;
	linkTypeName: string;
	snapLen: number;
	name?: string;
	description?: string;
	tsResol?: number;
}

export interface PcapInspectDetails {
	action: PcapInspectAction;
	targetPath: string;
	fileSize: number;
	format: "pcap" | "pcapng";
	endianness: "little" | "big";
	version: string;
	snapLen?: number;
	linkType?: string;
	totalPackets: number;
	duration?: {
		startTime: string;
		endTime: string;
		elapsedSeconds: number;
	};
	protocolCounts?: Record<string, number>;
	topEndpoints?: Array<{ ip: string; packets: number; bytes: number }>;
	interfaces?: PcapInterfaceInfo[];
	packets?: Array<{
		number: number;
		time: string;
		relative: string;
		src: string;
		dst: string;
		protocol: string;
		length: number;
		summary: string;
	}>;
	endpoints?: Array<{
		ip: string;
		packetsSent: number;
		packetsReceived: number;
		totalPackets: number;
		bytesSent: number;
		bytesReceived: number;
		totalBytes: number;
		protocols: string[];
		ports: number[];
		hostnames: string[];
	}>;
	conversations?: Array<{
		endpointA: string;
		endpointB: string;
		protocol: string;
		packetsAtoB: number;
		bytesAtoB: number;
		packetsBtoA: number;
		bytesBtoA: number;
		totalPackets: number;
		totalBytes: number;
	}>;
	dnsQueries?: Array<{
		packetNumber: number;
		time: string;
		qr: "query" | "response";
		id: number;
		domain: string;
		type: string;
		rcode: string;
		answers: string[];
	}>;
	packetDetail?: {
		packetNumber: number;
		timestamp: string;
		capturedLength: number;
		originalLength: number;
		linkLayer: {
			type: string;
			srcMac?: string;
			dstMac?: string;
		};
		networkLayer?: {
			protocol: string;
			srcIp?: string;
			dstIp?: string;
		};
		transportLayer?: {
			protocol: string;
			srcPort?: number;
			dstPort?: number;
			tcpFlags?: string[];
		};
		applicationLayer?: {
			protocol?: string;
			summary: string;
			tlsSni?: string;
			httpMethod?: string;
			httpPath?: string;
			dns?: DecodedDnsMessage;
		};
		payloadPreview?: {
			bytes: number;
			hex: string;
			ascii: string;
		};
	};
}

// ============================================================================
// Binary Helper Functions
// ============================================================================

function readUInt16(buf: Buffer, offset: number, isLE: boolean): number {
	return isLE ? buf.readUInt16LE(offset) : buf.readUInt16BE(offset);
}

function readUInt32(buf: Buffer, offset: number, isLE: boolean): number {
	return isLE ? buf.readUInt32LE(offset) : buf.readUInt32BE(offset);
}

function getLinkTypeName(linkType: number): string {
	switch (linkType) {
		case 0:
			return "BSD Loopback (0)";
		case 1:
			return "Ethernet (1)";
		case 12:
			return "Raw IP (12)";
		case 101:
			return "Raw IPv4 (101)";
		case 105:
			return "IEEE 802.11 Wireless (105)";
		case 113:
			return "Linux Cooked v1 (113)";
		case 127:
			return "IEEE 802.11 Radiotap (127)";
		case 276:
			return "Linux Cooked v2 (276)";
		default:
			return `LinkType (${linkType})`;
	}
}

function formatMac(buf: Buffer): string {
	return Array.from(buf)
		.map(b => b.toString(16).padStart(2, "0"))
		.join(":");
}

function formatIpv6(buf: Buffer): string {
	const words: string[] = [];
	for (let i = 0; i < 16; i += 2) {
		words.push(buf.readUInt16BE(i).toString(16));
	}
	return words.join(":");
}

function formatTcpFlags(flags: number): string[] {
	const res: string[] = [];
	if (flags & 0x01) res.push("FIN");
	if (flags & 0x02) res.push("SYN");
	if (flags & 0x04) res.push("RST");
	if (flags & 0x08) res.push("PSH");
	if (flags & 0x10) res.push("ACK");
	if (flags & 0x20) res.push("URG");
	if (flags & 0x40) res.push("ECE");
	if (flags & 0x80) res.push("CWR");
	return res;
}

function extractTlsSni(data: Buffer): string | undefined {
	if (data.length < 9) return undefined;
	// ContentType == 22 (handshake) and TLS major 3
	if (data[0] !== 0x16 || data[1] !== 0x03) return undefined;
	// HandshakeType == 1 (ClientHello)
	if (data[5] !== 0x01) return undefined;

	let offset = 5 + 4; // Skip handshake header (1 byte type + 3 bytes length)
	if (offset + 34 > data.length) return undefined;
	offset += 2 + 32; // Skip version (2) + random (32)

	if (offset >= data.length) return undefined;
	const sessionLen = data[offset++];
	offset += sessionLen;

	if (offset + 2 > data.length) return undefined;
	const cipherLen = data.readUInt16BE(offset);
	offset += 2 + cipherLen;

	if (offset >= data.length) return undefined;
	const compLen = data[offset++];
	offset += compLen;

	if (offset + 2 > data.length) return undefined;
	const extLen = data.readUInt16BE(offset);
	offset += 2;

	const extEnd = Math.min(offset + extLen, data.length);
	while (offset + 4 <= extEnd) {
		const extType = data.readUInt16BE(offset);
		const itemLen = data.readUInt16BE(offset + 2);
		offset += 4;
		if (extType === 0) {
			// SNI extension
			if (offset + 2 <= extEnd) {
				const listLen = data.readUInt16BE(offset);
				let listOffset = offset + 2;
				const listEnd = Math.min(listOffset + listLen, offset + itemLen);
				while (listOffset + 3 <= listEnd) {
					const nameType = data[listOffset];
					const nameLen = data.readUInt16BE(listOffset + 1);
					listOffset += 3;
					if (nameType === 0 && listOffset + nameLen <= listEnd) {
						return data.toString("utf8", listOffset, listOffset + nameLen);
					}
					listOffset += nameLen;
				}
			}
		}
		offset += itemLen;
	}
	return undefined;
}

function decodeDnsName(buf: Buffer, offset: number): [string, number] {
	const labels: string[] = [];
	let curr = offset;
	let jumped = false;
	let nextOffset = -1;
	let hops = 0;

	while (curr < buf.length && hops < 30) {
		hops++;
		const len = buf[curr];
		if (len === 0) {
			if (!jumped) nextOffset = curr + 1;
			break;
		}
		if ((len & 0xc0) === 0xc0) {
			if (curr + 1 >= buf.length) break;
			if (!jumped) nextOffset = curr + 2;
			const ptr = ((len & 0x3f) << 8) | buf[curr + 1];
			curr = ptr;
			jumped = true;
			continue;
		}
		curr++;
		if (curr + len > buf.length) break;
		labels.push(buf.toString("utf8", curr, curr + len));
		curr += len;
	}
	return [labels.join("."), nextOffset >= 0 ? nextOffset : curr < buf.length && buf[curr] === 0 ? curr + 1 : curr];
}

const DNS_TYPE_NAMES: Record<number, string> = {
	0: "A",
	1: "A",
	2: "NS",
	5: "CNAME",
	6: "SOA",
	12: "PTR",
	15: "MX",
	16: "TXT",
	28: "AAAA",
	33: "SRV",
	255: "ANY",
};

const DNS_RCODE_NAMES: Record<number, string> = {
	0: "NOERROR",
	1: "FORMERR",
	2: "SERVFAIL",
	3: "NXDOMAIN",
	4: "NOTIMP",
	5: "REFUSED",
};

function decodeDns(payload: Buffer): DecodedDnsMessage | undefined {
	if (payload.length < 12) return undefined;
	try {
		const id = payload.readUInt16BE(0);
		const flags = payload.readUInt16BE(2);
		const qr = (flags & 0x8000) !== 0 ? "response" : "query";
		const opcode = (flags >> 11) & 0x0f;
		const rcodeNum = flags & 0x0f;
		const rcode = DNS_RCODE_NAMES[rcodeNum] ?? `RCODE_${rcodeNum}`;
		const qdCount = payload.readUInt16BE(4);
		const anCount = payload.readUInt16BE(6);

		let offset = 12;
		const questions: DecodedDnsRecord[] = [];
		for (let i = 0; i < qdCount && offset < payload.length; i++) {
			const [domain, nextOffset] = decodeDnsName(payload, offset);
			offset = nextOffset;
			if (offset + 4 <= payload.length) {
				const qtypeNum = payload.readUInt16BE(offset);
				const qclassNum = payload.readUInt16BE(offset + 2);
				offset += 4;
				const typeStr = DNS_TYPE_NAMES[qtypeNum] ?? (qtypeNum === 0 ? "A" : `TYPE_${qtypeNum}`);
				questions.push({
					domain,
					type: typeStr,
					class: qclassNum === 1 ? "IN" : `CLASS_${qclassNum}`,
				});
			}
		}

		const answers: DecodedDnsRecord[] = [];
		for (let i = 0; i < anCount && offset < payload.length; i++) {
			const [domain, nextOffset] = decodeDnsName(payload, offset);
			offset = nextOffset;
			if (offset + 10 <= payload.length) {
				const atypeNum = payload.readUInt16BE(offset);
				const aclassNum = payload.readUInt16BE(offset + 2);
				const ttl = payload.readUInt32BE(offset + 4);
				const rdLen = payload.readUInt16BE(offset + 8);
				offset += 10;
				let dataStr = "";
				if ((atypeNum === 1 || atypeNum === 0) && rdLen === 4 && offset + 4 <= payload.length) {
					// IPv4
					dataStr = `${payload[offset]}.${payload[offset + 1]}.${payload[offset + 2]}.${payload[offset + 3]}`;
				} else if (atypeNum === 28 && rdLen === 16 && offset + 16 <= payload.length) {
					// IPv6
					dataStr = formatIpv6(payload.subarray(offset, offset + 16));
				} else if (atypeNum === 5) {
					// CNAME
					const [cname] = decodeDnsName(payload, offset);
					dataStr = cname;
				} else {
					dataStr = `<${rdLen} bytes>`;
				}
				offset += rdLen;
				answers.push({
					domain,
					type: DNS_TYPE_NAMES[atypeNum] ?? (atypeNum === 0 ? "A" : `TYPE_${atypeNum}`),
					class: aclassNum === 1 ? "IN" : `CLASS_${aclassNum}`,
					ttl,
					data: dataStr,
				});
			}
		}

		return {
			id,
			qr,
			opcode,
			rcode,
			questions,
			answers,
		};
	} catch {
		return undefined;
	}
}

function hexDump(buf: Buffer, maxBytes: number = 256): { hex: string; ascii: string } {
	const slice = buf.subarray(0, Math.min(buf.length, maxBytes));
	const hexParts: string[] = [];
	const asciiParts: string[] = [];

	for (let i = 0; i < slice.length; i++) {
		hexParts.push(slice[i].toString(16).padStart(2, "0"));
		const c = slice[i];
		asciiParts.push(c >= 32 && c <= 126 ? String.fromCharCode(c) : ".");
	}

	return {
		hex: hexParts.join(" "),
		ascii: asciiParts.join(""),
	};
}

// ============================================================================
// Packet Dissection Logic
// ============================================================================

export function dissectPacketData(
	data: Buffer,
	index: number,
	timestampSec: number,
	firstTimestampSec: number,
	linkType: number,
	interfaceId?: number,
): DecodedPacket {
	const relSec = Math.max(0, timestampSec - firstTimestampSec);
	const date = new Date(timestampSec * 1000);
	const timestampIso = date.toISOString();

	const decoded: DecodedPacket = {
		index,
		timestampSec,
		timestampIso,
		relativeSeconds: relSec,
		capturedLength: data.length,
		originalLength: data.length,
		interfaceId,
		linkType,
		linkTypeName: getLinkTypeName(linkType),
		summary: "",
	};

	let payloadOffset = 0;
	let etherType = 0;

	// Link-layer decoding
	if (linkType === 1) {
		// Ethernet (DLT_EN10MB)
		if (data.length >= 14) {
			decoded.dstMac = formatMac(data.subarray(0, 6));
			decoded.srcMac = formatMac(data.subarray(6, 12));
			etherType = data.readUInt16BE(12);
			payloadOffset = 14;

			// Handle 802.1Q VLAN tag
			if ((etherType === 0x8100 || etherType === 0x88a8) && data.length >= 18) {
				etherType = data.readUInt16BE(16);
				payloadOffset = 18;
			}
		}
	} else if (linkType === 113) {
		// Linux Cooked v1 (DLT_LINUX_SLL)
		if (data.length >= 16) {
			etherType = data.readUInt16BE(14);
			payloadOffset = 16;
		}
	} else if (linkType === 276) {
		// Linux Cooked v2 (DLT_LINUX_SLL2)
		if (data.length >= 20) {
			etherType = data.readUInt16BE(0);
			payloadOffset = 20;
		}
	} else if (linkType === 0) {
		// BSD Loopback (DLT_NULL)
		if (data.length >= 4) {
			const family = data.readUInt32LE(0);
			etherType = family === 2 ? 0x0800 : family === 24 || family === 28 || family === 30 ? 0x86dd : 0;
			payloadOffset = 4;
		}
	} else if (linkType === 12 || linkType === 101) {
		// Raw IP
		if (data.length > 0) {
			const ver = data[0] >> 4;
			etherType = ver === 6 ? 0x86dd : 0x0800;
			payloadOffset = 0;
		}
	} else {
		// Fallback: check if starts like IPv4
		if (data.length >= 20 && data[0] >> 4 === 4) {
			etherType = 0x0800;
			payloadOffset = 0;
		}
	}

	// Network layer decoding
	let transportOffset = payloadOffset;
	let ipProtocol = 0;

	if (etherType === 0x0800 && data.length >= payloadOffset + 20) {
		// IPv4
		decoded.networkProtocol = "IPv4";
		const ihl = (data[payloadOffset] & 0x0f) * 4;
		ipProtocol = data[payloadOffset + 9];
		decoded.srcIp = `${data[payloadOffset + 12]}.${data[payloadOffset + 13]}.${data[payloadOffset + 14]}.${data[payloadOffset + 15]}`;
		decoded.dstIp = `${data[payloadOffset + 16]}.${data[payloadOffset + 17]}.${data[payloadOffset + 18]}.${data[payloadOffset + 19]}`;
		transportOffset = payloadOffset + Math.max(20, ihl);
	} else if (etherType === 0x86dd && data.length >= payloadOffset + 40) {
		// IPv6
		decoded.networkProtocol = "IPv6";
		ipProtocol = data[payloadOffset + 6];
		decoded.srcIp = formatIpv6(data.subarray(payloadOffset + 8, payloadOffset + 24));
		decoded.dstIp = formatIpv6(data.subarray(payloadOffset + 24, payloadOffset + 40));
		transportOffset = payloadOffset + 40;
	} else if (etherType === 0x0806 && data.length >= payloadOffset + 8) {
		// ARP
		decoded.networkProtocol = "ARP";
		const opcode = data.readUInt16BE(payloadOffset + 6);
		let arpSummary = opcode === 1 ? "ARP Request" : opcode === 2 ? "ARP Reply" : `ARP (op ${opcode})`;
		if (data.length >= payloadOffset + 28) {
			const sIp = `${data[payloadOffset + 14]}.${data[payloadOffset + 15]}.${data[payloadOffset + 16]}.${data[payloadOffset + 17]}`;
			const tIp = `${data[payloadOffset + 24]}.${data[payloadOffset + 25]}.${data[payloadOffset + 26]}.${data[payloadOffset + 27]}`;
			decoded.srcIp = sIp;
			decoded.dstIp = tIp;
			arpSummary =
				opcode === 1
					? `Who has ${tIp}? Tell ${sIp}`
					: opcode === 2
						? `${sIp} is at ${decoded.srcMac ?? "target"}`
						: arpSummary;
		}
		decoded.summary = arpSummary;
		return decoded;
	}

	// Transport layer decoding
	let appPayloadOffset = transportOffset;

	if (ipProtocol === 6 && data.length >= transportOffset + 20) {
		// TCP
		decoded.transportProtocol = "TCP";
		decoded.srcPort = data.readUInt16BE(transportOffset);
		decoded.dstPort = data.readUInt16BE(transportOffset + 2);
		const seq = data.readUInt32BE(transportOffset + 4);
		const ack = data.readUInt32BE(transportOffset + 8);
		const dataOffset = (data[transportOffset + 12] >> 4) * 4;
		const rawFlags = data.readUInt16BE(transportOffset + 12) & 0x01ff;
		decoded.tcpFlags = formatTcpFlags(rawFlags);
		const win = data.readUInt16BE(transportOffset + 14);
		appPayloadOffset = transportOffset + Math.max(20, dataOffset);

		let tcpSummary = `[${decoded.tcpFlags.join(", ")}] Seq=${seq} Win=${win}`;
		if (decoded.tcpFlags.includes("ACK")) {
			tcpSummary += ` Ack=${ack}`;
		}
		decoded.summary = tcpSummary;
	} else if (ipProtocol === 17 && data.length >= transportOffset + 8) {
		// UDP
		decoded.transportProtocol = "UDP";
		decoded.srcPort = data.readUInt16BE(transportOffset);
		decoded.dstPort = data.readUInt16BE(transportOffset + 2);
		const udpLen = data.readUInt16BE(transportOffset + 4);
		appPayloadOffset = transportOffset + 8;
		decoded.summary = `Len=${Math.max(0, udpLen - 8)}`;
	} else if (ipProtocol === 1 && data.length >= transportOffset + 2) {
		// ICMP
		decoded.transportProtocol = "ICMP";
		const icmpType = data[transportOffset];
		const icmpCode = data[transportOffset + 1];
		if (icmpType === 8) decoded.summary = "Echo (ping) request";
		else if (icmpType === 0) decoded.summary = "Echo (ping) reply";
		else if (icmpType === 3) decoded.summary = `Destination unreachable (code ${icmpCode})`;
		else decoded.summary = `ICMP type ${icmpType} code ${icmpCode}`;
		return decoded;
	} else if (ipProtocol === 58 && data.length >= transportOffset + 2) {
		// ICMPv6
		decoded.transportProtocol = "ICMPv6";
		const icmpType = data[transportOffset];
		const icmpCode = data[transportOffset + 1];
		if (icmpType === 128) decoded.summary = "Echo request";
		else if (icmpType === 129) decoded.summary = "Echo reply";
		else decoded.summary = `ICMPv6 type ${icmpType} code ${icmpCode}`;
		return decoded;
	}

	// Application layer inspection
	const appData = data.subarray(appPayloadOffset);
	if (appData.length > 0) {
		const preview = hexDump(appData, 128);
		decoded.payloadPreview = {
			bytes: appData.length,
			hex: preview.hex,
			ascii: preview.ascii,
		};

		// 1. DNS check (Port 53 / 5353 or valid DNS payload)
		if (decoded.srcPort === 53 || decoded.dstPort === 53 || decoded.srcPort === 5353 || decoded.dstPort === 5353) {
			const dns = decodeDns(appData);
			if (dns) {
				decoded.applicationProtocol = "DNS";
				decoded.dns = dns;
				if (dns.qr === "query" && dns.questions.length > 0) {
					decoded.summary = `Standard query ${dns.questions[0].type} ${dns.questions[0].domain}`;
				} else if (dns.qr === "response") {
					const firstAns = dns.answers[0]?.data ?? dns.rcode;
					const qDomain = dns.questions[0]?.domain ?? "";
					decoded.summary = `Standard query response ${firstAns}${qDomain ? ` for ${qDomain}` : ""}`;
				}
				return decoded;
			}
		}

		// 2. TLS check
		const sni = extractTlsSni(appData);
		if (sni) {
			decoded.applicationProtocol = "TLS";
			decoded.tlsSni = sni;
			decoded.summary = `Client Hello (SNI: ${sni})`;
			return decoded;
		}
		if (appData.length >= 5 && appData[0] === 0x16 && appData[1] === 0x03) {
			decoded.applicationProtocol = "TLS";
			const hsType = appData[5];
			if (hsType === 1) decoded.summary = "Client Hello";
			else if (hsType === 2) decoded.summary = "Server Hello";
			else if (hsType === 11) decoded.summary = "Certificate";
			else decoded.summary = `TLS Handshake (type ${hsType})`;
			return decoded;
		}
		if (appData.length >= 5 && appData[0] === 0x17 && appData[1] === 0x03) {
			decoded.applicationProtocol = "TLS";
			decoded.summary = `Application Data (${appData.length} bytes)`;
			return decoded;
		}

		// 3. HTTP check
		const textHeader = appData.subarray(0, Math.min(appData.length, 512)).toString("utf8");
		const httpReqMatch = textHeader.match(
			/^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT)\s+([^\s]+)\s+HTTP\/1\.[01]/,
		);
		if (httpReqMatch) {
			decoded.applicationProtocol = "HTTP";
			decoded.httpMethod = httpReqMatch[1];
			decoded.httpPath = httpReqMatch[2];
			const hostMatch = textHeader.match(/\r?\nHost:\s*([^\r\n]+)/i);
			const host = hostMatch ? ` [Host: ${hostMatch[1].trim()}]` : "";
			decoded.summary = `${decoded.httpMethod} ${decoded.httpPath}${host}`;
			return decoded;
		}
		const httpResMatch = textHeader.match(/^HTTP\/1\.[01]\s+(\d{3})\s+([^\r\n]*)/);
		if (httpResMatch) {
			decoded.applicationProtocol = "HTTP";
			decoded.summary = `HTTP/1.1 ${httpResMatch[1]} ${httpResMatch[2]}`;
			return decoded;
		}

		// 4. SSH check
		if (textHeader.startsWith("SSH-1.") || textHeader.startsWith("SSH-2.")) {
			decoded.applicationProtocol = "SSH";
			const firstLine = textHeader.split("\r\n")[0];
			decoded.summary = `SSH identification: ${firstLine}`;
			return decoded;
		}
	}

	if (!decoded.summary) {
		decoded.summary = `${decoded.transportProtocol ?? decoded.networkProtocol ?? "Frame"} [${data.length} bytes]`;
	}

	return decoded;
}

// ============================================================================
// Capture Parser
// ============================================================================

export function parsePcapBuffer(fileBuffer: Buffer): {
	format: "pcap" | "pcapng";
	endianness: "little" | "big";
	version: string;
	snapLen?: number;
	linkType?: string;
	interfaces: PcapInterfaceInfo[];
	packets: DecodedPacket[];
} {
	if (fileBuffer.length < 24) {
		throw new ToolError("File too small to be a valid PCAP or PCAPNG capture file.");
	}

	const magic = fileBuffer.readUInt32LE(0);

	// 1. Classic PCAP
	if (magic === 0xa1b2c3d4 || magic === 0xd4c3b2a1 || magic === 0xa1b23c4d || magic === 0x4d3c2ba1) {
		const isLE = magic === 0xa1b2c3d4 || magic === 0xa1b23c4d;
		const isNano = magic === 0xa1b23c4d || magic === 0x4d3c2ba1;
		const vMajor = readUInt16(fileBuffer, 4, isLE);
		const vMinor = readUInt16(fileBuffer, 6, isLE);
		const snapLen = readUInt32(fileBuffer, 16, isLE);
		const dlt = readUInt32(fileBuffer, 20, isLE);

		let offset = 24;
		let index = 1;
		const packets: DecodedPacket[] = [];
		let firstTs = 0;

		while (offset + 16 <= fileBuffer.length) {
			const tsSec = readUInt32(fileBuffer, offset, isLE);
			const tsFrac = readUInt32(fileBuffer, offset + 4, isLE);
			const capLen = readUInt32(fileBuffer, offset + 8, isLE);
			const origLen = readUInt32(fileBuffer, offset + 12, isLE);
			offset += 16;

			if (offset + capLen > fileBuffer.length) {
				// Truncated packet at end of file
				break;
			}

			const pktData = fileBuffer.subarray(offset, offset + capLen);
			offset += capLen;

			const ts = tsSec + (isNano ? tsFrac / 1e9 : tsFrac / 1e6);
			if (index === 1) firstTs = ts;

			const pkt = dissectPacketData(pktData, index++, ts, firstTs, dlt);
			pkt.originalLength = origLen;
			packets.push(pkt);
		}

		return {
			format: "pcap",
			endianness: isLE ? "little" : "big",
			version: `${vMajor}.${vMinor}`,
			snapLen,
			linkType: getLinkTypeName(dlt),
			interfaces: [
				{
					id: 0,
					linkType: dlt,
					linkTypeName: getLinkTypeName(dlt),
					snapLen,
				},
			],
			packets,
		};
	}

	// 2. PCAP Next Generation (PCAPNG)
	if (magic === 0x0a0d0d0a) {
		let isLE = true;
		let offset = 0;
		const interfaces: PcapInterfaceInfo[] = [];
		const packets: DecodedPacket[] = [];
		let index = 1;
		let firstTs = 0;
		let version = "1.0";

		while (offset + 8 <= fileBuffer.length) {
			const blockType = readUInt32(fileBuffer, offset, isLE);
			const blockLen = readUInt32(fileBuffer, offset + 4, isLE);

			if (blockLen < 12 || offset + blockLen > fileBuffer.length) {
				break;
			}

			if (blockType === 0x0a0d0d0a) {
				// Section Header Block (SHB)
				if (blockLen >= 24) {
					const bom = fileBuffer.readUInt32LE(offset + 8);
					if (bom === 0x1a2e3b4c) {
						isLE = true;
					} else if (bom === 0x4c3b2e1a) {
						isLE = false;
					}
					const major = readUInt16(fileBuffer, offset + 12, isLE);
					const minor = readUInt16(fileBuffer, offset + 14, isLE);
					version = `${major}.${minor}`;
				}
			} else if (blockType === 0x00000001) {
				// Interface Description Block (IDB)
				if (blockLen >= 16) {
					const linkType = readUInt16(fileBuffer, offset + 8, isLE);
					const snapLen = readUInt32(fileBuffer, offset + 12, isLE);
					let tsResol = 1e-6; // default microsecond

					// Parse IDB options
					let optOffset = offset + 16;
					const optEnd = offset + blockLen - 4;
					let ifName: string | undefined;
					let ifDesc: string | undefined;

					while (optOffset + 4 <= optEnd) {
						const optCode = readUInt16(fileBuffer, optOffset, isLE);
						const optLen = readUInt16(fileBuffer, optOffset + 2, isLE);
						optOffset += 4;
						if (optCode === 0) break; // end of options

						if (optCode === 2 && optOffset + optLen <= optEnd) {
							ifName = fileBuffer.toString("utf8", optOffset, optOffset + optLen);
						} else if (optCode === 3 && optOffset + optLen <= optEnd) {
							ifDesc = fileBuffer.toString("utf8", optOffset, optOffset + optLen);
						} else if (optCode === 9 && optOffset < optEnd) {
							const resolByte = fileBuffer[optOffset];
							if ((resolByte & 0x80) === 0) {
								tsResol = 10 ** -resolByte;
							} else {
								tsResol = 2 ** -(resolByte & 0x7f);
							}
						}
						optOffset += Math.ceil(optLen / 4) * 4;
					}

					interfaces.push({
						id: interfaces.length,
						linkType,
						linkTypeName: getLinkTypeName(linkType),
						snapLen,
						name: ifName,
						description: ifDesc,
						tsResol,
					});
				}
			} else if (blockType === 0x00000006) {
				// Enhanced Packet Block (EPB)
				if (blockLen >= 32) {
					const ifId = readUInt32(fileBuffer, offset + 8, isLE);
					const tsHigh = readUInt32(fileBuffer, offset + 12, isLE);
					const tsLow = readUInt32(fileBuffer, offset + 16, isLE);
					const capLen = readUInt32(fileBuffer, offset + 20, isLE);
					const origLen = readUInt32(fileBuffer, offset + 24, isLE);

					const iface = interfaces[ifId] ?? interfaces[0] ?? { linkType: 1, tsResol: 1e-6 };
					const tsUnits = (BigInt(tsHigh) << 32n) | BigInt(tsLow);
					const tsSec = Number(tsUnits) * (iface.tsResol ?? 1e-6);

					if (index === 1) firstTs = tsSec;

					const pktStart = offset + 28;
					const pktData = fileBuffer.subarray(pktStart, pktStart + Math.min(capLen, blockLen - 32));

					const pkt = dissectPacketData(pktData, index++, tsSec, firstTs, iface.linkType, ifId);
					pkt.originalLength = origLen;
					packets.push(pkt);
				}
			} else if (blockType === 0x00000003) {
				// Simple Packet Block (SPB)
				if (blockLen >= 16) {
					const origLen = readUInt32(fileBuffer, offset + 8, isLE);
					const capLen = Math.min(origLen, blockLen - 16);
					const pktStart = offset + 12;
					const pktData = fileBuffer.subarray(pktStart, pktStart + capLen);
					const iface = interfaces[0] ?? { linkType: 1, tsResol: 1e-6 };

					const pkt = dissectPacketData(pktData, index++, firstTs, firstTs, iface.linkType, 0);
					pkt.originalLength = origLen;
					packets.push(pkt);
				}
			}

			offset += blockLen;
		}

		return {
			format: "pcapng",
			endianness: isLE ? "little" : "big",
			version,
			interfaces,
			packets,
		};
	}

	throw new ToolError(
		`Not a valid PCAP or PCAPNG capture file: unrecognized magic bytes (0x${magic.toString(16).padStart(8, "0")})`,
	);
}

// ============================================================================
// Tool Implementation
// ============================================================================

export class PcapInspectTool implements AgentTool<typeof pcapInspectSchema, PcapInspectDetails> {
	readonly name = "pcap_inspect";
	readonly approval: ToolTier = "read";
	readonly label = "PCAP / PCAPNG Network Inspect";
	readonly summary =
		"Native offline read-only PCAP and PCAPNG network capture analysis: file headers, packet lists, protocols, IP endpoints, conversations, and DNS queries without live capture or network replay";
	readonly description: string;
	readonly parameters = pcapInspectSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	constructor(private readonly session: ToolSession) {
		this.description = prompt.render(pcapInspectDescription);
	}

	async execute(
		_toolCallId: string,
		params: PcapInspectParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<PcapInspectDetails> & { details: PcapInspectDetails }> {
		throwIfAborted(signal);

		const resolvedPath = resolveReadPath(params.path, this.session.cwd);

		let fileStat: Stats;
		try {
			fileStat = await fs.stat(resolvedPath);
		} catch (err) {
			throw new ToolError(
				`Capture file not found: ${resolvedPath} (${err instanceof Error ? err.message : String(err)})`,
			);
		}

		if (fileStat.isDirectory()) {
			throw new ToolError(`Target path is a directory, not a capture file: ${resolvedPath}`);
		}

		const maxBytes = Math.min(params.max_bytes ?? DEFAULT_MAX_BYTES, HARD_MAX_BYTES);
		if (fileStat.size > maxBytes) {
			throw new ToolError(
				`Capture file size (${formatBytes(fileStat.size)}) exceeds limit (${formatBytes(maxBytes)})`,
			);
		}

		const fileBuffer = await fs.readFile(resolvedPath);
		const parsed = parsePcapBuffer(fileBuffer);
		const allPackets = parsed.packets;

		// Calculate protocol breakdown
		const protocolCounts: Record<string, number> = {};
		for (const pkt of allPackets) {
			const proto = pkt.applicationProtocol ?? pkt.transportProtocol ?? pkt.networkProtocol ?? "Other";
			protocolCounts[proto] = (protocolCounts[proto] ?? 0) + 1;
		}

		// Calculate top endpoints
		const endpointBytes: Record<string, { packets: number; bytes: number }> = {};
		for (const pkt of allPackets) {
			if (pkt.networkProtocol !== "IPv4" && pkt.networkProtocol !== "IPv6") {
				continue;
			}
			if (pkt.srcIp) {
				const entry = endpointBytes[pkt.srcIp] ?? { packets: 0, bytes: 0 };
				entry.packets++;
				entry.bytes += pkt.capturedLength;
				endpointBytes[pkt.srcIp] = entry;
			}
			if (pkt.dstIp && pkt.dstIp !== pkt.srcIp) {
				const entry = endpointBytes[pkt.dstIp] ?? { packets: 0, bytes: 0 };
				entry.packets++;
				entry.bytes += pkt.capturedLength;
				endpointBytes[pkt.dstIp] = entry;
			}
		}

		const topEndpoints = Object.entries(endpointBytes)
			.map(([ip, stats]) => ({ ip, packets: stats.packets, bytes: stats.bytes }))
			.sort((a, b) => b.packets - a.packets)
			.slice(0, 10);

		// Duration
		let duration: PcapInspectDetails["duration"];
		if (allPackets.length > 0) {
			const startPkt = allPackets[0];
			const endPkt = allPackets[allPackets.length - 1];
			duration = {
				startTime: startPkt.timestampIso,
				endTime: endPkt.timestampIso,
				elapsedSeconds: Math.round((endPkt.timestampSec - startPkt.timestampSec) * 1000) / 1000,
			};
		}

		const action = params.action;
		const limit = Math.min(params.limit ?? DEFAULT_LIMIT, MAX_LIMIT);
		const offset = params.offset ?? 0;

		// Handle single packet inspection if packet_number is specified
		let packetDetail: PcapInspectDetails["packetDetail"];
		if (params.packet_number !== undefined) {
			const targetPkt = allPackets.find(p => p.index === params.packet_number);
			if (!targetPkt) {
				throw new ToolError(
					`Packet #${params.packet_number} not found. Capture contains ${allPackets.length} packet${allPackets.length > 1 ? "s" : ""}.`,
				);
			}
			packetDetail = {
				packetNumber: targetPkt.index,
				timestamp: targetPkt.timestampIso,
				capturedLength: targetPkt.capturedLength,
				originalLength: targetPkt.originalLength,
				linkLayer: {
					type: targetPkt.linkTypeName,
					srcMac: targetPkt.srcMac,
					dstMac: targetPkt.dstMac,
				},
				networkLayer: targetPkt.networkProtocol
					? {
							protocol: targetPkt.networkProtocol,
							srcIp: targetPkt.srcIp,
							dstIp: targetPkt.dstIp,
						}
					: undefined,
				transportLayer: targetPkt.transportProtocol
					? {
							protocol: targetPkt.transportProtocol,
							srcPort: targetPkt.srcPort,
							dstPort: targetPkt.dstPort,
							tcpFlags: targetPkt.tcpFlags,
						}
					: undefined,
				applicationLayer: {
					protocol: targetPkt.applicationProtocol,
					summary: targetPkt.summary,
					tlsSni: targetPkt.tlsSni,
					httpMethod: targetPkt.httpMethod,
					httpPath: targetPkt.httpPath,
					dns: targetPkt.dns,
				},
				payloadPreview: targetPkt.payloadPreview,
			};
		}

		// ------------------------------------------------------------------------
		// Action: info
		// ------------------------------------------------------------------------
		if (action === "info") {
			const textLines = [
				`# Capture File: ${resolvedPath}`,
				`- **Format**: ${parsed.format.toUpperCase()} (${parsed.endianness} endian, version ${parsed.version})`,
				parsed.snapLen ? `- **SnapLen**: ${parsed.snapLen} bytes` : "",
				parsed.linkType ? `- **Link Type**: ${parsed.linkType}` : "",
				`- **File Size**: ${formatBytes(fileStat.size)}`,
				`- **Total Packets**: ${allPackets.length}`,
				duration
					? `- **Duration**: ${duration.elapsedSeconds}s (${duration.startTime} to ${duration.endTime})`
					: "",
				"",
				"## Protocol Breakdown",
				...Object.entries(protocolCounts).map(([proto, count]) => `- **${proto}**: ${count} packets`),
				...Object.entries(protocolCounts).map(([proto, count]) => `${proto}: ${count} packets`),
				"",
				"## Top IP Endpoints",
				...topEndpoints.map(ep => `- \`${ep.ip}\`: ${ep.packets} packets (${formatBytes(ep.bytes)})`),
			].filter(Boolean);

			if (parsed.interfaces.length > 0) {
				textLines.push(
					"",
					"## Interfaces",
					...parsed.interfaces.map(
						iface =>
							`- Interface #${iface.id}: ${iface.name ?? iface.description ?? "default"} (${iface.linkTypeName}, snaplen ${iface.snapLen})`,
					),
				);
			}

			if (packetDetail) {
				textLines.push(
					"",
					`## Packet #${packetDetail.packetNumber} Detail`,
					`- **Timestamp**: ${packetDetail.timestamp}`,
					`- **Length**: ${packetDetail.capturedLength} bytes (captured) / ${packetDetail.originalLength} bytes (original)`,
					`- **Link**: ${packetDetail.linkLayer.type}${packetDetail.linkLayer.srcMac ? ` (${packetDetail.linkLayer.srcMac} -> ${packetDetail.linkLayer.dstMac})` : ""}`,
					packetDetail.networkLayer
						? `- **Network**: ${packetDetail.networkLayer.protocol} (${packetDetail.networkLayer.srcIp} -> ${packetDetail.networkLayer.dstIp})`
						: "",
					packetDetail.transportLayer
						? `- **Transport**: ${packetDetail.transportLayer.protocol} (port ${packetDetail.transportLayer.srcPort} -> ${packetDetail.transportLayer.dstPort})`
						: "",
					`- **Summary**: ${packetDetail.applicationLayer?.summary ?? ""}`,
				);
				if (packetDetail.payloadPreview) {
					textLines.push(
						`- **Payload Preview** (${packetDetail.payloadPreview.bytes} bytes):`,
						"```",
						packetDetail.payloadPreview.ascii,
						"```",
					);
				}
			}

			return {
				content: [{ type: "text", text: textLines.join("\n") }],
				details: {
					action: "info",
					targetPath: resolvedPath,
					fileSize: fileStat.size,
					format: parsed.format,
					endianness: parsed.endianness,
					version: parsed.version,
					snapLen: parsed.snapLen,
					linkType: parsed.linkType,
					totalPackets: allPackets.length,
					duration,
					protocolCounts,
					topEndpoints,
					interfaces: parsed.interfaces,
					packetDetail,
				},
			};
		}

		// ------------------------------------------------------------------------
		// Action: list
		// ------------------------------------------------------------------------
		if (action === "list") {
			// Apply filters
			let filtered = allPackets;

			if (params.protocol) {
				const pLower = params.protocol.toLowerCase();
				filtered = filtered.filter(p => {
					const app = p.applicationProtocol?.toLowerCase();
					const trans = p.transportProtocol?.toLowerCase();
					const net = p.networkProtocol?.toLowerCase();
					return (
						app === pLower ||
						trans === pLower ||
						net === pLower ||
						app?.includes(pLower) ||
						p.summary.toLowerCase().includes(pLower)
					);
				});
			}

			if (params.ip) {
				const ipFilter = params.ip;
				filtered = filtered.filter(p => p.srcIp === ipFilter || p.dstIp === ipFilter);
			}

			if (params.port !== undefined) {
				const portFilter = params.port;
				filtered = filtered.filter(p => p.srcPort === portFilter || p.dstPort === portFilter);
			}

			const paged = filtered.slice(offset, offset + limit);

			const packetRows = paged.map(p => {
				const srcStr = p.srcIp ? `${p.srcIp}${p.srcPort ? `:${p.srcPort}` : ""}` : (p.srcMac ?? "-");
				const dstStr = p.dstIp ? `${p.dstIp}${p.dstPort ? `:${p.dstPort}` : ""}` : (p.dstMac ?? "-");
				const protoStr = p.applicationProtocol ?? p.transportProtocol ?? p.networkProtocol ?? "Other";
				const relTime = `+${p.relativeSeconds.toFixed(4)}s`;
				return {
					number: p.index,
					time: p.timestampIso,
					relative: relTime,
					src: srcStr,
					dst: dstStr,
					protocol: protoStr,
					length: p.capturedLength,
					summary: p.summary,
				};
			});

			const textLines = [
				`# Packets in ${resolvedPath} (${filtered.length} matching, showing ${offset + 1}-${offset + paged.length})`,
				"| # | Time | Source | Destination | Protocol | Len | Info |",
				"|---|---|---|---|---|---|---|",
				...packetRows.map(
					r =>
						`| ${r.number} | ${r.relative} | ${r.src} | ${r.dst} | ${r.protocol} | ${r.length} | ${r.summary} |`,
				),
			];

			if (filtered.length > offset + limit) {
				textLines.push(
					"",
					`*Note: ${filtered.length - (offset + limit)} additional packets available. Use offset=${offset + limit} to page further.*`,
				);
			}

			if (packetDetail) {
				textLines.push(
					"",
					`## Packet #${packetDetail.packetNumber} Detail`,
					`- **Timestamp**: ${packetDetail.timestamp}`,
					`- **Summary**: ${packetDetail.applicationLayer?.summary ?? ""}`,
				);
			}

			return {
				content: [{ type: "text", text: textLines.join("\n") }],
				details: {
					action: "list",
					targetPath: resolvedPath,
					fileSize: fileStat.size,
					format: parsed.format,
					endianness: parsed.endianness,
					version: parsed.version,
					totalPackets: allPackets.length,
					duration,
					packets: packetRows,
					packetDetail,
				},
			};
		}

		// ------------------------------------------------------------------------
		// Action: endpoints
		// ------------------------------------------------------------------------
		if (action === "endpoints") {
			const map: Record<
				string,
				{
					ip: string;
					packetsSent: number;
					packetsReceived: number;
					bytesSent: number;
					bytesReceived: number;
					protocols: Set<string>;
					ports: Set<number>;
					hostnames: Set<string>;
				}
			> = {};

			for (const pkt of allPackets) {
				if (pkt.networkProtocol !== "IPv4" && pkt.networkProtocol !== "IPv6") {
					continue;
				}
				const proto = pkt.applicationProtocol ?? pkt.transportProtocol ?? pkt.networkProtocol ?? "Other";
				if (pkt.srcIp) {
					const entry = map[pkt.srcIp] ?? {
						ip: pkt.srcIp,
						packetsSent: 0,
						packetsReceived: 0,
						bytesSent: 0,
						bytesReceived: 0,
						protocols: new Set<string>(),
						ports: new Set<number>(),
						hostnames: new Set<string>(),
					};
					entry.packetsSent++;
					entry.bytesSent += pkt.capturedLength;
					entry.protocols.add(proto);
					if (pkt.srcPort) entry.ports.add(pkt.srcPort);
					if (pkt.tlsSni) entry.hostnames.add(pkt.tlsSni);
					map[pkt.srcIp] = entry;
				}

				if (pkt.dstIp) {
					const entry = map[pkt.dstIp] ?? {
						ip: pkt.dstIp,
						packetsSent: 0,
						packetsReceived: 0,
						bytesSent: 0,
						bytesReceived: 0,
						protocols: new Set<string>(),
						ports: new Set<number>(),
						hostnames: new Set<string>(),
					};
					entry.packetsReceived++;
					entry.bytesReceived += pkt.capturedLength;
					entry.protocols.add(proto);
					if (pkt.dstPort) entry.ports.add(pkt.dstPort);
					if (pkt.tlsSni) entry.hostnames.add(pkt.tlsSni);
					map[pkt.dstIp] = entry;
				}

				if (pkt.dns?.answers) {
					for (const ans of pkt.dns.answers) {
						if (ans.data && (ans.type === "A" || ans.type === "AAAA") && map[ans.data]) {
							map[ans.data].hostnames.add(ans.domain);
						}
					}
				}
			}

			const endpointsList = Object.values(map)
				.map(e => ({
					ip: e.ip,
					packetsSent: e.packetsSent,
					packetsReceived: e.packetsReceived,
					totalPackets: e.packetsSent + e.packetsReceived,
					bytesSent: e.bytesSent,
					bytesReceived: e.bytesReceived,
					totalBytes: e.bytesSent + e.bytesReceived,
					protocols: Array.from(e.protocols),
					ports: Array.from(e.ports).sort((a, b) => a - b),
					hostnames: Array.from(e.hostnames),
				}))
				.sort((a, b) => b.totalPackets - a.totalPackets);

			const pagedEndpoints = endpointsList.slice(offset, offset + limit);

			const textLines = [
				`# IP Endpoints in ${resolvedPath} (${endpointsList.length} total, showing top ${pagedEndpoints.length})`,
				"| IP Address | Total Packets | Tx / Rx | Total Bytes | Protocols | Hostnames |",
				"|---|---|---|---|---|---|",
				...pagedEndpoints.map(e => {
					const txRx = `${e.packetsSent} / ${e.packetsReceived}`;
					const hosts = e.hostnames.length > 0 ? e.hostnames.join(", ") : "-";
					const protos = e.protocols.join(", ");
					return `| \`${e.ip}\` | ${e.totalPackets} | ${txRx} | ${formatBytes(e.totalBytes)} | ${protos} | ${hosts} |`;
				}),
			];

			return {
				content: [{ type: "text", text: textLines.join("\n") }],
				details: {
					action: "endpoints",
					targetPath: resolvedPath,
					fileSize: fileStat.size,
					format: parsed.format,
					endianness: parsed.endianness,
					version: parsed.version,
					totalPackets: allPackets.length,
					endpoints: pagedEndpoints,
				},
			};
		}

		// ------------------------------------------------------------------------
		// Action: conversations
		// ------------------------------------------------------------------------
		if (action === "conversations") {
			const convMap: Record<
				string,
				{
					endpointA: string;
					endpointB: string;
					protocol: string;
					packetsAtoB: number;
					bytesAtoB: number;
					packetsBtoA: number;
					bytesBtoA: number;
				}
			> = {};

			for (const pkt of allPackets) {
				if (!pkt.srcIp || !pkt.dstIp) continue;
				const proto = pkt.transportProtocol ?? pkt.networkProtocol ?? "Other";
				const epSrc = `${pkt.srcIp}${pkt.srcPort ? `:${pkt.srcPort}` : ""}`;
				const epDst = `${pkt.dstIp}${pkt.dstPort ? `:${pkt.dstPort}` : ""}`;

				// Canonical key independent of direction
				const isA = epSrc <= epDst;
				const epA = isA ? epSrc : epDst;
				const epB = isA ? epDst : epSrc;
				const key = `${proto}|${epA}<->${epB}`;

				let entry = convMap[key];
				if (!entry) {
					entry = {
						endpointA: epA,
						endpointB: epB,
						protocol: proto,
						packetsAtoB: 0,
						bytesAtoB: 0,
						packetsBtoA: 0,
						bytesBtoA: 0,
					};
					convMap[key] = entry;
				}

				if (isA) {
					entry.packetsAtoB++;
					entry.bytesAtoB += pkt.capturedLength;
				} else {
					entry.packetsBtoA++;
					entry.bytesBtoA += pkt.capturedLength;
				}
			}

			const conversationsList = Object.values(convMap)
				.map(c => ({
					endpointA: c.endpointA,
					endpointB: c.endpointB,
					protocol: c.protocol,
					packetsAtoB: c.packetsAtoB,
					bytesAtoB: c.bytesAtoB,
					packetsBtoA: c.packetsBtoA,
					bytesBtoA: c.bytesBtoA,
					totalPackets: c.packetsAtoB + c.packetsBtoA,
					totalBytes: c.bytesAtoB + c.bytesBtoA,
				}))
				.sort((a, b) => b.totalBytes - a.totalBytes);

			const pagedConversations = conversationsList.slice(offset, offset + limit);

			const textLines = [
				`# Network Conversations in ${resolvedPath} (${conversationsList.length} total, showing top ${pagedConversations.length})`,
				"| Endpoint A | Endpoint B | Proto | Pkts (A->B / B->A) | Bytes (A->B / B->A) | Total Bytes |",
				"|---|---|---|---|---|---|",
				...pagedConversations.map(c => {
					const pkts = `${c.packetsAtoB} / ${c.packetsBtoA}`;
					const bytes = `${formatBytes(c.bytesAtoB)} / ${formatBytes(c.bytesBtoA)}`;
					return `| \`${c.endpointA}\` | \`${c.endpointB}\` | ${c.protocol} | ${pkts} | ${bytes} | ${formatBytes(c.totalBytes)} |`;
				}),
			];

			return {
				content: [{ type: "text", text: textLines.join("\n") }],
				details: {
					action: "conversations",
					targetPath: resolvedPath,
					fileSize: fileStat.size,
					format: parsed.format,
					endianness: parsed.endianness,
					version: parsed.version,
					totalPackets: allPackets.length,
					conversations: pagedConversations,
				},
			};
		}

		// ------------------------------------------------------------------------
		// Action: dns
		// ------------------------------------------------------------------------
		if (action === "dns") {
			const dnsPackets = allPackets.filter(p => p.dns !== undefined);
			const paged = dnsPackets.slice(offset, offset + limit);

			const dnsQueries = paged.map(p => {
				const dns = p.dns!;
				const domain = dns.questions[0]?.domain ?? "-";
				const qtype = dns.questions[0]?.type ?? "-";
				const answers = dns.answers.map(a => `${a.type} ${a.data ?? ""}`.trim());
				return {
					packetNumber: p.index,
					time: p.timestampIso,
					qr: dns.qr,
					id: dns.id,
					domain,
					type: qtype,
					rcode: dns.rcode,
					answers,
				};
			});

			const textLines = [
				`# DNS Forensics in ${resolvedPath} (${dnsPackets.length} queries/responses found)`,
				"| # | QR | ID | Type | Query Domain | RCODE | Answers |",
				"|---|---|---|---|---|---|---|",
				...dnsQueries.map(q => {
					const ansStr = q.answers.length > 0 ? q.answers.join("; ") : "-";
					return `| ${q.packetNumber} | ${q.qr} | 0x${q.id.toString(16)} | ${q.type} | \`${q.domain}\` | ${q.rcode} | ${ansStr} |`;
				}),
			];

			return {
				content: [{ type: "text", text: textLines.join("\n") }],
				details: {
					action: "dns",
					targetPath: resolvedPath,
					fileSize: fileStat.size,
					format: parsed.format,
					endianness: parsed.endianness,
					version: parsed.version,
					totalPackets: allPackets.length,
					dnsQueries,
				},
			};
		}

		throw new ToolError(`Unsupported action: ${String(action)}`);
	}
}
