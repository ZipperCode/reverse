import { beforeAll, afterAll, describe, expect, it } from "bun:test";
import * as os from "node:os";
import * as path from "node:path";
import * as fs from "node:fs/promises";
import { Settings } from "@reverse/coding-agent/config/settings";
import { createTools, PcapInspectTool, type ToolSession } from "@reverse/coding-agent/tools";
import { BUILTIN_TOOL_NAMES, normalizeToolName } from "@reverse/coding-agent/tools/builtin-names";
import { removeWithRetries } from "@reverse/utils";

function createTestSession(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
	};
}

function textOf(result: { content: Array<{ type: string; text?: string }> }): string {
	return result.content
		.map(item => item.text ?? "")
		.join("\n")
		.trim();
}

// ============================================================================
// Fixture Generators
// ============================================================================

/**
 * Builds a TLS ClientHello packet with Server Name Indication (SNI).
 */
function createTlsClientHelloPayload(sniHostname: string): Buffer {
	const sniBuf = Buffer.from(sniHostname);
	const extBuf = Buffer.alloc(4 + 2 + 3 + sniBuf.length);
	extBuf.writeUInt16BE(0, 0); // Extension type: server_name (0)
	extBuf.writeUInt16BE(2 + 3 + sniBuf.length, 2); // Extension length
	extBuf.writeUInt16BE(3 + sniBuf.length, 4); // ServerNameList length
	extBuf[6] = 0; // NameType: host_name (0)
	extBuf.writeUInt16BE(sniBuf.length, 7); // HostName length
	sniBuf.copy(extBuf, 9);

	const random = Buffer.alloc(32, 0x5a);
	const clientHello = Buffer.concat([
		Buffer.from([
			0x16,
			0x03,
			0x01,
			0x00,
			0x00, // TLS record header (type 22, TLS 1.0, len patched later)
			0x01,
			0x00,
			0x00,
			0x00, // ClientHello (type 1, len patched later)
			0x03,
			0x03, // client_version (TLS 1.2)
		]),
		random,
		Buffer.from([
			0x00, // session_id length 0
			0x00,
			0x02,
			0xc0,
			0x2f, // cipher suites (2 bytes len, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
			0x01,
			0x00, // compression methods (1 byte len, null)
		]),
		Buffer.from([(extBuf.length >> 8) & 0xff, extBuf.length & 0xff]),
		extBuf,
	]);

	// Patch lengths
	clientHello.writeUInt16BE(clientHello.length - 5, 3);
	const hsLen = clientHello.length - 9;
	clientHello[6] = (hsLen >> 16) & 0xff;
	clientHello[7] = (hsLen >> 8) & 0xff;
	clientHello[8] = hsLen & 0xff;

	return clientHello;
}

/**
 * Builds a DNS query packet payload for a given domain name and type.
 */
function createDnsQueryPayload(domain: string, qtype: number = 1): Buffer {
	const labels = domain.split(".");
	const qnameParts: Buffer[] = [];
	for (const label of labels) {
		const buf = Buffer.alloc(1 + label.length);
		buf[0] = label.length;
		buf.write(label, 1);
		qnameParts.push(buf);
	}
	qnameParts.push(Buffer.from([0])); // root label null terminator

	const qname = Buffer.concat(qnameParts);
	const header = Buffer.alloc(12);
	header.writeUInt16BE(0x1234, 0); // ID
	header.writeUInt16BE(0x0100, 2); // Flags: standard query, recursion desired
	header.writeUInt16BE(1, 4); // QDCOUNT: 1
	header.writeUInt16BE(0, 6); // ANCOUNT: 0
	header.writeUInt16BE(0, 8); // NSCOUNT: 0
	header.writeUInt16BE(0, 10); // ARCOUNT: 0

	const trailer = Buffer.alloc(4);
	trailer.writeUInt16BE(qtype, 0); // QTYPE (1 = A)
	trailer.writeUInt16BE(1, 2); // QCLASS (1 = IN)

	return Buffer.concat([header, qname, trailer]);
}

/**
 * Encapsulates an IPv4 packet into an Ethernet frame.
 */
function encapsulateEthernetIpv4(
	srcIp: [number, number, number, number],
	dstIp: [number, number, number, number],
	ipProto: number,
	transportPayload: Buffer,
): Buffer {
	const ipHeader = Buffer.alloc(20);
	ipHeader[0] = 0x45; // Version 4, IHL 5
	ipHeader[1] = 0x00;
	ipHeader.writeUInt16BE(20 + transportPayload.length, 2); // Total length
	ipHeader.writeUInt16BE(0x5432, 4); // ID
	ipHeader.writeUInt16BE(0x4000, 6); // Flags: DF
	ipHeader[8] = 64; // TTL
	ipHeader[9] = ipProto; // Protocol
	ipHeader.writeUInt16BE(0, 10); // Checksum
	Buffer.from(srcIp).copy(ipHeader, 12);
	Buffer.from(dstIp).copy(ipHeader, 16);

	const ethHeader = Buffer.alloc(14);
	Buffer.from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]).copy(ethHeader, 0); // Dst MAC
	Buffer.from([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]).copy(ethHeader, 6); // Src MAC
	ethHeader.writeUInt16BE(0x0800, 12); // EtherType: IPv4

	return Buffer.concat([ethHeader, ipHeader, transportPayload]);
}

/**
 * Creates TCP payload with header and data.
 */
function createTcpPacket(
	srcPort: number,
	dstPort: number,
	seq: number,
	ack: number,
	flags: number,
	payload: Buffer = Buffer.alloc(0),
): Buffer {
	const tcpHeader = Buffer.alloc(20);
	tcpHeader.writeUInt16BE(srcPort, 0);
	tcpHeader.writeUInt16BE(dstPort, 2);
	tcpHeader.writeUInt32BE(seq, 4);
	tcpHeader.writeUInt32BE(ack, 8);
	tcpHeader[12] = 0x50; // Data offset 5 (20 bytes)
	tcpHeader[13] = flags; // Flags (SYN=0x02, ACK=0x10, PSH=0x08, etc.)
	tcpHeader.writeUInt16BE(65535, 14); // Window size
	tcpHeader.writeUInt16BE(0, 16); // Checksum
	tcpHeader.writeUInt16BE(0, 18); // Urgent pointer

	return Buffer.concat([tcpHeader, payload]);
}

/**
 * Creates UDP packet with header and data.
 */
function createUdpPacket(srcPort: number, dstPort: number, payload: Buffer): Buffer {
	const udpHeader = Buffer.alloc(8);
	udpHeader.writeUInt16BE(srcPort, 0);
	udpHeader.writeUInt16BE(dstPort, 2);
	udpHeader.writeUInt16BE(8 + payload.length, 4);
	udpHeader.writeUInt16BE(0, 6); // Checksum

	return Buffer.concat([udpHeader, payload]);
}

/**
 * Builds a multi-packet classic PCAP fixture with HTTP, TLS, DNS, ICMP, and ARP.
 */
function createClassicPcapFixture(): Buffer {
	const packets: Array<{ sec: number; usec: number; data: Buffer }> = [];
	const tSec = 1700000000;
	let tUsec = 100000;

	// 1. TCP SYN
	const tcpSyn = encapsulateEthernetIpv4(
		[192, 168, 1, 100],
		[93, 184, 216, 34],
		6,
		createTcpPacket(54321, 80, 1000, 0, 0x02),
	);
	packets.push({ sec: tSec, usec: tUsec, data: tcpSyn });

	// 2. HTTP GET Request
	tUsec += 50000;
	const httpPayload = Buffer.from("GET /api/v1/status HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test/1.0\r\n\r\n");
	const httpPkt = encapsulateEthernetIpv4(
		[192, 168, 1, 100],
		[93, 184, 216, 34],
		6,
		createTcpPacket(54321, 80, 1001, 5000, 0x18, httpPayload),
	);
	packets.push({ sec: tSec, usec: tUsec, data: httpPkt });

	// 3. TLS ClientHello with SNI api.example.com
	tUsec += 60000;
	const tlsPayload = createTlsClientHelloPayload("api.example.com");
	const tlsPkt = encapsulateEthernetIpv4(
		[192, 168, 1, 100],
		[104, 16, 1, 1],
		6,
		createTcpPacket(54322, 443, 2000, 0, 0x18, tlsPayload),
	);
	packets.push({ sec: tSec, usec: tUsec, data: tlsPkt });

	// 4. DNS Query for example.org
	tUsec += 40000;
	const dnsPayload = createDnsQueryPayload("example.org", 1);
	const dnsPkt = encapsulateEthernetIpv4([192, 168, 1, 100], [8, 8, 8, 8], 17, createUdpPacket(55555, 53, dnsPayload));
	packets.push({ sec: tSec, usec: tUsec, data: dnsPkt });

	// 5. ICMP Echo Request
	tUsec += 30000;
	const icmpPayload = Buffer.from([0x08, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04]);
	const icmpPkt = encapsulateEthernetIpv4([192, 168, 1, 100], [8, 8, 8, 8], 1, icmpPayload);
	packets.push({ sec: tSec, usec: tUsec, data: icmpPkt });

	// 6. ARP Request
	tUsec += 20000;
	const arpHeader = Buffer.alloc(28);
	arpHeader.writeUInt16BE(1, 0); // HW: Ethernet
	arpHeader.writeUInt16BE(0x0800, 2); // Proto: IPv4
	arpHeader[4] = 6; // HW size
	arpHeader[5] = 4; // Proto size
	arpHeader.writeUInt16BE(1, 6); // Opcode: Request (1)
	Buffer.from([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]).copy(arpHeader, 8); // Sender MAC
	Buffer.from([192, 168, 1, 100]).copy(arpHeader, 14); // Sender IP
	Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).copy(arpHeader, 18); // Target MAC
	Buffer.from([192, 168, 1, 1]).copy(arpHeader, 24); // Target IP

	const arpEth = Buffer.alloc(14);
	Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).copy(arpEth, 0); // Broadcast
	Buffer.from([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]).copy(arpEth, 6);
	arpEth.writeUInt16BE(0x0806, 12); // EtherType: ARP
	const arpPkt = Buffer.concat([arpEth, arpHeader]);
	packets.push({ sec: tSec, usec: tUsec, data: arpPkt });

	// Global Header (24 bytes)
	const globalHdr = Buffer.alloc(24);
	globalHdr.writeUInt32LE(0xa1b2c3d4, 0); // Magic: microsecond LE
	globalHdr.writeUInt16LE(2, 4); // Major 2
	globalHdr.writeUInt16LE(4, 6); // Minor 4
	globalHdr.writeInt32LE(0, 8); // Timezone 0
	globalHdr.writeUInt32LE(0, 12); // Sigfigs 0
	globalHdr.writeUInt32LE(65535, 16); // Snaplen
	globalHdr.writeUInt32LE(1, 20); // LinkType: Ethernet (1)

	const chunkList: Buffer[] = [globalHdr];
	for (const p of packets) {
		const pktHdr = Buffer.alloc(16);
		pktHdr.writeUInt32LE(p.sec, 0);
		pktHdr.writeUInt32LE(p.usec, 4);
		pktHdr.writeUInt32LE(p.data.length, 8); // CapLen
		pktHdr.writeUInt32LE(p.data.length, 12); // OrigLen
		chunkList.push(pktHdr, p.data);
	}

	return Buffer.concat(chunkList);
}

/**
 * Builds a PCAPNG fixture with SHB, IDB, and EPB blocks.
 */
function createPcapNgFixture(): Buffer {
	const chunks: Buffer[] = [];

	// 1. Section Header Block (SHB)
	const shb = Buffer.alloc(28);
	shb.writeUInt32LE(0x0a0d0d0a, 0); // Type: SHB
	shb.writeUInt32LE(28, 4); // Block total len
	shb.writeUInt32LE(0x1a2e3b4c, 8); // Byte-Order Magic LE
	shb.writeUInt16LE(1, 12); // Major 1
	shb.writeUInt16LE(0, 14); // Minor 0
	shb.writeBigInt64LE(-1n, 16); // Section length unknown
	shb.writeUInt32LE(28, 24); // Trailer total len
	chunks.push(shb);

	// 2. Interface Description Block (IDB) with options (name: eth0)
	const ifName = Buffer.from("eth0");
	const optLen = 4 + Math.ceil(ifName.length / 4) * 4;
	const idbLen = 20 + optLen + 4; // Header(16) + opts + endopt(4) + trailer(4)
	const idb = Buffer.alloc(idbLen);
	idb.writeUInt32LE(1, 0); // Type: IDB
	idb.writeUInt32LE(idbLen, 4);
	idb.writeUInt16LE(1, 8); // LinkType: Ethernet (1)
	idb.writeUInt16LE(0, 10);
	idb.writeUInt32LE(65535, 12); // Snaplen
	// Option: if_name (code 2)
	idb.writeUInt16LE(2, 16);
	idb.writeUInt16LE(ifName.length, 18);
	ifName.copy(idb, 20);
	// End of options
	idb.writeUInt32LE(0, 20 + Math.ceil(ifName.length / 4) * 4);
	idb.writeUInt32LE(idbLen, idbLen - 4); // Trailer
	chunks.push(idb);

	// 3. Enhanced Packet Block (EPB)
	const rawPkt = encapsulateEthernetIpv4([10, 0, 0, 1], [10, 0, 0, 2], 6, createTcpPacket(8080, 9090, 42, 0, 0x02));
	const paddedPktLen = Math.ceil(rawPkt.length / 4) * 4;
	const epbLen = 32 + paddedPktLen;
	const epb = Buffer.alloc(epbLen);
	epb.writeUInt32LE(6, 0); // Type: EPB
	epb.writeUInt32LE(epbLen, 4);
	epb.writeUInt32LE(0, 8); // Interface ID 0
	epb.writeUInt32LE(0, 12); // Timestamp high
	epb.writeUInt32LE(1000000, 16); // Timestamp low (1s at 1e-6)
	epb.writeUInt32LE(rawPkt.length, 20); // Caplen
	epb.writeUInt32LE(rawPkt.length, 24); // Origlen
	rawPkt.copy(epb, 28);
	epb.writeUInt32LE(epbLen, epbLen - 4); // Trailer
	chunks.push(epb);

	return Buffer.concat(chunks);
}

// ============================================================================
// Test Suites
// ============================================================================

describe("pcap_inspect registration and discovery", () => {
	it("registers in BUILTIN_TOOL_NAMES and normalizes aliases", () => {
		expect(BUILTIN_TOOL_NAMES).toContain("pcap_inspect");
		expect(normalizeToolName("pcap_inspect")).toBe("pcap_inspect");
		expect(normalizeToolName("pcap")).toBe("pcap_inspect");
		expect(normalizeToolName("pcapng")).toBe("pcap_inspect");
		expect(normalizeToolName("pcap_analyze")).toBe("pcap_inspect");
		expect(normalizeToolName("packet_inspect")).toBe("pcap_inspect");
	});

	it("creates tool instance with discoverable loadMode and read approval", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "pcap-reg-"));
		try {
			const session = createTestSession(tempDir);
			const tools = await createTools(session, ["pcap_inspect"]);
			const tool = tools.find(t => t.name === "pcap_inspect") as PcapInspectTool | undefined;
			expect(tool).toBeDefined();
			expect(tool?.name).toBe("pcap_inspect");
			expect(tool?.approval).toBe("read");
			expect(tool?.loadMode).toBe("discoverable");
			expect(tool?.label).toBe("PCAP / PCAPNG Network Inspect");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("pcap_inspect path validation and error handling", () => {
	it("rejects non-existent capture file with informative error", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "pcap-miss-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new PcapInspectTool(session);
			await expect(
				tool.execute("call-1", {
					action: "info",
					path: "non_existent.pcap",
				}),
			).rejects.toThrow("Capture file not found");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects directory target", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "pcap-dir-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new PcapInspectTool(session);
			await expect(
				tool.execute("call-2", {
					action: "info",
					path: tempDir,
				}),
			).rejects.toThrow("Target path is a directory");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects invalid/corrupt magic header", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "pcap-corrupt-"));
		try {
			const filePath = path.join(tempDir, "invalid.pcap");
			await fs.writeFile(filePath, Buffer.from("THIS IS NOT A VALID PCAP FILE AT ALL!!"));
			const session = createTestSession(tempDir);
			const tool = new PcapInspectTool(session);
			await expect(
				tool.execute("call-3", {
					action: "info",
					path: "invalid.pcap",
				}),
			).rejects.toThrow("Not a valid PCAP or PCAPNG capture file");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("pcap_inspect classic PCAP analysis", () => {
	let tempDir: string;
	let pcapPath: string;

	beforeAll(async () => {
		tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "pcap-classic-"));
		pcapPath = path.join(tempDir, "sample.pcap");
		await fs.writeFile(pcapPath, createClassicPcapFixture());
	});

	afterAll(async () => {
		await removeWithRetries(tempDir);
	});

	it("inspects capture metadata and protocol breakdown with action: info", async () => {
		const session = createTestSession(tempDir);
		const tool = new PcapInspectTool(session);
		const res = await tool.execute("call-info", {
			action: "info",
			path: "sample.pcap",
		});

		expect(res.details.format).toBe("pcap");
		expect(res.details.endianness).toBe("little");
		expect(res.details.version).toBe("2.4");
		expect(res.details.totalPackets).toBe(6);
		expect(res.details.linkType).toContain("Ethernet");

		// Protocol breakdown checks
		expect(res.details.protocolCounts).toBeDefined();
		expect(res.details.protocolCounts?.HTTP).toBe(1);
		expect(res.details.protocolCounts?.TLS).toBe(1);
		expect(res.details.protocolCounts?.DNS).toBe(1);
		expect(res.details.protocolCounts?.ICMP).toBe(1);
		expect(res.details.protocolCounts?.ARP).toBe(1);

		// Top endpoints checks
		expect(res.details.topEndpoints?.length).toBeGreaterThanOrEqual(2);
		const ips = res.details.topEndpoints?.map(e => e.ip);
		expect(ips).toContain("192.168.1.100");
		expect(ips).toContain("93.184.216.34");

		const text = textOf(res);
		expect(text).toContain("PCAP (little endian, version 2.4)");
		expect(text).toContain("HTTP: 1 packets");
		expect(text).toContain("TLS: 1 packets");
	});

	it("lists packets with Wireshark-like summaries and filters with action: list", async () => {
		const session = createTestSession(tempDir);
		const tool = new PcapInspectTool(session);

		// List all
		const listAll = await tool.execute("call-list-all", {
			action: "list",
			path: "sample.pcap",
		});
		expect(listAll.details.packets?.length).toBe(6);

		// Filter by protocol: http
		const listHttp = await tool.execute("call-list-http", {
			action: "list",
			path: "sample.pcap",
			protocol: "http",
		});
		expect(listHttp.details.packets?.length).toBe(1);
		expect(listHttp.details.packets?.[0].summary).toContain("GET /api/v1/status");

		// Filter by IP: 93.184.216.34
		const listIp = await tool.execute("call-list-ip", {
			action: "list",
			path: "sample.pcap",
			ip: "93.184.216.34",
		});
		expect(listIp.details.packets?.length).toBe(2);

		// Filter by port: 443
		const listPort = await tool.execute("call-list-port", {
			action: "list",
			path: "sample.pcap",
			port: 443,
		});
		expect(listPort.details.packets?.length).toBe(1);
		expect(listPort.details.packets?.[0].summary).toContain("Client Hello (SNI: api.example.com)");

		// Pagination
		const paged = await tool.execute("call-list-page", {
			action: "list",
			path: "sample.pcap",
			limit: 2,
			offset: 1,
		});
		expect(paged.details.packets?.length).toBe(2);
		expect(paged.details.packets?.[0].number).toBe(2);
	});

	it("decodes detailed packet layers and payload preview when packet_number is provided", async () => {
		const session = createTestSession(tempDir);
		const tool = new PcapInspectTool(session);

		// Inspect packet #3 (TLS ClientHello)
		const res = await tool.execute("call-pkt3", {
			action: "list",
			path: "sample.pcap",
			packet_number: 3,
		});

		expect(res.details.packetDetail).toBeDefined();
		expect(res.details.packetDetail?.packetNumber).toBe(3);
		expect(res.details.packetDetail?.applicationLayer?.tlsSni).toBe("api.example.com");
		expect(res.details.packetDetail?.transportLayer?.protocol).toBe("TCP");
		expect(res.details.packetDetail?.transportLayer?.dstPort).toBe(443);
		expect(res.details.packetDetail?.networkLayer?.dstIp).toBe("104.16.1.1");
	});

	it("aggregates IP statistics and hostnames with action: endpoints", async () => {
		const session = createTestSession(tempDir);
		const tool = new PcapInspectTool(session);

		const res = await tool.execute("call-endpoints", {
			action: "endpoints",
			path: "sample.pcap",
		});

		expect(res.details.endpoints).toBeDefined();
		expect(res.details.endpoints?.length).toBeGreaterThanOrEqual(3);

		const client = res.details.endpoints?.find(e => e.ip === "192.168.1.100");
		expect(client).toBeDefined();
		expect(client?.packetsSent).toBe(5);

		// TLS destination should resolve SNI hostname
		const tlsDest = res.details.endpoints?.find(e => e.ip === "104.16.1.1");
		expect(tlsDest).toBeDefined();
		expect(tlsDest?.hostnames).toContain("api.example.com");

		const text = textOf(res);
		expect(text).toContain("IP Endpoints in");
		expect(text).toContain("api.example.com");
	});

	it("groups communication flows with action: conversations", async () => {
		const session = createTestSession(tempDir);
		const tool = new PcapInspectTool(session);

		const res = await tool.execute("call-conv", {
			action: "conversations",
			path: "sample.pcap",
		});

		expect(res.details.conversations).toBeDefined();
		expect(res.details.conversations?.length).toBeGreaterThanOrEqual(3);

		const text = textOf(res);
		expect(text).toContain("Network Conversations in");
	});

	it("extracts domain queries and record types with action: dns", async () => {
		const session = createTestSession(tempDir);
		const tool = new PcapInspectTool(session);

		const res = await tool.execute("call-dns", {
			action: "dns",
			path: "sample.pcap",
		});

		expect(res.details.dnsQueries).toBeDefined();
		expect(res.details.dnsQueries?.length).toBe(1);
		expect(res.details.dnsQueries?.[0].domain).toBe("example.org");
		expect(res.details.dnsQueries?.[0].type).toBe("A");
		expect(res.details.dnsQueries?.[0].qr).toBe("query");

		const text = textOf(res);
		expect(text).toContain("example.org");
		expect(text).toContain("0x1234");
	});
});

describe("pcap_inspect PCAPNG analysis", () => {
	let tempDir: string;
	let pcapngPath: string;

	beforeAll(async () => {
		tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "pcap-ng-"));
		pcapngPath = path.join(tempDir, "capture.pcapng");
		await fs.writeFile(pcapngPath, createPcapNgFixture());
	});

	afterAll(async () => {
		await removeWithRetries(tempDir);
	});

	it("parses PCAPNG blocks, interfaces, and packets", async () => {
		const session = createTestSession(tempDir);
		const tool = new PcapInspectTool(session);

		const res = await tool.execute("call-pcapng-info", {
			action: "info",
			path: "capture.pcapng",
		});

		expect(res.details.format).toBe("pcapng");
		expect(res.details.totalPackets).toBe(1);
		expect(res.details.interfaces).toBeDefined();
		expect(res.details.interfaces?.length).toBe(1);
		expect(res.details.interfaces?.[0].name).toBe("eth0");

		const listRes = await tool.execute("call-pcapng-list", {
			action: "list",
			path: "capture.pcapng",
		});
		expect(listRes.details.packets?.length).toBe(1);
		expect(listRes.details.packets?.[0].src).toBe("10.0.0.1:8080");
		expect(listRes.details.packets?.[0].dst).toBe("10.0.0.2:9090");
	});
});
