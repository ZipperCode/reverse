import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "@rva/coding-agent/config/settings";
import {
	createTools,
	redactWebSocketUrl,
	type ToolSession,
	WebSocketObserveTool,
	type WebSocketObserveDetails,
	type WebSocketObserveParams,
} from "@rva/coding-agent/tools";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { BUILTIN_TOOL_NAMES } from "@rva/coding-agent/tools/builtin-names";
import { removeWithRetries } from "@rva/utils";

let root: string;
let artifactCounter = 0;
const artifactPaths: string[] = [];

function createTestSession(): ToolSession {
	return {
		cwd: root,
		hasUI: false,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
		allocateOutputArtifact: async () => {
			artifactCounter += 1;
			const artifactPath = path.join(root, `artifact-${artifactCounter}.json`);
			artifactPaths.push(artifactPath);
			return { id: String(artifactCounter), path: artifactPath };
		},
	};
}

function textOf(result: { content: Array<{ type: string; text?: string }> }): string {
	return result.content
		.map(item => item.text ?? "")
		.join("\n")
		.trim();
}

async function writeFixture(name: string, content: string): Promise<string> {
	const filePath = path.join(root, name);
	await fs.writeFile(filePath, content);
	return name;
}

async function run(
	params: WebSocketObserveParams,
	session: ToolSession = createTestSession(),
): Promise<{ details: WebSocketObserveDetails; text: string }> {
	const tool = new WebSocketObserveTool(session);
	const result = await tool.execute("call", params);
	return { details: result.details!, text: textOf(result) };
}

const HAR_CAPTURE = JSON.stringify({
	log: {
		version: "1.2",
		creator: { name: "test", version: "1" },
		entries: [
			{
				request: { method: "GET", url: "https://api.example.com/health" },
				response: { status: 200 },
			},
			{
				request: { method: "GET", url: "wss://api.example.com/ws?token=SECRET&room=1" },
				_resourceType: "websocket",
				_webSocketMessages: [
					{
						type: "send",
						time: 1700000000.5,
						opcode: 1,
						data: JSON.stringify({ action: "subscribe", token: "SECRET", room: 1 }),
					},
					{
						type: "receive",
						time: 1700000001,
						opcode: 1,
						data: JSON.stringify({ ok: true, items: [1, 2] }),
					},
					{
						type: "send",
						time: 1700000002,
						opcode: 2,
						data: Buffer.from("binarydata").toString("base64"),
					},
				],
			},
		],
	},
});

beforeAll(async () => {
	root = await fs.mkdtemp(path.join(os.tmpdir(), "rva-websocket-observe-"));
});

afterAll(async () => {
	await removeWithRetries(root);
});

describe("websocket_observe registration", () => {
	it("registers a read-only discoverable builtin", async () => {
		expect(BUILTIN_TOOL_NAMES).toContain("websocket_observe");
		const tools = await createTools(createTestSession(), ["websocket_observe"]);
		const tool = tools.find(entry => entry.name === "websocket_observe");
		expect(tool).toBeDefined();
		expect(tool?.approval).toBe("read");
		expect(tool?.description).toContain("never opens a socket");
	});
});

describe("websocket_observe URL redaction", () => {
	it("redacts userinfo and sensitive query values", () => {
		const result = redactWebSocketUrl("wss://user:pass@example.com/ws?token=abc&room=7&api_key=xyz");
		expect(result.redacted).toBe(true);
		expect(result.url).not.toContain("abc");
		expect(result.url).not.toContain("xyz");
		expect(result.url).not.toContain("user:pass");
		expect(result.url).toContain("room=7");
		expect(result.url).toContain("redacted");
	});
});

describe("websocket_observe HAR inspect", () => {
	it("summarizes connections, frames, directions, opcodes, and redactions", async () => {
		await writeFixture("session.har", HAR_CAPTURE);
		const { details, text } = await run({ action: "inspect", path: "session.har" });
		expect(details.status).toBe("ok");
		expect(details.format).toBe("har");
		expect(details.totalConnections).toBe(1);
		expect(details.totalFrames).toBe(3);
		expect(details.connections?.[0]?.url).not.toContain("SECRET");
		expect(details.connections?.[0]?.inFrames).toBe(1);
		expect(details.connections?.[0]?.outFrames).toBe(2);
		expect(details.redactions).toBeGreaterThan(0);
		expect(text).toContain("in 1 / out 2");
		expect(text).toContain("Time range: 2023-11-14");
	});

	it("reports a HAR with no WebSocket entries as empty rather than invalid", async () => {
		await writeFixture(
			"http-only.har",
			JSON.stringify({ log: { entries: [{ request: { url: "https://example.com/" } }] } }),
		);
		const { details } = await run({ action: "inspect", path: "http-only.har" });
		expect(details.status).toBe("ok");
		expect(details.totalConnections).toBe(0);
		expect(details.totalFrames).toBe(0);
	});
});

describe("websocket_observe list and paging", () => {
	it("pages frames and reports the next offset", async () => {
		await writeFixture("paging.har", HAR_CAPTURE);
		const first = await run({ action: "list", path: "paging.har", limit: 2 });
		expect(first.details.frames?.map(frame => frame.index)).toEqual([0, 1]);
		expect(first.details.hasMore).toBe(true);
		expect(first.details.nextOffset).toBe(2);
		expect(first.text).toContain("next offset 2");
		const second = await run({ action: "list", path: "paging.har", offset: 2, limit: 2 });
		expect(second.details.frames?.map(frame => frame.index)).toEqual([2]);
		expect(second.details.hasMore).toBe(false);
	});

	it("filters by URL, direction, and opcode", async () => {
		await writeFixture("filters.har", HAR_CAPTURE);
		const byUrl = await run({ action: "list", path: "filters.har", url: "api.example" });
		expect(byUrl.details.frames).toHaveLength(3);
		const byDirection = await run({ action: "list", path: "filters.har", direction: "in" });
		expect(byDirection.details.frames).toHaveLength(1);
		expect(byDirection.details.frames?.[0]?.direction).toBe("in");
		const binary = await run({ action: "list", path: "filters.har", opcode: 2 });
		expect(binary.details.frames).toHaveLength(1);
		expect(binary.details.frames?.[0]?.preview).toContain("<binary payload, 10 bytes>");
	});

	it("redacts payload credentials and never echoes the raw secret", async () => {
		await writeFixture("redaction.har", HAR_CAPTURE);
		const { details, text } = await run({ action: "list", path: "redaction.har" });
		const outbound = details.frames?.[0];
		expect(outbound?.redacted).toBe(true);
		expect(outbound?.preview).not.toContain("SECRET");
		expect(outbound?.preview).toContain("[redacted]");
		expect(text).not.toContain("SECRET");
	});

	it("truncates previews of large text payloads", async () => {
		const large = JSON.stringify({ blob: "x".repeat(2000) });
		await writeFixture(
			"large.json",
			JSON.stringify({
				websockets: [
					{
						url: "wss://large.example/ws",
						frames: [{ direction: "out", opcode: 1, payload: large }],
					},
				],
			}),
		);
		const { details } = await run({ action: "list", path: "large.json" });
		expect(details.frames?.[0]?.previewTruncated).toBe(true);
		expect(details.frames?.[0]?.preview.length).toBeLessThanOrEqual(400);
		expect(details.frames?.[0]?.bytes).toBe(Buffer.byteLength(large));
	});
});

describe("websocket_observe structured capture formats", () => {
	it("reads a structured JSON connection capture", async () => {
		await writeFixture(
			"capture.json",
			JSON.stringify({
				websockets: [
					{
						url: "wss://chat.example/feed",
						frames: [
							{
								direction: "in",
								timestamp: "2024-01-01T00:00:00Z",
								opcode: 1,
								payload: '{"token":"t0p","n":1}',
							},
							{ type: "out", opcode: "text", message: "hello" },
						],
					},
				],
			}),
		);
		const { details } = await run({ action: "list", path: "capture.json" });
		expect(details.format).toBe("json");
		expect(details.totalConnections).toBe(1);
		expect(details.frames).toHaveLength(2);
		expect(details.frames?.[0]?.time).toBe("2024-01-01T00:00:00.000Z");
		expect(details.frames?.[0]?.preview).not.toContain("t0p");
		expect(details.frames?.[1]?.direction).toBe("out");
		const search = await run({ action: "search", path: "capture.json", filter: "HELLO" });
		expect(search.details.matchedFrames).toBe(1);
	});

	it("reads CDP Network.webSocket NDJSON events", async () => {
		await writeFixture(
			"cdp.ndjson",
			[
				JSON.stringify({
					method: "Network.webSocketCreated",
					params: { requestId: "r1", url: "wss://cdp.example/socket?access_token=abc" },
				}),
				JSON.stringify({
					method: "Network.webSocketFrameSent",
					params: { requestId: "r1", timestamp: 12.5, response: { opcode: 1, payloadData: "hello" } },
				}),
				JSON.stringify({
					method: "Network.webSocketFrameReceived",
					params: { requestId: "r1", timestamp: 13, response: { opcode: 2, payloadData: "AAECAw==" } },
				}),
			].join("\n"),
		);
		const { details } = await run({ action: "list", path: "cdp.ndjson" });
		expect(details.format).toBe("ndjson");
		expect(details.totalConnections).toBe(1);
		expect(details.frames?.map(frame => frame.direction)).toEqual(["out", "in"]);
		expect(details.frames?.[1]?.opcodeName).toBe("binary");
		expect(details.frames?.[1]?.bytes).toBe(4);
		expect(details.connections?.[0]?.url).not.toContain("abc");
	});
});

describe("websocket_observe search", () => {
	it("supports literal and regex filters over payloads", async () => {
		await writeFixture("search.har", HAR_CAPTURE);
		const literal = await run({ action: "search", path: "search.har", filter: "subscribe" });
		expect(literal.details.matchedFrames).toBe(1);
		const regex = await run({ action: "search", path: "search.har", filter: "sub.*ribe", regex: true });
		expect(regex.details.matchedFrames).toBe(1);
		const none = await run({ action: "search", path: "search.har", filter: "not-present" });
		expect(none.details.matchedFrames).toBe(0);
		expect(none.details.status).toBe("ok");
	});

	it("rejects search without a filter and invalid regular expressions", async () => {
		await writeFixture("search-errors.har", HAR_CAPTURE);
		await expect(run({ action: "search", path: "search-errors.har" })).rejects.toBeInstanceOf(ToolError);
		await expect(
			run({ action: "search", path: "search-errors.har", filter: "(", regex: true }),
		).rejects.toBeInstanceOf(ToolError);
	});
});

describe("websocket_observe error handling", () => {
	it("reports a missing file without throwing", async () => {
		const { details } = await run({ action: "inspect", path: "does-not-exist.har" });
		expect(details.status).toBe("not_found");
	});

	it("reports an empty file", async () => {
		await writeFixture("empty.har", "");
		const { details } = await run({ action: "inspect", path: "empty.har" });
		expect(details.status).toBe("empty");
	});

	it("reports corrupt HAR and unknown shapes as invalid_format", async () => {
		await writeFixture("corrupt.har", '{"log": {"entries": [');
		const corrupt = await run({ action: "inspect", path: "corrupt.har" });
		expect(corrupt.details.status).toBe("invalid_format");
		await writeFixture("unknown.json", JSON.stringify({ foo: "bar" }));
		const unknown = await run({ action: "inspect", path: "unknown.json" });
		expect(unknown.details.status).toBe("invalid_format");
		await writeFixture("corrupt.ndjson", '{"method":"Network.webSocketCreated"}\nnot json');
		const ndjson = await run({ action: "inspect", path: "corrupt.ndjson" });
		expect(ndjson.details.status).toBe("invalid_format");
	});

	it("rejects URL paths and inspect-only filter arguments", async () => {
		await expect(run({ action: "inspect", path: "wss://example.com/ws" })).rejects.toBeInstanceOf(ToolError);
		await expect(run({ action: "inspect", path: "x.har", direction: "in" })).rejects.toBeInstanceOf(ToolError);
		await expect(run({ action: "list", path: "x.har", export_format: "json" })).rejects.toBeInstanceOf(ToolError);
	});
});

describe("websocket_observe export", () => {
	it("writes redacted frames to a JSON artifact", async () => {
		await writeFixture("export.har", HAR_CAPTURE);
		const { details, text } = await run({ action: "export", path: "export.har", export_format: "json" });
		expect(details.status).toBe("ok");
		expect(details.artifactId).toBeDefined();
		expect(details.artifactPath).toBeDefined();
		expect(details.exportFormat).toBe("json");
		const written = await fs.readFile(details.artifactPath!, "utf8");
		expect(Buffer.byteLength(written)).toBe(details.bytesWritten!);
		const frames = JSON.parse(written) as Array<{ payload: string; direction: string }>;
		expect(frames).toHaveLength(3);
		expect(written).not.toContain("SECRET");
		expect(frames[0]?.payload).toContain("[redacted]");
		expect(frames[0]?.direction).toBe("out");
		expect(text).toContain("Saved artifact: artifact://");
	});

	it("writes NDJSON and honors the artifact byte cap", async () => {
		const bigPayload = "y".repeat(5000);
		await writeFixture(
			"export-large.json",
			JSON.stringify({
				websockets: [
					{
						url: "wss://large.example/ws",
						frames: [
							{ direction: "out", opcode: 1, payload: bigPayload },
							{ direction: "in", opcode: 1, payload: "small" },
						],
					},
				],
			}),
		);
		const { details } = await run({
			action: "export",
			path: "export-large.json",
			export_format: "ndjson",
			max_bytes: 1024,
		});
		expect(details.status).toBe("ok");
		expect(details.truncated).toBe(true);
		expect(details.payloadsTruncated).toBeGreaterThan(0);
		const written = await fs.readFile(details.artifactPath!, "utf8");
		expect(Buffer.byteLength(written)).toBeLessThanOrEqual(1024);
		const lines = written.trim().split("\n");
		expect(lines.length).toBeGreaterThanOrEqual(1);
		expect(JSON.parse(lines[0]!).payload.length).toBeLessThan(bigPayload.length);
	});

	it("paging applies to export and an empty selection writes nothing", async () => {
		await writeFixture("export-page.har", HAR_CAPTURE);
		const page = await run({ action: "export", path: "export-page.har", offset: 1, limit: 1 });
		expect(page.details.hasMore).toBe(true);
		const written = JSON.parse(await fs.readFile(page.details.artifactPath!, "utf8")) as unknown[];
		expect(written).toHaveLength(1);
		const empty = await run({ action: "export", path: "export-page.har", filter: "absent" });
		expect(empty.details.matchedFrames).toBe(0);
		expect(empty.details.artifactId).toBeUndefined();
		expect(empty.text).toContain("nothing was written");
	});

	it("returns artifact_unavailable when the session has no artifact storage", async () => {
		await writeFixture("export-no-artifact.har", HAR_CAPTURE);
		const session = createTestSession();
		session.allocateOutputArtifact = undefined;
		const { details } = await run({ action: "export", path: "export-no-artifact.har" }, session);
		expect(details.status).toBe("artifact_unavailable");
	});
});
