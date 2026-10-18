import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "@rva/coding-agent/config/settings";
import {
	createTools,
	type ToolSession,
	WindowsObserveTool,
	type WindowsObserveDetails,
	type WindowsObserveParams,
} from "@rva/coding-agent/tools";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { BUILTIN_TOOL_NAMES, normalizeToolName } from "@rva/coding-agent/tools/builtin-names";
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

async function writeFixture(name: string, content: string | unknown): Promise<string> {
	const filePath = path.join(root, name);
	await fs.writeFile(filePath, typeof content === "string" ? content : JSON.stringify(content, null, 2));
	return name;
}

async function run(
	params: WindowsObserveParams,
	session: ToolSession = createTestSession(),
): Promise<{ details: WindowsObserveDetails; text: string }> {
	const tool = new WindowsObserveTool(session);
	const result = await tool.execute("call", params);
	return { details: result.details!, text: textOf(result) };
}

const SAMPLE_JSON_EVENTS = JSON.stringify({
	events: [
		{
			timestamp: "2024-03-10T14:20:00.000Z",
			pid: 1000,
			tid: 2000,
			processName: "target.exe",
			module: "kernel32.dll",
			api: "CreateFileW",
			direction: "call",
			category: "file",
			parameters: {
				lpFileName: "C:\\Windows\\System32\\config\\SAM",
				dwDesiredAccess: "GENERIC_READ",
				password: "SUPER_SECRET_PASSWORD_123",
			},
			result: "0x00000080",
			duration: "0.15ms",
		},
		{
			timestamp: "2024-03-10T14:20:01.000Z",
			pid: 1000,
			tid: 2000,
			processName: "target.exe",
			module: "advapi32.dll",
			api: "RegOpenKeyExW",
			direction: "call",
			category: "registry",
			parameters: {
				hKey: "HKEY_LOCAL_MACHINE",
				lpSubKey: "Software\\MyApp",
				token: "SECRET_TOKEN_XYZ",
			},
			result: 0,
			duration: "0.05ms",
		},
		{
			timestamp: "2024-03-10T14:20:02.000Z",
			pid: 1000,
			tid: 2001,
			processName: "target.exe",
			module: "ws2_32.dll",
			api: "send",
			direction: "return",
			category: "network",
			parameters: {
				s: 144,
				authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M",
				len: 128,
			},
			result: 128,
			duration: "1.20ms",
		},
		{
			timestamp: "2024-03-10T14:20:03.000Z",
			pid: 2000,
			tid: 3000,
			processName: "helper.exe",
			module: "kernel32.dll",
			api: "VirtualAlloc",
			direction: "call",
			category: "memory",
			parameters: {
				lpAddress: 0,
				dwSize: 4096,
				flAllocationType: "MEM_COMMIT",
			},
			result: "0x00400000",
			duration: "0.02ms",
		},
	],
});

beforeAll(async () => {
	root = await fs.mkdtemp(path.join(os.tmpdir(), "rev-windows-observe-"));
});

afterAll(async () => {
	await removeWithRetries(root);
});

describe("windows_observe registration and metadata", () => {
	it("registers in BUILTIN_TOOL_NAMES and normalizes tool name", () => {
		expect(BUILTIN_TOOL_NAMES).toContain("windows_observe");
		expect(normalizeToolName("windows_observe")).toBe("windows_observe");
		expect(normalizeToolName("WINDOWS_OBSERVE")).toBe("windows_observe");
	});

	it("instantiates via createTools with read tier approval", async () => {
		const tools = await createTools(createTestSession(), ["windows_observe"]);
		const tool = tools.find(entry => entry.name === "windows_observe");
		expect(tool).toBeDefined();
		expect(tool?.approval).toBe("read");
		expect(tool?.strict).toBe(true);
		expect(tool?.loadMode).toBe("discoverable");
		expect(tool?.description).toContain("never injects");
	});
});

describe("windows_observe JSON & NDJSON parsing", () => {
	it("inspects structured JSON capture and summarizes processes, modules, categories, APIs", async () => {
		await writeFixture("trace.json", SAMPLE_JSON_EVENTS);
		const { details, text } = await run({ action: "inspect", path: "trace.json" });

		expect(details.status).toBe("ok");
		expect(details.format).toBe("json");
		expect(details.totalEvents).toBe(4);
		expect(details.processes).toHaveLength(2);
		expect(details.processes?.[0]?.pid).toBe(1000);
		expect(details.processes?.[0]?.events).toBe(3);
		expect(details.processes?.[1]?.pid).toBe(2000);
		expect(details.processes?.[1]?.events).toBe(1);

		expect(details.categories?.file).toBe(1);
		expect(details.categories?.registry).toBe(1);
		expect(details.categories?.network).toBe(1);
		expect(details.categories?.memory).toBe(1);

		expect(details.redactions).toBeGreaterThan(0);
		expect(text).toContain("windows_observe inspect: trace.json");
		expect(text).toContain("Events: 4");
		expect(text).toContain("PID 1000 (target.exe): 3 events");
		expect(text).toContain("PID 2000 (helper.exe): 1 events");
		expect(text).not.toContain("SUPER_SECRET_PASSWORD");
	});

	it("parses NDJSON capture stream", async () => {
		const ndjsonContent = [
			JSON.stringify({
				timestamp: "2024-03-10T10:00:00.000Z",
				pid: 111,
				module: "kernel32.dll",
				api: "ReadFile",
				category: "file",
				parameters: { hFile: 4, nNumberOfBytesToRead: 512 },
				result: 1,
			}),
			JSON.stringify({
				timestamp: "2024-03-10T10:00:01.000Z",
				pid: 111,
				module: "kernel32.dll",
				api: "WriteFile",
				category: "file",
				parameters: { hFile: 4, password: "SecretWritePassword" },
				result: 1,
			}),
		].join("\n");

		await writeFixture("stream.ndjson", ndjsonContent);
		const { details, text } = await run({ action: "inspect", path: "stream.ndjson" });
		expect(details.status).toBe("ok");
		expect(details.format).toBe("ndjson");
		expect(details.totalEvents).toBe(2);
		expect(text).toContain("Events: 2");
		expect(text).not.toContain("SecretWritePassword");
	});

	it("parses API Monitor JSON shape with Calls array", async () => {
		const apiMonitorContent = JSON.stringify({
			Calls: [
				{
					Time: "2024-03-10T12:00:00.000Z",
					PID: 500,
					TID: 600,
					Module: "ntdll.dll",
					API: "NtOpenFile",
					Parameters: { DesiredAccess: "0x100000" },
					ReturnValue: "0x00000000",
				},
			],
		});

		await writeFixture("apimonitor.json", apiMonitorContent);
		const { details } = await run({ action: "inspect", path: "apimonitor.json" });
		expect(details.status).toBe("ok");
		expect(details.format).toBe("api_monitor");
		expect(details.totalEvents).toBe(1);
	});

	it("parses ETW JSON shape with System and EventData", async () => {
		const etwContent = JSON.stringify({
			Events: [
				{
					Event: {
						System: {
							Provider: { Name: "Microsoft-Windows-Kernel-Process" },
							EventID: 1,
							ProcessID: 1234,
							ThreadID: 5678,
							TimeCreated: { SystemTime: "2024-03-10T15:00:00.000Z" },
						},
						EventData: {
							ProcessName: "notepad.exe",
							CommandLine: "notepad.exe",
							secret: "token123",
						},
					},
				},
			],
		});

		await writeFixture("etw.json", etwContent);
		const { details } = await run({ action: "inspect", path: "etw.json" });
		expect(details.status).toBe("ok");
		expect(details.format).toBe("etw");
		expect(details.totalEvents).toBe(1);
		expect(details.processes?.[0]?.pid).toBe(1234);
	});
});

describe("windows_observe list and filtering", () => {
	it("filters by PID and category", async () => {
		await writeFixture("filter-test.json", SAMPLE_JSON_EVENTS);
		const pidFilter = await run({ action: "list", path: "filter-test.json", pid: 2000 });
		expect(pidFilter.details.matchedEvents).toBe(1);
		expect(pidFilter.details.events?.[0]?.api).toBe("VirtualAlloc");
		expect(pidFilter.text).toContain("VirtualAlloc");

		const catFilter = await run({ action: "list", path: "filter-test.json", category: "registry" });
		expect(catFilter.details.matchedEvents).toBe(1);
		expect(catFilter.details.events?.[0]?.api).toBe("RegOpenKeyExW");
	});

	it("filters by module and api name substring", async () => {
		await writeFixture("filter-names.json", SAMPLE_JSON_EVENTS);
		const moduleFilter = await run({ action: "list", path: "filter-names.json", module: "ws2_32" });
		expect(moduleFilter.details.matchedEvents).toBe(1);
		expect(moduleFilter.details.events?.[0]?.module).toBe("ws2_32.dll");

		const apiFilter = await run({ action: "list", path: "filter-names.json", api: "CreateFile" });
		expect(apiFilter.details.matchedEvents).toBe(1);
		expect(apiFilter.details.events?.[0]?.api).toBe("CreateFileW");
	});

	it("filters by call direction", async () => {
		await writeFixture("filter-dir.json", SAMPLE_JSON_EVENTS);
		const calls = await run({ action: "list", path: "filter-dir.json", direction: "call" });
		expect(calls.details.matchedEvents).toBe(3);

		const returns = await run({ action: "list", path: "filter-dir.json", direction: "return" });
		expect(returns.details.matchedEvents).toBe(1);
		expect(returns.details.events?.[0]?.api).toBe("send");
	});

	it("filters by time range (start_time and end_time)", async () => {
		await writeFixture("filter-time.json", SAMPLE_JSON_EVENTS);
		const timeFilter = await run({
			action: "list",
			path: "filter-time.json",
			start_time: "2024-03-10T14:20:01.000Z",
			end_time: "2024-03-10T14:20:02.000Z",
		});
		expect(timeFilter.details.matchedEvents).toBe(2);
		expect(timeFilter.details.events?.map(e => e.api)).toEqual(["RegOpenKeyExW", "send"]);
	});

	it("pages events with offset and limit, reporting nextOffset", async () => {
		await writeFixture("paging.json", SAMPLE_JSON_EVENTS);
		const page1 = await run({ action: "list", path: "paging.json", offset: 0, limit: 2 });
		expect(page1.details.events).toHaveLength(2);
		expect(page1.details.hasMore).toBe(true);
		expect(page1.details.nextOffset).toBe(2);
		expect(page1.text).toContain("next offset 2");

		const page2 = await run({ action: "list", path: "paging.json", offset: 2, limit: 2 });
		expect(page2.details.events).toHaveLength(2);
		expect(page2.details.hasMore).toBe(false);
		expect(page2.details.nextOffset).toBeUndefined();
	});
});

describe("windows_observe search action", () => {
	it("searches with substring filter over API, parameters, and result", async () => {
		await writeFixture("search.json", SAMPLE_JSON_EVENTS);
		const found = await run({ action: "search", path: "search.json", filter: "RegOpenKey" });
		expect(found.details.matchedEvents).toBe(1);
		expect(found.details.events?.[0]?.api).toBe("RegOpenKeyExW");

		const paramMatch = await run({ action: "search", path: "search.json", filter: "SAM" });
		expect(paramMatch.details.matchedEvents).toBe(1);
		expect(paramMatch.details.events?.[0]?.api).toBe("CreateFileW");
	});

	it("searches with regular expression", async () => {
		await writeFixture("search-regex.json", SAMPLE_JSON_EVENTS);
		const regexMatch = await run({
			action: "search",
			path: "search-regex.json",
			filter: "Virtual(Alloc|Protect)",
			regex: true,
		});
		expect(regexMatch.details.matchedEvents).toBe(1);
		expect(regexMatch.details.events?.[0]?.api).toBe("VirtualAlloc");
	});

	it("rejects search without filter and rejects invalid regex", async () => {
		await writeFixture("search-err.json", SAMPLE_JSON_EVENTS);
		await expect(run({ action: "search", path: "search-err.json" })).rejects.toBeInstanceOf(ToolError);
		await expect(
			run({ action: "search", path: "search-err.json", filter: "(invalid", regex: true }),
		).rejects.toBeInstanceOf(ToolError);
	});
});

describe("windows_observe credential redaction", () => {
	it("redacts sensitive keys, passwords, tokens, and Bearer headers", async () => {
		await writeFixture("redact.json", SAMPLE_JSON_EVENTS);
		const { details, text } = await run({ action: "list", path: "redact.json" });

		// Check event 0 (password)
		const ev0 = details.events?.[0];
		expect(ev0?.redacted).toBe(true);
		expect(ev0?.paramSummary).toContain("[redacted]");
		expect(ev0?.paramSummary).not.toContain("SUPER_SECRET_PASSWORD_123");

		// Check event 1 (token)
		const ev1 = details.events?.[1];
		expect(ev1?.redacted).toBe(true);
		expect(ev1?.paramSummary).toContain("[redacted]");
		expect(ev1?.paramSummary).not.toContain("SECRET_TOKEN_XYZ");

		// Check event 2 (Bearer / JWT)
		const ev2 = details.events?.[2];
		expect(ev2?.redacted).toBe(true);
		expect(ev2?.paramSummary).toContain("[redacted]");
		expect(ev2?.paramSummary).not.toContain("eyJhbGciOiJIUzI1NiIs");

		// Rendered text must not leak any secret
		expect(text).not.toContain("SUPER_SECRET_PASSWORD_123");
		expect(text).not.toContain("SECRET_TOKEN_XYZ");
		expect(text).not.toContain("eyJhbGciOiJIUzI1NiIs");
	});
});

describe("windows_observe error handling and path security", () => {
	it("returns not_found status when capture file is missing", async () => {
		const { details, text } = await run({ action: "inspect", path: "missing.json" });
		expect(details.status).toBe("not_found");
		expect(text).toContain("capture file not found: missing.json");
	});

	it("returns empty status when file is 0 bytes", async () => {
		await writeFixture("empty.json", "");
		const { details, text } = await run({ action: "inspect", path: "empty.json" });
		expect(details.status).toBe("empty");
		expect(text).toContain("is empty");
	});

	it("returns invalid_format on corrupted JSON", async () => {
		await writeFixture("corrupt.json", "{ not valid json");
		const { details, text } = await run({ action: "inspect", path: "corrupt.json" });
		expect(details.status).toBe("invalid_format");
		expect(text).toContain("cannot analyze corrupt.json");
	});

	it("strictly forbids URL paths, remote network shares, commands, and remote paths", async () => {
		await expect(run({ action: "inspect", path: "http://example.com/trace.json" })).rejects.toBeInstanceOf(ToolError);
		await expect(run({ action: "inspect", path: "wss://example.com/ws" })).rejects.toBeInstanceOf(ToolError);
		await expect(run({ action: "inspect", path: "ssh:host/path" })).rejects.toBeInstanceOf(ToolError);
		await expect(run({ action: "inspect", path: "\\\\server\\share\\trace.json" })).rejects.toBeInstanceOf(ToolError);
		await expect(run({ action: "inspect", path: "//server/share/trace.json" })).rejects.toBeInstanceOf(ToolError);
		await expect(run({ action: "inspect", path: "user@host:/var/log/trace.json" })).rejects.toBeInstanceOf(ToolError);
		await expect(run({ action: "inspect", path: "powershell Get-WinEvent" })).rejects.toBeInstanceOf(ToolError);
		await expect(run({ action: "inspect", path: "cmd.exe /c type trace.json" })).rejects.toBeInstanceOf(ToolError);
		await expect(run({ action: "inspect", path: "| logman query" })).rejects.toBeInstanceOf(ToolError);
		await expect(run({ action: "inspect", path: "trace.json; rm -rf /" })).rejects.toBeInstanceOf(ToolError);
	});

	it("validates regex syntax and time range parameters", async () => {
		await writeFixture("test-time.json", SAMPLE_JSON_EVENTS);
		await expect(
			run({ action: "search", path: "test-time.json", filter: "[invalid(regex", regex: true }),
		).rejects.toThrow("invalid filter regular expression");
		await expect(run({ action: "list", path: "test-time.json", start_time: "not-a-valid-time" })).rejects.toThrow(
			"invalid start_time",
		);
		await expect(run({ action: "list", path: "test-time.json", end_time: "not-a-valid-time" })).rejects.toThrow(
			"invalid end_time",
		);
		await expect(
			run({
				action: "list",
				path: "test-time.json",
				start_time: "2024-03-10T15:00:00Z",
				end_time: "2024-03-10T14:00:00Z",
			}),
		).rejects.toThrow("start_time must be earlier than or equal to end_time");
	});

	it("parses Windows FILETIME timestamps", async () => {
		const fileTimeEvent = [
			{
				API: "CreateFileW",
				Module: "kernel32.dll",
				Time: 133545000000000000,
			},
		];
		await writeFixture("filetime.json", fileTimeEvent);
		const result = await run({ action: "list", path: "filetime.json" });
		expect(result.details.status).toBe("ok");
		expect(result.details.events?.[0].epochMs).toBeDefined();
		expect(result.details.events?.[0].timestamp).toContain("2024-");
	});

	it("rejects inspect action with filtering parameters", async () => {
		await expect(run({ action: "inspect", path: "x.json", pid: 100 })).rejects.toBeInstanceOf(ToolError);
		await expect(run({ action: "inspect", path: "x.json", filter: "test" })).rejects.toBeInstanceOf(ToolError);
	});
});

describe("windows_observe export action and byte capping", () => {
	it("exports matching events to a JSON artifact with redactions preserved", async () => {
		await writeFixture("export.json", SAMPLE_JSON_EVENTS);
		const { details, text } = await run({
			action: "export",
			path: "export.json",
			export_format: "json",
		});

		expect(details.status).toBe("ok");
		expect(details.artifactId).toBeDefined();
		expect(details.artifactPath).toBeDefined();
		expect(details.exportFormat).toBe("json");

		const artifactContent = await fs.readFile(details.artifactPath!, "utf8");
		expect(artifactContent).not.toContain("SUPER_SECRET_PASSWORD_123");
		expect(artifactContent).toContain("[redacted]");
		const exportedArray = JSON.parse(artifactContent) as Array<{ api: string }>;
		expect(exportedArray).toHaveLength(4);
		expect(text).toContain("Saved artifact: artifact://");
	});

	it("exports to an NDJSON artifact", async () => {
		await writeFixture("export-nd.json", SAMPLE_JSON_EVENTS);
		const { details } = await run({
			action: "export",
			path: "export-nd.json",
			export_format: "ndjson",
		});

		expect(details.status).toBe("ok");
		expect(details.exportFormat).toBe("ndjson");

		const artifactContent = await fs.readFile(details.artifactPath!, "utf8");
		const lines = artifactContent.trim().split("\n");
		expect(lines).toHaveLength(4);
		const first = JSON.parse(lines[0]!) as { api: string };
		expect(first.api).toBe("CreateFileW");
	});

	it("honors export byte cap and reports omitted events", async () => {
		await writeFixture("export-cap.json", SAMPLE_JSON_EVENTS);
		const { details } = await run({
			action: "export",
			path: "export-cap.json",
			export_format: "json",
			max_bytes: 1024,
		});

		expect(details.status).toBe("ok");
		expect(details.truncated).toBe(true);
		expect(details.omitted).toBeGreaterThan(0);
	});

	it("returns artifact_unavailable when session has no artifact allocation", async () => {
		await writeFixture("export-no-alloc.json", SAMPLE_JSON_EVENTS);
		const session = createTestSession();
		session.allocateOutputArtifact = undefined;
		const { details } = await run({ action: "export", path: "export-no-alloc.json" }, session);
		expect(details.status).toBe("artifact_unavailable");
	});
});
