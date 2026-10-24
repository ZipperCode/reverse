import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { BUILTIN_TOOL_NAMES, normalizeToolName } from "@reverse/coding-agent/tools/builtin-names";
import {
	createTools,
	type ToolSession,
	FridaSessionTool,
	type FridaSessionDetails,
	type FridaSessionRecord,
	type DynamicSessionEvent,
	type FridaRunner,
	appendEventsToBuffer,
	parseFridaOutputIntoEvents,
	parseStructuredFridaMessage,
	parsePythonLiteral,
	sanitizeRecordSecrets,
	isProcessAlive,
	encodeProjectKey,
	buildEvidenceReference,
} from "@reverse/coding-agent/tools";
import { Settings } from "@reverse/coding-agent/config/settings";

function createTestSession(
	cwd: string,
	options: {
		allocateArtifact?: boolean;
	} = {},
): ToolSession {
	let artifactCounter = 0;
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
		...(options.allocateArtifact
			? {
					allocateOutputArtifact: async (prefix: string) => {
						artifactCounter++;
						const id = `${prefix}_test_artifact_${artifactCounter}`;
						const artifactPath = path.join(cwd, `${id}.json`);
						return { id, path: artifactPath };
					},
				}
			: {}),
	};
}

async function removeTestDir(dirPath: string): Promise<void> {
	await fs.rm(dirPath, { recursive: true, force: true }).catch(() => {});
}

function textOf(result: { content: Array<{ type: string; text?: string }> }): string {
	return result.content
		.filter((c): c is { type: string; text: string } => c.type === "text" && typeof c.text === "string")
		.map(c => c.text)
		.join("\n");
}

describe("frida_session registration and normalization", () => {
	it("is registered as a builtin discoverable tool with aliases", async () => {
		expect(BUILTIN_TOOL_NAMES).toContain("frida_session");
		expect(normalizeToolName("frida_session")).toBe("frida_session");
		expect(normalizeToolName("FRIDA_SESSION")).toBe("frida_session");
		expect(normalizeToolName("frida-session")).toBe("frida_session");
		expect(normalizeToolName("FRIDA-SESSION")).toBe("frida_session");
		expect(normalizeToolName("frida_sessions")).toBe("frida_session");

		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-reg-"));
		try {
			const tools = await createTools(createTestSession(tempDir), ["frida_session"]);
			const tool = tools.find(c => c.name === "frida_session");
			expect(tool).toBeDefined();
			expect(tool?.strict).toBe(true);
			expect(tool?.loadMode).toBe("discoverable");
		} finally {
			await removeTestDir(tempDir);
		}
	});

	it("resolves alias frida-session through createTools", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-alias-"));
		try {
			const tools = await createTools(createTestSession(tempDir), ["frida-session"]);
			const tool = tools.find(c => c.name === "frida_session");
			expect(tool).toBeDefined();
			expect(tool?.name).toBe("frida_session");
		} finally {
			await removeTestDir(tempDir);
		}
	});

	it("resolves alias reverse_dynamic_session through createTools", async () => {
		expect(normalizeToolName("reverse_dynamic_session")).toBe("frida_session");
		expect(normalizeToolName("REVERSE_DYNAMIC_SESSION")).toBe("frida_session");
		expect(normalizeToolName("reverse-dynamic-session")).toBe("frida_session");
		expect(normalizeToolName("dynamic_session")).toBe("frida_session");

		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-dyn-alias-"));
		try {
			const tools = await createTools(createTestSession(tempDir), ["reverse_dynamic_session"]);
			const tool = tools.find(c => c.name === "frida_session");
			expect(tool).toBeDefined();
			expect(tool?.name).toBe("frida_session");
		} finally {
			await removeTestDir(tempDir);
		}
	});
});

describe("frida_session parameter validation", () => {
	it("rejects create action without target", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-val-1-"));
		try {
			const tool = new FridaSessionTool(createTestSession(tempDir));
			await expect(tool.execute("c1", { action: "create" })).rejects.toThrow(
				"Must specify target: 'pid', 'process', or 'spawn'",
			);
		} finally {
			await removeTestDir(tempDir);
		}
	});

	it("rejects create action with mutually exclusive targets", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-val-2-"));
		try {
			const tool = new FridaSessionTool(createTestSession(tempDir));
			await expect(
				tool.execute("c2", {
					action: "create",
					pid: 1234,
					process: "com.example.app",
				}),
			).rejects.toThrow("cannot provide more than one of 'pid', 'process', or 'spawn'");
		} finally {
			await removeTestDir(tempDir);
		}
	});

	it("rejects create action with mutually exclusive transport options", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-val-3-"));
		try {
			const tool = new FridaSessionTool(createTestSession(tempDir));
			await expect(
				tool.execute("c3", {
					action: "create",
					process: "com.example.app",
					usb: true,
					host: "127.0.0.1:27042",
				}),
			).rejects.toThrow("cannot combine 'usb', 'device', or 'host'");
		} finally {
			await removeTestDir(tempDir);
		}
	});

	it("rejects run action without script, script_path, or command", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-val-4-"));
		const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-state-"));
		try {
			const tool = new FridaSessionTool(createTestSession(tempDir), {
				stateRoot: stateDir,
				which: () => "/usr/local/bin/frida",
			});
			await expect(
				tool.execute("c4", {
					action: "run",
					session_id: "missing-sess",
				}),
			).rejects.toThrow("Frida session 'missing-sess' not found");
		} finally {
			await removeTestDir(tempDir);
			await removeTestDir(stateDir);
		}
	});
});

describe("frida_session lifecycle and persistence", () => {
	it("executes full lifecycle: create -> list -> status -> run -> stop -> destroy", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-ws-"));
		const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-state-"));
		try {
			const calls: Array<{ binary: string; args: string[] }> = [];
			const runner: FridaRunner = async (binary, args) => {
				calls.push({ binary, args });
				return {
					stdout: Buffer.from("console: Hook attached successfully\n"),
					stderr: "",
					exitCode: 0,
					outputBytes: 36,
					truncated: false,
					timedOut: false,
				};
			};

			const which = (cmd: string) => (cmd === "frida" ? "/usr/local/bin/frida" : null);
			const sessionContext = createTestSession(tempDir, { allocateArtifact: true });
			const tool = new FridaSessionTool(sessionContext, {
				runner,
				which,
				stateRoot: stateDir,
			});

			// 1. Create
			const createResult = await tool.execute("call-create", {
				action: "create",
				session_id: "sess-lifecycle-1",
				process: "com.example.target",
				usb: true,
				name: "Lifecycle Test Session",
			});
			const createDetails = createResult.details as FridaSessionDetails;
			expect(createDetails.status).toBe("ok");
			expect(createDetails.sessionId).toBe("sess-lifecycle-1");
			expect(createDetails.session?.status).toBe("active");
			expect(createDetails.session?.target.process).toBe("com.example.target");
			expect(createDetails.session?.target.usb).toBe(true);
			expect(textOf(createResult)).toContain("Frida session 'sess-lifecycle-1' created");

			// Verify file was written to disk under stateRoot
			const projectKey = encodeProjectKey(tempDir);
			const sessionFilePath = path.join(stateDir, "frida-sessions", projectKey, "sess-lifecycle-1.json");
			const savedJson = JSON.parse(await fs.readFile(sessionFilePath, "utf8")) as FridaSessionRecord;
			expect(savedJson.id).toBe("sess-lifecycle-1");
			expect(savedJson.status).toBe("active");

			// 2. List
			const listResult = await tool.execute("call-list", { action: "list" });
			const listDetails = listResult.details as FridaSessionDetails;
			expect(listDetails.status).toBe("ok");
			expect(listDetails.sessions).toHaveLength(1);
			expect(listDetails.sessions?.[0].id).toBe("sess-lifecycle-1");
			expect(textOf(listResult)).toContain("sess-lifecycle-1");

			// 3. Status
			const statusResult = await tool.execute("call-status", {
				action: "status",
				session_id: "sess-lifecycle-1",
			});
			const statusDetails = statusResult.details as FridaSessionDetails;
			expect(statusDetails.status).toBe("ok");
			expect(statusDetails.session?.id).toBe("sess-lifecycle-1");
			expect(textOf(statusResult)).toContain("Frida session status: sess-lifecycle-1");
			expect(textOf(statusResult)).toContain("Target: process:com.example.target");

			// 4. Run modules command
			const runModulesResult = await tool.execute("call-run-mods", {
				action: "run",
				session_id: "sess-lifecycle-1",
				command: "modules",
			});
			expect(calls).toHaveLength(1);
			expect(calls[0].args).toContain("-U");
			expect(calls[0].args).toContain("-n");
			expect(calls[0].args).toContain("com.example.target");
			expect(calls[0].args).toContain("-q");

			const runModulesDetails = runModulesResult.details as FridaSessionDetails;
			expect(runModulesDetails.status).toBe("ok");
			expect(runModulesDetails.session?.runsCount).toBe(1);

			// 5. Run inline script with parameters and artifact
			const runScriptResult = await tool.execute("call-run-script", {
				action: "run",
				session_id: "sess-lifecycle-1",
				script: "Java.perform(function() { console.log('Ping'); });",
				script_args: { verbose: true },
				to_artifact: true,
			});
			expect(calls).toHaveLength(2);
			expect(calls[1].args).toContain("-P");
			expect(calls[1].args).toContain('{"verbose":true}');

			const runScriptDetails = runScriptResult.details as FridaSessionDetails;
			expect(runScriptDetails.status).toBe("ok");
			expect(runScriptDetails.session?.runsCount).toBe(2);
			expect(runScriptDetails.artifactId).toBeDefined();
			expect(runScriptDetails.artifactPath).toBeDefined();

			// Verify artifact file exists on disk
			const artifactPath = runScriptDetails.artifactPath;
			const artifactExists = artifactPath
				? await fs.stat(artifactPath).then(
						() => true,
						() => false,
					)
				: false;
			expect(artifactExists).toBe(true);

			// 6. Stop
			const stopResult = await tool.execute("call-stop", {
				action: "stop",
				session_id: "sess-lifecycle-1",
			});
			const stopDetails = stopResult.details as FridaSessionDetails;
			expect(stopDetails.status).toBe("ok");
			expect(textOf(stopResult)).toContain("Frida session 'sess-lifecycle-1' stopped");

			// Verify status on disk is now stopped
			const stoppedRecord = JSON.parse(await fs.readFile(sessionFilePath, "utf8")) as FridaSessionRecord;
			expect(stoppedRecord.status).toBe("stopped");

			// 7. Destroy
			const destroyResult = await tool.execute("call-destroy", {
				action: "destroy",
				session_id: "sess-lifecycle-1",
			});
			const destroyDetails = destroyResult.details as FridaSessionDetails;
			expect(destroyDetails.status).toBe("ok");
			expect(textOf(destroyResult)).toContain("destroyed and removed");

			// Verify file was deleted from disk
			const fileStillExists = await fs.stat(sessionFilePath).then(
				() => true,
				() => false,
			);
			expect(fileStillExists).toBe(false);

			// 8. List should now be empty
			const emptyListResult = await tool.execute("call-empty-list", { action: "list" });
			expect((emptyListResult.details as FridaSessionDetails).sessions).toHaveLength(0);
		} finally {
			await removeTestDir(tempDir);
			await removeTestDir(stateDir);
		}
	});

	it("defaults session_id to existing session when only one active session exists", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-auto-"));
		const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-state-"));
		try {
			const runner: FridaRunner = async () => ({
				stdout: Buffer.from("Executed"),
				stderr: "",
				exitCode: 0,
				outputBytes: 8,
				truncated: false,
				timedOut: false,
			});

			const which = (cmd: string) => (cmd === "frida" ? "/usr/local/bin/frida" : null);
			const tool = new FridaSessionTool(createTestSession(tempDir), {
				runner,
				which,
				stateRoot: stateDir,
			});

			// Create session without explicit ID
			const createResult = await tool.execute("call-auto-create", {
				action: "create",
				pid: 9999,
			});
			const createDetails = createResult.details as FridaSessionDetails;
			const autoSessionId = createDetails.sessionId;
			expect(autoSessionId).toBeDefined();

			// Run without session_id — should automatically pick the single active session
			const runResult = await tool.execute("call-auto-run", {
				action: "run",
				script: "console.log(1)",
			});
			const runDetails = runResult.details as FridaSessionDetails;
			expect(runDetails.sessionId).toBe(autoSessionId);
			expect(runDetails.status).toBe("ok");
		} finally {
			await removeTestDir(tempDir);
			await removeTestDir(stateDir);
		}
	});
});

describe("frida_session missing dependency handling", () => {
	it("returns structured missing_dependency status on create when frida is absent", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-miss-1-"));
		const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-state-"));
		try {
			const which = () => null; // Frida missing
			const tool = new FridaSessionTool(createTestSession(tempDir), {
				which,
				stateRoot: stateDir,
			});

			const result = await tool.execute("call-miss-create", {
				action: "create",
				process: "com.example.app",
			});

			const details = result.details as FridaSessionDetails;
			expect(details.status).toBe("missing_dependency");
			expect(details.dependency?.available).toBe(false);
			expect(details.fallback).toBeDefined();
			expect(textOf(result)).toContain("Frida tools are not available on this machine");
		} finally {
			await removeTestDir(tempDir);
			await removeTestDir(stateDir);
		}
	});

	it("returns structured missing_dependency status on run when frida is absent", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-miss-2-"));
		const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-state-"));
		try {
			// First create with available frida
			const toolWithFrida = new FridaSessionTool(createTestSession(tempDir), {
				which: () => "/usr/local/bin/frida",
				runner: async () => ({
					stdout: Buffer.from("ok"),
					stderr: "",
					exitCode: 0,
					outputBytes: 2,
					truncated: false,
					timedOut: false,
				}),
				stateRoot: stateDir,
			});

			await toolWithFrida.execute("c1", {
				action: "create",
				session_id: "persisted-sess",
				pid: 1234,
			});

			// Now attempt to run with missing frida
			const toolWithoutFrida = new FridaSessionTool(createTestSession(tempDir), {
				which: () => null,
				stateRoot: stateDir,
			});

			const runResult = await toolWithoutFrida.execute("c2", {
				action: "run",
				session_id: "persisted-sess",
				script: "console.log(1)",
			});

			const details = runResult.details as FridaSessionDetails;
			expect(details.status).toBe("missing_dependency");
			expect(details.dependency?.available).toBe(false);
			expect(textOf(runResult)).toContain("Frida tools are not available");
		} finally {
			await removeTestDir(tempDir);
			await removeTestDir(stateDir);
		}
	});
});

describe("frida_session secret redaction and privacy", () => {
	it("redacts sensitive tokens and passwords before persisting session metadata", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-sec-"));
		const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-state-"));
		try {
			const secretScript = "const token = 'bearer secret_token_value_abc123'; const pass = 'password123';";
			const runner: FridaRunner = async () => ({
				stdout: Buffer.from("Script executed"),
				stderr: "",
				exitCode: 0,
				outputBytes: 15,
				truncated: false,
				timedOut: false,
			});

			const tool = new FridaSessionTool(createTestSession(tempDir), {
				which: () => "/usr/local/bin/frida",
				runner,
				stateRoot: stateDir,
			});

			await tool.execute("create-sec", {
				action: "create",
				session_id: "secret-session",
				pid: 5678,
				script: secretScript,
			});

			const projectKey = encodeProjectKey(tempDir);
			const sessionFilePath = path.join(stateDir, "frida-sessions", projectKey, "secret-session.json");
			const fileContent = await fs.readFile(sessionFilePath, "utf8");

			// Verify secrets are redacted in persisted JSON
			expect(fileContent).not.toContain("secret_token_value_abc123");
			expect(fileContent).toContain("[REDACTED]");
		} finally {
			await removeTestDir(tempDir);
			await removeTestDir(stateDir);
		}
	});

	it("sanitizeRecordSecrets helper scrubs history and metadata", () => {
		const rawRecord: FridaSessionRecord = {
			id: "test",
			target: { type: "pid", value: 123 },
			status: "active",
			createdAt: "2026-01-01T00:00:00Z",
			updatedAt: "2026-01-01T00:00:00Z",
			runsCount: 1,
			lastScript: "const api_key = 'sk-live-1234567890abcdef';",
			history: [
				{
					id: "h1",
					timestamp: "2026-01-01T00:00:00Z",
					scriptSnippet:
						"bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M",
				},
			],
			metadata: {
				authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M",
			},
		};

		const sanitized = sanitizeRecordSecrets(rawRecord);
		expect(sanitized.lastScript).not.toContain("sk-live-1234567890abcdef");
		expect(sanitized.history[0].scriptSnippet).not.toContain("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
		expect(sanitized.metadata?.authHeader).not.toContain("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
	});
});

describe("frida_session process liveness helper", () => {
	it("detects current process as alive and non-existent pid as dead", () => {
		expect(isProcessAlive(process.pid)).toBe(true);
		expect(isProcessAlive(999999999)).toBe(false);
		expect(isProcessAlive(-1)).toBe(false);
		expect(isProcessAlive(0)).toBe(false);
	});
});

describe("frida_session dynamic event ring buffer and spawn idempotency", () => {
	it("bounds event ring buffer to capacity", () => {
		const initial: DynamicSessionEvent[] = [];
		for (let i = 1; i <= 10; i++) {
			initial.push({
				id: `ev_test_${i}`,
				seq: i,
				timestamp: new Date().toISOString(),
				sessionId: "test-sess",
				kind: "stdout",
				payload: `line ${i}`,
			});
		}

		const newEvents: DynamicSessionEvent[] = [];
		for (let i = 11; i <= 15; i++) {
			newEvents.push({
				id: `ev_test_${i}`,
				seq: i,
				timestamp: new Date().toISOString(),
				sessionId: "test-sess",
				kind: "message",
				payload: `new line ${i}`,
			});
		}

		const capped = appendEventsToBuffer(initial, newEvents, 8);
		expect(capped).toHaveLength(8);
		// Oldest events dropped, keeping latest 8 (8 through 15)
		expect(capped[0].seq).toBe(8);
		expect(capped[capped.length - 1].seq).toBe(15);
	});

	it("parses stdout, stderr, and send messages into structured events", () => {
		const stdout = [
			"__FRIDA_SPAWN_OK__:4321",
			'{"type":"send","payload":{"action":"decrypt","algo":"AES-GCM","bytes":128}}',
			"console: initialization complete",
			"/* 0x140001000 sub_140001000 */",
		].join("\n");
		const stderr = "[error] hook failure warning";

		const parsed = parseFridaOutputIntoEvents("sess-parse", stdout, stderr, 0, {
			command: "run_hook",
			exitCode: 0,
		});

		expect(parsed.spawnedPid).toBe(4321);
		const events = parsed.events;
		expect(events.length).toBeGreaterThanOrEqual(6);

		const startEv = events.find(e => e.channel === "run_start");
		expect(startEv).toBeDefined();
		expect(startEv?.kind).toBe("lifecycle");

		const spawnEv = events.find(e => e.channel === "spawn");
		expect(spawnEv).toBeDefined();
		const spawnPayload = spawnEv?.payload;
		if (spawnPayload && typeof spawnPayload === "object" && "pid" in spawnPayload) {
			expect(spawnPayload.pid).toBe(4321);
		} else {
			throw new Error("Expected spawnPayload to have pid");
		}

		const msgEv = events.find(e => e.channel === "send");
		expect(msgEv).toBeDefined();
		expect(msgEv?.kind).toBe("message");
		const msgPayload = msgEv?.payload;
		if (msgPayload && typeof msgPayload === "object" && "algo" in msgPayload) {
			expect(msgPayload.algo).toBe("AES-GCM");
		} else {
			throw new Error("Expected msgPayload to have algo");
		}

		const traceEv = events.find(e => e.channel === "trace");
		expect(traceEv).toBeDefined();
		expect(traceEv?.kind).toBe("trace");

		const errEv = events.find(e => e.channel === "error");
		expect(errEv).toBeDefined();
		expect(errEv?.kind).toBe("stderr");

		const finishEv = events.find(e => e.channel === "run_finish");
		expect(finishEv).toBeDefined();
		const finishPayload = finishEv?.payload;
		if (finishPayload && typeof finishPayload === "object" && "exitCode" in finishPayload) {
			expect(finishPayload.exitCode).toBe(0);
		} else {
			throw new Error("Expected finishPayload to have exitCode");
		}
	});

	it("attaches to spawned child PID without re-spawning a new process on subsequent runs", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-spawn-"));
		const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-spawn-state-"));
		try {
			const runnerCalls: Array<{ binary: string; args: string[] }> = [];
			const runner: FridaRunner = async (binary, args) => {
				runnerCalls.push({ binary, args });
				if (args.includes("-f")) {
					// Initial spawn probe response
					return {
						stdout: Buffer.from("__FRIDA_SPAWN_OK__:55555\nSpawned `com.example.app`. Resuming...\n"),
						stderr: "",
						exitCode: 0,
						outputBytes: 50,
						truncated: false,
						timedOut: false,
					};
				}
				// Subsequent run response
				return {
					stdout: Buffer.from("Hook executed successfully on PID 55555\n"),
					stderr: "",
					exitCode: 0,
					outputBytes: 40,
					truncated: false,
					timedOut: false,
				};
			};

			const which = (cmd: string) => (cmd === "frida" ? "/usr/local/bin/frida" : null);
			const tool = new FridaSessionTool(createTestSession(tempDir), {
				runner,
				which,
				stateRoot: stateDir,
			});

			// 1. Create session with spawn target
			const createRes = await tool.execute("c-spawn", {
				action: "create",
				session_id: "spawned-app-sess",
				spawn: "com.example.app",
			});
			const createDetails = createRes.details as FridaSessionDetails;
			expect(createDetails.status).toBe("ok");
			expect(createDetails.session?.activeChildPid).toBe(55555);
			expect(runnerCalls).toHaveLength(1);
			expect(runnerCalls[0].args).toContain("-f");
			expect(runnerCalls[0].args).toContain("com.example.app");

			// 2. Run script in session context — MUST attach via -p 55555, NOT -f com.example.app!
			const runRes = await tool.execute("r-hook", {
				action: "run",
				session_id: "spawned-app-sess",
				script: "console.log('intercepted');",
			});
			const runDetails = runRes.details as FridaSessionDetails;
			expect(runDetails.status).toBe("ok");
			expect(runnerCalls).toHaveLength(2);

			// Verify second call attached via -p 55555 and did NOT pass -f
			const secondCallArgs = runnerCalls[1].args;
			expect(secondCallArgs).toContain("-p");
			expect(secondCallArgs).toContain("55555");
			expect(secondCallArgs).not.toContain("-f");
			expect(secondCallArgs).not.toContain("com.example.app");
		} finally {
			await removeTestDir(tempDir);
			await removeTestDir(stateDir);
		}
	});

	it("records events and supports query, filter, evidence export, and clear via action: 'events'", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-events-"));
		const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-events-state-"));
		try {
			let runCount = 0;
			const runner: FridaRunner = async () => {
				runCount++;
				if (runCount === 1) {
					return {
						stdout: Buffer.from("console: Session initialized\n"),
						stderr: "",
						exitCode: 0,
						outputBytes: 30,
						truncated: false,
						timedOut: false,
					};
				}
				return {
					stdout: Buffer.from(
						[
							'{"type":"send","payload":{"event":"key_exchange","key":"secret_key_hex_value","cipher":"AES"}}',
							"console: Key intercepted at 0x7fff0010",
						].join("\n"),
					),
					stderr: "[warn] memory scan slow",
					exitCode: 0,
					outputBytes: 120,
					truncated: false,
					timedOut: false,
				};
			};

			const which = (cmd: string) => (cmd === "frida" ? "/usr/local/bin/frida" : null);
			const tool = new FridaSessionTool(createTestSession(tempDir), {
				runner,
				which,
				stateRoot: stateDir,
			});

			// Create session
			await tool.execute("c1", {
				action: "create",
				session_id: "events-sess-1",
				pid: 12345,
				script: "console.log('Session initialized')",
			});

			// Run script that triggers structured events
			const runRes = await tool.execute("r1", {
				action: "run",
				session_id: "events-sess-1",
				script: "Interceptor.attach(...)",
				export_evidence: true,
			});
			const runDetails = runRes.details as FridaSessionDetails;
			expect(runDetails.events).toBeDefined();
			expect(runDetails.evidence).toBeDefined();

			// Query all events
			const evAllRes = await tool.execute("ev-all", {
				action: "events",
				session_id: "events-sess-1",
			});
			const evAllDetails = evAllRes.details as FridaSessionDetails;
			expect(evAllDetails.eventsCount).toBeGreaterThanOrEqual(4);
			expect(textOf(evAllRes)).toContain("events: showing");

			// Filter by kind: "message"
			const evMsgRes = await tool.execute("ev-msg", {
				action: "events",
				session_id: "events-sess-1",
				kind: "message",
				export_evidence: true,
			});
			const evMsgDetails = evMsgRes.details as FridaSessionDetails;
			expect(evMsgDetails.events).toHaveLength(1);
			expect(evMsgDetails.events?.[0].kind).toBe("message");
			expect(evMsgDetails.evidence).toBeDefined();

			const rawEvidence = evMsgDetails.evidence;
			const evidence = Array.isArray(rawEvidence) ? rawEvidence[0] : rawEvidence;
			expect(evidence).toBeDefined();
			if (!evidence) throw new Error("Expected exported message evidence");
			expect(evidence?.sourceTool).toBe("frida_session");
			expect(evidence.locator).toStartWith("session:events-sess-1:seq:");
			expect(evidence.kind).toBe("fact");
			expect(evidence.target).toBe("12345");
			expect(evidence.content).toContain("key_exchange");

			// Clear events
			const clearRes = await tool.execute("ev-clear", {
				action: "events",
				session_id: "events-sess-1",
				clear: true,
			});
			expect(textOf(clearRes)).toContain("Cleared");

			// Verify empty after clear
			const evAfterClear = await tool.execute("ev-after", {
				action: "events",
				session_id: "events-sess-1",
			});
			expect((evAfterClear.details as FridaSessionDetails).events).toHaveLength(0);
		} finally {
			await removeTestDir(tempDir);
			await removeTestDir(stateDir);
		}
	});

	it("enforces approval tiers for events action", () => {
		const tool = new FridaSessionTool(createTestSession(process.cwd()));
		expect(tool.approval({ action: "events" })).toBe("read");
		expect(tool.approval({ action: "events", clear: true })).toBe("write");
		expect(tool.approval({ action: "run" })).toBe("exec");
		expect(tool.approval({ action: "create" })).toBe("exec");
		expect(tool.approval({ action: "list" })).toBe("read");
		expect(tool.approval({ action: "status" })).toBe("read");
	});

	it("respects AbortSignal passed as third execute argument", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-abort-"));
		try {
			const tool = new FridaSessionTool(createTestSession(tempDir), {
				which: () => "/usr/local/bin/frida",
			});
			const controller = new AbortController();
			controller.abort();
			await expect(tool.execute("call-abort", { action: "create", pid: 1234 }, controller.signal)).rejects.toThrow();
		} finally {
			await removeTestDir(tempDir);
		}
	});
});
describe("frida_session regression: structured send/console/ws/crypto events, query, and classification", () => {
	it("predictably classifies and queries structured send, console, ws, crypto, and error events", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-regress-events-"));
		const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-regress-state-"));
		try {
			const runner: FridaRunner = async () => ({
				stdout: Buffer.from(
					[
						'[*] {"type":"send","payload":{"type":"crypto","algorithm":"AES-GCM-256","key":"00112233445566778899aabbccddeeff"}}',
						'{"type":"send","payload":{"type":"ws","url":"wss://api.test/socket","data":"hello"}}',
						'Message: {"type":"send","payload":{"event":"key_exchange","cipher":"ChaCha20"}}',
						'{"type":"log","payload":"Module initialized: libnative-sec.so"}',
						"console.log: Decrypted packet size 512 bytes",
						"[console] Memory scan at 0x7fff1000",
						'{"type":"error","description":"Memory access violation at 0x0"}',
					].join("\n"),
				),
				stderr: "[stderr] debugger attached",
				exitCode: 0,
				outputBytes: 300,
				truncated: false,
				timedOut: false,
			});

			const which = (cmd: string) => (cmd === "frida" ? "/usr/local/bin/frida" : null);
			const tool = new FridaSessionTool(createTestSession(tempDir), {
				runner,
				which,
				stateRoot: stateDir,
			});

			// 1. Create session with pid
			await tool.execute("c1", {
				action: "create",
				session_id: "frida-structured-sess",
				pid: 9999,
			});

			// 2. Run script emitting multi-channel events
			const runRes = await tool.execute("r1", {
				action: "run",
				session_id: "frida-structured-sess",
				script: "Interceptor.attach(...)",
				export_evidence: true,
			});
			const runDetails = runRes.details as FridaSessionDetails;
			expect(runDetails.events).toBeDefined();

			// 3. Query 'crypto' events by kind: "crypto"
			const cryptoByKind = await tool.execute("q_cr_kind", {
				action: "events",
				session_id: "frida-structured-sess",
				kind: "crypto",
			});
			const crKindDetails = cryptoByKind.details as FridaSessionDetails;
			expect(crKindDetails.events?.length).toBeGreaterThanOrEqual(2);
			const crKindRaw = crKindDetails.events?.map(e => JSON.stringify(e.payload)).join(" ");
			expect(crKindRaw).toContain("AES-GCM-256");
			expect(crKindRaw).toContain("ChaCha20");

			// 4. Query 'crypto' events by channel: "crypto"
			const cryptoByChannel = await tool.execute("q_cr_ch", {
				action: "events",
				session_id: "frida-structured-sess",
				channel: "crypto",
			});
			const crChDetails = cryptoByChannel.details as FridaSessionDetails;
			expect(crChDetails.events?.length).toBeGreaterThanOrEqual(2);

			// 5. Query 'ws' events by kind: "ws"
			const wsByKind = await tool.execute("q_ws_kind", {
				action: "events",
				session_id: "frida-structured-sess",
				kind: "ws",
			});
			const wsKindDetails = wsByKind.details as FridaSessionDetails;
			expect(wsKindDetails.events).toHaveLength(1);
			expect(JSON.stringify(wsKindDetails.events?.[0].payload)).toContain("wss://api.test/socket");

			// 6. Query 'console' events by kind: "console"
			const consoleByKind = await tool.execute("q_cons_kind", {
				action: "events",
				session_id: "frida-structured-sess",
				kind: "console",
			});
			const consKindDetails = consoleByKind.details as FridaSessionDetails;
			expect(consKindDetails.events?.length).toBeGreaterThanOrEqual(3);
			const consRaw = consKindDetails.events?.map(e => String(e.payload)).join(" ");
			expect(consRaw).toContain("libnative-sec.so");
			expect(consRaw).toContain("Decrypted packet size 512 bytes");
			expect(consRaw).toContain("Memory scan at 0x7fff1000");

			// 7. Query 'send' events by kind: "send"
			const sendByKind = await tool.execute("q_send_kind", {
				action: "events",
				session_id: "frida-structured-sess",
				kind: "send",
			});
			const sendKindDetails = sendByKind.details as FridaSessionDetails;
			expect(sendKindDetails.events).toHaveLength(3);

			// 8. Query 'error' events by kind: "error"
			const errorByKind = await tool.execute("q_err_kind", {
				action: "events",
				session_id: "frida-structured-sess",
				kind: "error",
			});
			const errKindDetails = errorByKind.details as FridaSessionDetails;
			expect(errKindDetails.events?.length).toBeGreaterThanOrEqual(1);

			// 9. Query via filter: "ChaCha20"
			const filterRes = await tool.execute("q_filter", {
				action: "events",
				session_id: "frida-structured-sess",
				filter: "ChaCha20",
				export_evidence: true,
			});
			const filterDetails = filterRes.details as FridaSessionDetails;
			expect(filterDetails.events).toHaveLength(1);
			expect(filterDetails.evidence).toBeDefined();
			const rawEv = filterDetails.evidence;
			const ev = Array.isArray(rawEv) ? rawEv[0] : rawEv;
			expect(ev).toBeDefined();
			if (!ev) throw new Error("Expected filtered event evidence");
			expect(ev?.locator).toStartWith("session:frida-structured-sess:seq:");
			expect(ev.content).toContain("ChaCha20");
		} finally {
			await removeTestDir(tempDir);
			await removeTestDir(stateDir);
		}
	});

	it("records clean session_create lifecycle event on create without initial script", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-regress-create-"));
		const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-regress-create-state-"));
		try {
			const which = (cmd: string) => (cmd === "frida" ? "/usr/local/bin/frida" : null);
			const tool = new FridaSessionTool(createTestSession(tempDir), {
				runner: async () => ({
					stdout: Buffer.from(""),
					stderr: "",
					exitCode: 0,
					outputBytes: 0,
					truncated: false,
					timedOut: false,
				}),
				which,
				stateRoot: stateDir,
			});

			// Create session without script
			const createRes = await tool.execute("c1", {
				action: "create",
				session_id: "clean-sess",
				pid: 1234,
				name: "Clean Session Test",
			});
			const createDetails = createRes.details as FridaSessionDetails;
			expect(createDetails.status).toBe("ok");
			expect(createDetails.session?.events).toHaveLength(1);
			expect(createDetails.session?.events?.[0].kind).toBe("lifecycle");
			expect(createDetails.session?.events?.[0].channel).toBe("session_create");
			expect(createDetails.session?.events?.[0].raw).toContain("session created for pid:1234");
		} finally {
			await removeTestDir(tempDir);
			await removeTestDir(stateDir);
		}
	});
});

describe("frida_session real Frida CLI normalization, pause semantics, and watchdog allowance", () => {
	it("normalizes actual Frida CLI python repr send messages with None/bool/apostrophe and trailing data", () => {
		const line1 =
			"message: {'type': 'send', 'payload': {'event': 'rea_demo_transform', 'input': 2, 'output': 17}} data: None";
		const res1 = parseStructuredFridaMessage(line1);
		expect(res1).not.toBeNull();
		expect(res1?.parsed).toEqual({
			type: "send",
			payload: { event: "rea_demo_transform", input: 2, output: 17 },
		});
		expect(res1?.data).toBeNull();

		// Apostrophe in string, booleans True/False, null/None, double quotes in single quotes
		const line2 =
			"message: {'type': 'send', 'payload': {'text': 'it\\'s running', 'flag': True, 'missing': None, 'desc': 'says \"hello\"'}} data: None";
		const res2 = parseStructuredFridaMessage(line2);
		expect(res2).not.toBeNull();
		expect(res2?.parsed).toEqual({
			type: "send",
			payload: { text: "it's running", flag: true, missing: null, desc: 'says "hello"' },
		});

		// Standard JSON without prefix
		const line3 = '{"type": "send", "payload": {"standard_json": true, "val": 42}}';
		const res3 = parseStructuredFridaMessage(line3);
		expect(res3).not.toBeNull();
		expect(res3?.parsed).toEqual({
			type: "send",
			payload: { standard_json: true, val: 42 },
		});

		// Python repr error message
		const line4 = "message: {'type': 'error', 'description': \"Error: it\\'s failed\", 'stack': 'at ...'} data: None";
		const res4 = parseStructuredFridaMessage(line4);
		expect(res4).not.toBeNull();
		expect(res4?.parsed).toEqual({
			type: "error",
			description: "Error: it's failed",
			stack: "at ...",
		});

		// Non-message text should not parse as structured message
		const line5 = "message: starting dynamic injection";
		expect(parseStructuredFridaMessage(line5)).toBeNull();

		const line6 = "console.log: hook installed";
		expect(parseStructuredFridaMessage(line6)).toBeNull();
	});

	it("parses real hook stdout into structured message events with numeric payloads", () => {
		const stdout = [
			"message: {'type': 'send', 'payload': {'event': 'rea_hook_ready', 'address': '0x100778460'}} data: None",
			"message: {'type': 'send', 'payload': {'event': 'rea_demo_transform', 'input': 2, 'output': 17}} data: None",
			"message: {'type': 'send', 'payload': {'event': 'rea_demo_transform', 'input': 3, 'output': 24}} data: None",
			"message: {'type': 'error', 'description': 'Non-fatal script warning'} data: None",
			"hook initialization stdout line",
		].join("\n");

		const parsed = parseFridaOutputIntoEvents("real-demo-sess", stdout, "", 0);
		const events = parsed.events;

		const sendEvents = events.filter(e => e.kind === "message" && e.channel === "send");
		expect(sendEvents).toHaveLength(3);

		const readyEvent = sendEvents.find(e => (e.payload as Record<string, unknown>)?.event === "rea_hook_ready");
		expect(readyEvent).toBeDefined();
		expect((readyEvent?.payload as Record<string, unknown>)?.address).toBe("0x100778460");

		const transformEvents = sendEvents.filter(
			e => (e.payload as Record<string, unknown>)?.event === "rea_demo_transform",
		);
		expect(transformEvents).toHaveLength(2);
		const p0 = transformEvents[0].payload as Record<string, unknown>;
		const p1 = transformEvents[1].payload as Record<string, unknown>;
		expect(p0.input).toBe(2);
		expect(p0.output).toBe(17);
		expect(p1.input).toBe(3);
		expect(p1.output).toBe(24);

		const errEvent = events.find(e => e.kind === "stderr" && e.channel === "error");
		expect(errEvent).toBeDefined();
		expect(errEvent?.payload).toBe("Non-fatal script warning");

		const stdoutEvent = events.find(e => e.kind === "stdout" && e.channel === "console");
		expect(stdoutEvent).toBeDefined();
		expect(stdoutEvent?.payload).toBe("hook initialization stdout line");
	});

	it("spawn mode: removes --no-pause and passes --pause only when requested", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-pause-test-"));
		const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-pause-state-"));
		try {
			const calls: Array<{ binary: string; args: string[] }> = [];
			const runner: FridaRunner = async (binary, args) => {
				calls.push({ binary, args });
				return {
					stdout: Buffer.from("__FRIDA_SPAWN_OK__:9999\n"),
					stderr: "",
					exitCode: 0,
					outputBytes: 25,
					truncated: false,
					timedOut: false,
				};
			};
			const which = (cmd: string) => (cmd === "frida" ? "/usr/local/bin/frida" : null);
			const tool = new FridaSessionTool(createTestSession(tempDir), { runner, which, stateRoot: stateDir });

			// 1. Default spawn: no pause flags
			await tool.execute("c1", {
				action: "create",
				session_id: "spawn-default",
				spawn: "com.example.app",
			});
			expect(calls[0].args).toContain("-f");
			expect(calls[0].args).not.toContain("--no-pause");
			expect(calls[0].args).not.toContain("--pause");

			// 2. Explicit pause: true -> passes --pause
			await tool.execute("c2", {
				action: "create",
				session_id: "spawn-paused",
				spawn: "com.example.app",
				pause: true,
			});
			expect(calls[1].args).toContain("-f");
			expect(calls[1].args).toContain("--pause");
			expect(calls[1].args).not.toContain("--no-pause");

			// 3. Explicit no_pause: false -> passes --pause
			await tool.execute("c3", {
				action: "create",
				session_id: "spawn-legacy-paused",
				spawn: "com.example.app",
				no_pause: false,
			});
			expect(calls[2].args).toContain("-f");
			expect(calls[2].args).toContain("--pause");
			expect(calls[2].args).not.toContain("--no-pause");
		} finally {
			await removeTestDir(tempDir);
			await removeTestDir(stateDir);
		}
	});

	it("preserves prototype integrity without prototype pollution or classification leakage", () => {
		const protoLine =
			"message: {'type': 'send', 'payload': {'__proto__': {'event': 'crypto'}, 'constructor': 'kept'}} data: None";
		const res = parseStructuredFridaMessage(protoLine);
		expect(res).not.toBeNull();
		let payload: unknown = null;
		if (res && res.parsed && typeof res.parsed === "object" && "payload" in res.parsed) {
			payload = res.parsed.payload;
		}
		expect(payload).not.toBeNull();
		expect(Object.prototype.hasOwnProperty.call(payload, "__proto__")).toBe(true);
		expect((payload as Record<string, unknown>).event).toBeUndefined();
		let constructorVal: unknown;
		if (payload && typeof payload === "object" && "constructor" in payload) {
			constructorVal = payload.constructor;
		}
		expect(constructorVal).toBe("kept");
		expect(JSON.stringify(payload)).toContain('"__proto__":{"event":"crypto"}');

		// Verify event classification in parseFridaOutputIntoEvents does not leak crypto category
		const parsed = parseFridaOutputIntoEvents("proto-sess", protoLine, "", 0);
		const msgEvent = parsed.events.find(e => e.kind === "message");
		expect(msgEvent).toBeDefined();
		expect(msgEvent?.metadata?.category).toBeUndefined();
	});

	it("rejects compound dictionary keys to prevent amplification attacks", () => {
		expect(() => parsePythonLiteral("{{'__proto__': [], 'length': 8}: 0}")).toThrow(
			"Dictionary keys must be scalar primitives",
		);
	});

	it("strictly validates suffixes and falls back to plain stdout for malformed trailing text", () => {
		const badSuffixes = [
			'{"count":1} hook installed',
			"{'type':'send','payload':1} garbage",
			"{'type':'send','payload':1} data: None garbage",
			"{'type':'send','payload':1} data: b'abc' garbage",
		];
		for (const bad of badSuffixes) {
			expect(parseStructuredFridaMessage(bad)).toBeNull();
			const parsed = parseFridaOutputIntoEvents("bad-suffix-sess", bad, "", 0);
			const stdoutEvent = parsed.events.find(e => e.kind === "stdout");
			expect(stdoutEvent).toBeDefined();
			expect(stdoutEvent?.payload).toBe(bad);
		}

		const validSuffixes = [
			"{'type':'send','payload':1}",
			"{'type':'send','payload':1} data: None",
			"{'type':'send','payload':1} data: b'abc'",
			"{'type':'send','payload':1} data: b'data: inside bytes'",
		];
		for (const valid of validSuffixes) {
			expect(parseStructuredFridaMessage(valid)).not.toBeNull();
		}
	});

	it("preserves unescaped Unicode line separators U+2028 and U+2029 in JSON payloads", () => {
		const unicodeJson = "message: " + JSON.stringify({ type: "send", payload: "a\u2028b\u2029c" });
		const res1 = parseStructuredFridaMessage(unicodeJson);
		expect(res1).not.toBeNull();
		let payload1: unknown;
		if (res1 && res1.parsed && typeof res1.parsed === "object" && "payload" in res1.parsed) {
			payload1 = res1.parsed.payload;
		}
		expect(payload1).toBe("a\u2028b\u2029c");

		const unicodeJsonWithData = unicodeJson + " data: None";
		const res2 = parseStructuredFridaMessage(unicodeJsonWithData);
		expect(res2).not.toBeNull();
		let payload2: unknown;
		if (res2 && res2.parsed && typeof res2.parsed === "object" && "payload" in res2.parsed) {
			payload2 = res2.parsed.payload;
		}
		expect(payload2).toBe("a\u2028b\u2029c");
	});

	it("decodes Python repr literal escape sequences safely", () => {
		const repr =
			"{'nul': '\\x00', 'u2028': '\\u2028', 'emoji': '\\U0001f600', 'surrogate': '\\ud800', 'quotes': 'it\\'s \"fine\"\\\\'}";
		const res = parsePythonLiteral(repr);
		const val = res.value as Record<string, unknown>;
		expect(val.nul).toBe("\0");
		expect(val.u2028).toBe("\u2028");
		expect(val.emoji).toBe("😀");
		expect(val.surrogate).toBe("\ud800");
		expect(val.quotes).toBe('it\'s "fine"\\');
	});
});
describe("frida_session built-in templates and structured evidence mapping", () => {
	const sampleSession: FridaSessionRecord = {
		id: "test-sess-1",
		mode: "live",
		status: "active",
		target: { type: "pid", value: 1234, pid: 1234 },
		createdAt: new Date().toISOString(),
		updatedAt: new Date().toISOString(),
		runsCount: 1,
		history: [],
		events: [],
		eventsCount: 0,
	};

	it("formats confirmed JNI RegisterNatives event as confirmed fact evidence", () => {
		const event: DynamicSessionEvent = {
			id: "ev_1",
			seq: 1,
			timestamp: new Date().toISOString(),
			sessionId: "test-sess-1",
			kind: "message",
			channel: "send",
			payload: {
				event: "jni_register_natives",
				status: "confirmed",
				retval: 0,
				class: "com.example.app.LicenseChecker",
				nMethods: 1,
				methods: [
					{
						name: "verifyLicense",
						signature: "(Ljava/lang/String;)Z",
						fnPtr: "0x7f001000",
						module: "liblicense.so",
						base: "0x7f000000",
						offset: "0x1000",
					},
				],
			},
		};

		const ref = buildEvidenceReference(sampleSession, event);
		expect(ref.locator).toBe("session:test-sess-1:seq:1");
		expect(ref.kind).toBe("fact");
		expect(ref.title).toContain("JNI RegisterNatives: com.example.app.LicenseChecker");
		expect(ref.metadata?.confirmed).toBe(true);
		expect(ref.metadata?.rejected).toBe(false);
	});

	it("formats rejected JNI RegisterNatives event with explicit rejected mapping metadata", () => {
		const event: DynamicSessionEvent = {
			id: "ev_2",
			seq: 2,
			timestamp: new Date().toISOString(),
			sessionId: "test-sess-1",
			kind: "message",
			channel: "send",
			payload: {
				event: "jni_register_natives",
				status: "rejected",
				retval: -1,
				class: "com.example.app.SecurityBridge",
				nMethods: 2,
			},
		};

		const ref = buildEvidenceReference(sampleSession, event);
		expect(ref.locator).toBe("session:test-sess-1:seq:2");
		expect(ref.title).toContain("[Rejected]");
		expect(ref.metadata?.confirmed).toBe(false);
		expect(ref.metadata?.rejected).toBe(true);
		expect(ref.metadata?.retval).toBe(-1);
	});

	it("formats native function call event as structured evidence reference", () => {
		const event: DynamicSessionEvent = {
			id: "ev_3",
			seq: 3,
			timestamp: new Date().toISOString(),
			sessionId: "test-sess-1",
			kind: "message",
			channel: "send",
			payload: {
				event: "native_call",
				target: "check_integrity",
				address: "0x7f12345000",
				module: "libsec.so",
				offset: "0x5000",
				args: [1, "0x2000"],
				retval: "0x1",
			},
		};

		const ref = buildEvidenceReference(sampleSession, event);
		expect(ref.locator).toBe("session:test-sess-1:seq:3");
		expect(ref.title).toContain("Native Call: check_integrity [libsec.so+0x5000]");
		expect(ref.metadata?.target).toBe("check_integrity");
		expect(ref.metadata?.offset).toBe("0x5000");
	});

	it("parses stdout trace markers into categorized structured session events", () => {
		const rawStdout = `
__FRIDA_TRACE_START__{"event":"jni_register_natives","status":"confirmed","retval":0,"class":"com.example.Native","nMethods":1}__FRIDA_TRACE_END__
__FRIDA_TRACE_START__{"event":"native_call","target":"calc","address":"0x1000","offset":"0x100"}__FRIDA_TRACE_END__
`;
		const parsed = parseFridaOutputIntoEvents("sess-cat-test", rawStdout, "", 0);
		expect(parsed.events).toHaveLength(2);
		expect(parsed.events[0].metadata?.category).toBe("jni");
		expect(parsed.events[1].metadata?.category).toBe("native_trace");
	});
});
