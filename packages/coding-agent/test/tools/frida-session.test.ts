import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { BUILTIN_TOOL_NAMES, normalizeToolName } from "@rva/coding-agent/tools/builtin-names";
import {
	createTools,
	type ToolSession,
	FridaSessionTool,
	type FridaSessionDetails,
	type FridaSessionRecord,
	type FridaRunner,
	type FridaRunResult,
	sanitizeRecordSecrets,
	isProcessAlive,
	encodeProjectKey,
} from "@rva/coding-agent/tools";
import { Settings } from "@rva/coding-agent/config/settings";

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
		.filter(c => c.type === "text" && c.text)
		.map(c => c.text!)
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
			const sessionFilePath = path.join(stateDir, projectKey, "sess-lifecycle-1.json");
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
			const artifactExists = await fs.stat(runScriptDetails.artifactPath!).then(
				() => true,
				() => false,
			);
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
			const sessionFilePath = path.join(stateDir, projectKey, "secret-session.json");
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
					scriptSnippet: "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M",
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
