import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "@rva/coding-agent/config/settings";
import {
	createTools,
	ReverseRuntimeSessionTool,
	type ToolSession,
	BUILTIN_TOOLS,
} from "@rva/coding-agent/tools";
import { BUILTIN_TOOL_NAMES, normalizeToolName } from "@rva/coding-agent/tools/builtin-names";
import { removeWithRetries } from "@rva/utils";
import { ToolError } from "@rva/tui/tools/tool-errors";
import {
	computeSessionStaleState,
	createRuntimeSessionId,
	encodeRuntimeSessionProjectKey,
	generateRestorePlan,
	probeSessionStatus,
	ReverseRuntimeSessionStore,
	sanitizeMetadataObject,
	sanitizeSessionString,
	sanitizeUrlString,
	deriveTargetSummary,
	sanitizeRuntimeSessionRecord,
} from "@rva/coding-agent/reverse-runtime-session";

function createTestSession(cwd: string, options: { allocateArtifact?: boolean } = {}): ToolSession {
	const artifactsDir = path.join(cwd, "artifacts");
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
		allocateOutputArtifact: options.allocateArtifact
			? async (toolType: string) => {
					await fs.mkdir(artifactsDir, { recursive: true });
					const id = `art-${Date.now()}`;
					return { id, path: path.join(artifactsDir, `${id}.${toolType}.txt`) };
				}
			: undefined,
	};
}

function textOf(result: { content: Array<{ type: string; text?: string }> }): string {
	return result.content
		.map(item => item.text ?? "")
		.join("\n")
		.trim();
}

// ============================================================================
// 1. Tool Registration and Discovery
// ============================================================================

describe("reverse_runtime_session tool registration and discovery", () => {
	it("registers in BUILTIN_TOOL_NAMES", () => {
		expect(BUILTIN_TOOL_NAMES).toContain("reverse_runtime_session");
	});

	it("normalizes tool aliases to reverse_runtime_session", () => {
		expect(normalizeToolName("reverse_runtime_session")).toBe("reverse_runtime_session");
		expect(normalizeToolName("runtime_session")).toBe("reverse_runtime_session");
		expect(normalizeToolName("reverse_session")).toBe("reverse_runtime_session");
		expect(normalizeToolName("runtime_registry")).toBe("reverse_runtime_session");
		expect(normalizeToolName("reverse_runtime_registry")).toBe("reverse_runtime_session");
	});

	it("instantiates via createTools and BUILTIN_TOOLS", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "runt-reg-"));
		try {
			const session = createTestSession(tempDir);
			const tools = await createTools(session, ["reverse_runtime_session"]);
			const tool = tools.find(t => t.name === "reverse_runtime_session");
			expect(tool).toBeDefined();
			expect(tool?.label).toBe("Reverse Runtime Session Registry");
			expect(tool?.strict).toBe(true);

			const direct = BUILTIN_TOOLS.reverse_runtime_session(session);
			expect(direct).toBeInstanceOf(ReverseRuntimeSessionTool);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("enforces approval tiers for read vs write actions", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "runt-appr-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new ReverseRuntimeSessionTool(session);

			expect(tool.approval({ action: "list" })).toBe("read");
			expect(tool.approval({ action: "status" })).toBe("read");
			expect(tool.approval({ action: "restore" })).toBe("read");
			expect(tool.approval({ action: "register" })).toBe("write");
			expect(tool.approval({ action: "heartbeat" })).toBe("write");
			expect(tool.approval({ action: "unregister" })).toBe("write");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

// ============================================================================
// 2. Sanitization of Secrets, URLs, and Live Handles
// ============================================================================

describe("reverse_runtime_session sanitization", () => {
	it("redacts credentials and bearer tokens in strings", () => {
		const secretText = "Bearer eyJhbGciOiJIUzI1NiJ9.secret password=super_secret_12345 token: abcdef1234567890";
		const sanitized = sanitizeSessionString(secretText);
		expect(sanitized).not.toContain("super_secret_12345");
		expect(sanitized).not.toContain("eyJhbGciOiJIUzI1NiJ9");
		expect(sanitized).toContain("[REDACTED]");
	});

	it("sanitizes URLs containing embedded auth and sensitive query params", () => {
		const rawUrl = "https://admin:myPassword123@api.target.com/cdp?token=secretToken456&auth=secret789&view=main";
		const sanitized = sanitizeUrlString(rawUrl);
		expect(sanitized).not.toContain("myPassword123");
		expect(sanitized).not.toContain("secretToken456");
		expect(sanitized).not.toContain("secret789");
		expect(sanitized).toContain("[REDACTED]");
		expect(sanitized).toContain("view=main");
	});

	it("strips live process handles, sockets, and sensitive keys from objects", () => {
		const mockProcess = {
			pid: 1234,
			socket: { readyState: "open" },
			stdin: { write: () => true },
			stdout: { read: () => null },
			_handle: {},
			password: "secret_value_should_be_stripped",
			processName: "target_bin",
		};

		const sanitized = sanitizeMetadataObject(mockProcess) as Record<string, unknown>;
		expect(sanitized.pid).toBe(1234);
		expect(sanitized.processName).toBe("target_bin");
		expect(sanitized.socket).toBeUndefined();
		expect(sanitized.stdin).toBeUndefined();
		expect(sanitized.stdout).toBeUndefined();
		expect(sanitized._handle).toBeUndefined();
		expect(sanitized.password).toBe("[REDACTED]");
	});

	it("derives target summary from sanitized target details and redacts tokens", () => {
		const rawToken = "super_secret_token_live_abcdef123456789";
		const targetDetails = {
			url: `https://admin:mySecretPass123@api.target.com/cdp?token=${rawToken}&view=main`,
			token: rawToken,
		};
		const sanitizedDetails = sanitizeMetadataObject(targetDetails) as Record<string, unknown>;
		const derived = deriveTargetSummary("browser", sanitizedDetails);

		expect(derived).not.toContain(rawToken);
		expect(derived).not.toContain("mySecretPass123");
		expect(derived).toContain("[REDACTED]");
	});

	it("sanitizes complete runtime session records at construction and store boundaries", () => {
		const rawToken = "super_secret_token_live_abcdef123456789";
		const record = {
			id: "runt_browser_12345",
			name: `Debugger session with token: ${rawToken}`,
			kind: "browser" as const,
			status: "active" as const,
			target_summary: `https://admin:pass@host/path?token=${rawToken}`,
			target_details: {
				token: rawToken,
				url: `https://admin:pass@host/path?token=${rawToken}`,
			},
			connection: {
				cdp_url: `wss://host:9222/devtools?token=${rawToken}`,
				auth_token: rawToken,
			},
			recovery_hints: {
				restore_tool: "browser",
				restore_action: "open",
				restore_params: {
					url: `https://admin:pass@host/path?token=${rawToken}`,
					token: rawToken,
				},
				instructions: [`Open with token: ${rawToken}`],
			},
			created_at: new Date().toISOString(),
			updated_at: new Date().toISOString(),
			last_heartbeat_at: new Date().toISOString(),
			heartbeat_count: 1,
			stale_timeout_sec: 300,
			status_source: "registered" as const,
			last_probe: {
				timestamp: new Date().toISOString(),
				ok: true,
				message: `Connected with token: ${rawToken}`,
			},
			workflow_id: `wf_secret_${rawToken}`,
			step_id: `step_secret_${rawToken}`,
		};

		const sanitized = sanitizeRuntimeSessionRecord(record);
		const json = JSON.stringify(sanitized);

		expect(json).not.toContain(rawToken);
		expect(sanitized.name).not.toContain(rawToken);
		expect(sanitized.target_summary).not.toContain(rawToken);
		expect(sanitized.last_probe?.message).not.toContain(rawToken);
		expect(sanitized.workflow_id).not.toContain(rawToken);
		expect(sanitized.step_id).not.toContain(rawToken);
	});

	it("regression: asserts raw token absent from complete persisted JSON and rendered/list/status outputs", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "runt-privacy-reg-"));
		const stateRoot = path.join(tempDir, "state");
		const rawToken = "secret_raw_token_live_9876543210abcdef";
		const rawPassword = "super_secret_auth_password_123";

		try {
			const session = createTestSession(tempDir);
			const tool = new ReverseRuntimeSessionTool(session, { stateRoot });
			const store = ReverseRuntimeSessionStore.forSession(tempDir, stateRoot);

			// 1. Register with sensitive tokens across target, name, connection, and details
			const regRes = await tool.execute({
				action: "register",
				kind: "browser",
				name: `Production Debugger (token: ${rawToken})`,
				target: `https://admin:${rawPassword}@api.target.com/cdp?token=${rawToken}&auth=${rawToken}`,
				target_details: {
					name: "admin_devtools",
					url: `https://admin:${rawPassword}@api.target.com/cdp?token=${rawToken}&auth=${rawToken}`,
					token: rawToken,
					password: rawPassword,
				},
				connection: {
					cdp_url: `wss://admin:${rawPassword}@api.target.com/cdp?token=${rawToken}`,
					auth_token: rawToken,
					password: rawPassword,
				},
			});

			const sessionId = regRes.details.session!.id;
			const regRendered = textOf(regRes);

			// Assert rendered register output does NOT contain secrets
			expect(regRendered).not.toContain(rawToken);
			expect(regRendered).not.toContain(rawPassword);
			expect(JSON.stringify(regRes.details)).not.toContain(rawToken);
			expect(JSON.stringify(regRes.details)).not.toContain(rawPassword);

			// 2. Assert complete persisted JSON file on disk contains NO raw token or password
			const diskFilePath = store.filePath(sessionId);
			const persistedJson = await Bun.file(diskFilePath).text();
			expect(persistedJson).not.toContain(rawToken);
			expect(persistedJson).not.toContain(rawPassword);
			expect(persistedJson).toContain("[REDACTED]");

			// 3. Assert list output contains NO raw token or password
			const listRes = await tool.execute({ action: "list" });
			const listRendered = textOf(listRes);
			expect(listRendered).not.toContain(rawToken);
			expect(listRendered).not.toContain(rawPassword);
			expect(JSON.stringify(listRes.details)).not.toContain(rawToken);
			expect(JSON.stringify(listRes.details)).not.toContain(rawPassword);

			// 4. Heartbeat update with probe result containing secrets
			const hbRes = await tool.execute({
				action: "heartbeat",
				session_id: sessionId,
				probe_result: `Observation token=${rawToken} auth_fail`,
			});
			const hbRendered = textOf(hbRes);
			expect(hbRendered).not.toContain(rawToken);
			expect(JSON.stringify(hbRes.details)).not.toContain(rawToken);

			// Check updated file on disk after heartbeat
			const diskAfterHb = await Bun.file(diskFilePath).text();
			expect(diskAfterHb).not.toContain(rawToken);

			// 5. Status action with safe probe containing secrets
			const statusRes = await tool.execute({
				action: "status",
				session_id: sessionId,
				probe: true,
				probe_result: `Diagnostic error: token=${rawToken}`,
			});
			const statusRendered = textOf(statusRes);
			expect(statusRendered).not.toContain(rawToken);
			expect(statusRendered).not.toContain(rawPassword);
			expect(JSON.stringify(statusRes.details)).not.toContain(rawToken);
			expect(JSON.stringify(statusRes.details)).not.toContain(rawPassword);
			expect(statusRes.details.session?.last_probe?.message).not.toContain(rawToken);
			expect(statusRes.details.session?.last_probe?.message).toContain("[REDACTED]");

			// Check updated file on disk after status probe
			const diskAfterStatus = await Bun.file(diskFilePath).text();
			expect(diskAfterStatus).not.toContain(rawToken);

			// 6. Test derived summary when explicit target is omitted
			const derivedRegRes = await tool.execute({
				action: "register",
				kind: "browser",
				target_details: {
					url: `https://admin:${rawPassword}@dashboard.internal.corp/cdp?token=${rawToken}`,
					token: rawToken,
				},
			});
			const derivedSessionId = derivedRegRes.details.session!.id;
			const derivedRendered = textOf(derivedRegRes);
			expect(derivedRendered).not.toContain(rawToken);
			expect(derivedRendered).not.toContain(rawPassword);
			expect(derivedRegRes.details.session!.target_summary).not.toContain(rawToken);
			expect(derivedRegRes.details.session!.target_summary).toContain("[REDACTED]");

			const derivedDiskJson = await Bun.file(store.filePath(derivedSessionId)).text();
			expect(derivedDiskJson).not.toContain(rawToken);
			expect(derivedDiskJson).not.toContain(rawPassword);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

// ============================================================================
// 3. Lifecycle Across Session Kinds (Frida, Browser, IDA, Ghidra)
// ============================================================================

describe("reverse_runtime_session lifecycle across kinds", () => {
	it("registers, inspects, and restores a Frida session", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "runt-frida-"));
		const stateRoot = path.join(tempDir, "state");
		try {
			const session = createTestSession(tempDir);
			const tool = new ReverseRuntimeSessionTool(session, { stateRoot });

			// Register
			const regRes = await tool.execute({
				action: "register",
				kind: "frida",
				target: "com.example.bank",
				target_details: { process: "com.example.bank", usb: true },
				connection: { host: "127.0.0.1:27042", password: "should_redact" },
			});

			const regText = textOf(regRes);
			expect(regText).toContain("Registered reverse runtime session");
			expect(regText).toContain("com.example.bank");
			expect(regRes.details.session?.kind).toBe("frida");
			expect(regRes.details.session?.connection.password).toBe("[REDACTED]");

			const sessionId = regRes.details.session!.id;

			// Status
			const statusRes = await tool.execute({
				action: "status",
				session_id: sessionId,
			});
			const statusText = textOf(statusRes);
			expect(statusText).toContain(sessionId);
			expect(statusText).toContain("ACTIVE");
			expect(statusRes.details.restore_plan?.restore_tool).toBe("frida_session");
			expect(statusRes.details.restore_plan?.restore_action).toBe("create");

			// Restore
			const restoreRes = await tool.execute({
				action: "restore",
				session_id: sessionId,
			});
			const restoreText = textOf(restoreRes);
			expect(restoreText).toContain("Deterministic Restore Plan");
			expect(restoreRes.details.restore_plan?.can_restore).toBe(true);
			expect(restoreRes.details.restore_plan?.restore_params.process).toBe("com.example.bank");

			// Unregister
			const unregRes = await tool.execute({
				action: "unregister",
				session_id: sessionId,
			});
			expect(textOf(unregRes)).toContain("Unregistered runtime session");

			// Verify deleted
			await expect(tool.execute({ action: "status", session_id: sessionId })).rejects.toThrow(ToolError);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("registers, inspects, and restores a Browser session", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "runt-browser-"));
		const stateRoot = path.join(tempDir, "state");
		try {
			const session = createTestSession(tempDir);
			const tool = new ReverseRuntimeSessionTool(session, { stateRoot });

			const regRes = await tool.execute({
				action: "register",
				kind: "browser",
				target: "https://auth.internal.corp/admin?token=secret123",
				target_details: {
					name: "auth_panel",
					url: "https://auth.internal.corp/admin?token=secret123",
					headed: false,
				},
			});

			const sessionId = regRes.details.session!.id;
			expect(regRes.details.session?.target_details.url).toContain("[REDACTED]");
			expect(regRes.details.session?.target_details.url).not.toContain("secret123");

			const restoreRes = await tool.execute({
				action: "restore",
				session_id: sessionId,
			});

			expect(restoreRes.details.restore_plan?.restore_tool).toBe("browser");
			expect(restoreRes.details.restore_plan?.restore_action).toBe("open");
			expect(restoreRes.details.restore_plan?.restore_params.name).toBe("auth_panel");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("registers, inspects, and restores an IDA Pro session", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "runt-ida-"));
		const stateRoot = path.join(tempDir, "state");
		try {
			const session = createTestSession(tempDir);
			const tool = new ReverseRuntimeSessionTool(session, { stateRoot });

			const idbPath = path.join(tempDir, "sample.i64");
			await fs.writeFile(idbPath, "IDA IDB MOCK BYTES");

			const regRes = await tool.execute({
				action: "register",
				kind: "ida",
				target: idbPath,
				target_details: { db: idbPath },
			});

			const sessionId = regRes.details.session!.id;

			// Safe metadata probe checks file presence on disk
			const probeRes = await tool.execute({
				action: "status",
				session_id: sessionId,
				probe: true,
			});

			expect(probeRes.details.probe_info?.ok).toBe(true);
			expect(probeRes.details.probe_info?.source).toBe("metadata_check");
			expect(probeRes.details.probe_info?.message).toContain("IDA target file exists on disk");

			const restoreRes = await tool.execute({
				action: "restore",
				session_id: sessionId,
			});

			expect(restoreRes.details.restore_plan?.restore_tool).toBe("ida");
			expect(restoreRes.details.restore_plan?.restore_action).toBe("open");
			expect(restoreRes.details.restore_plan?.restore_params.db).toBe(idbPath);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("registers, inspects, and restores a Ghidra session", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "runt-ghidra-"));
		const stateRoot = path.join(tempDir, "state");
		try {
			const session = createTestSession(tempDir);
			const tool = new ReverseRuntimeSessionTool(session, { stateRoot });

			const binPath = path.join(tempDir, "firmware.bin");
			await fs.writeFile(binPath, "BINARY CODE");

			const regRes = await tool.execute({
				action: "register",
				kind: "ghidra",
				target: binPath,
				target_details: { path: binPath, project_dir: path.join(tempDir, "ghidra_proj") },
			});

			const sessionId = regRes.details.session!.id;

			const probeRes = await tool.execute({
				action: "status",
				session_id: sessionId,
				probe: true,
			});

			expect(probeRes.details.probe_info?.ok).toBe(true);
			expect(probeRes.details.probe_info?.message).toContain("Ghidra target binary exists on disk");

			const restoreRes = await tool.execute({
				action: "restore",
				session_id: sessionId,
			});

			expect(restoreRes.details.restore_plan?.restore_tool).toBe("ghidra_inspect");
			expect(restoreRes.details.restore_plan?.restore_action).toBe("info");
			expect(restoreRes.details.restore_plan?.restore_params.path).toBe(binPath);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

// ============================================================================
// 4. Stale Detection, Heartbeat, and Opt-In Safe Probes
// ============================================================================

describe("reverse_runtime_session stale detection and heartbeat", () => {
	it("detects stale status deterministically based on threshold", () => {
		const now = Date.now();
		const oldTime = new Date(now - 400 * 1000).toISOString(); // 400s ago

		const mockRecord = {
			id: "runt_frida_mock",
			kind: "frida" as const,
			status: "active" as const,
			target_summary: "mock target",
			target_details: {},
			connection: {},
			recovery_hints: { restore_tool: "frida_session", restore_action: "create", restore_params: {}, instructions: [] },
			created_at: oldTime,
			updated_at: oldTime,
			last_heartbeat_at: oldTime,
			heartbeat_count: 1,
			stale_timeout_sec: 300,
			status_source: "registered" as const,
		};

		const staleCheck = computeSessionStaleState(mockRecord, now);
		expect(staleCheck.isStale).toBe(true);
		expect(staleCheck.effectiveStatus).toBe("stale");
		expect(staleCheck.secondsSinceHeartbeat).toBeGreaterThanOrEqual(400);
	});

	it("refreshes heartbeat and resets stale status to active", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "runt-hb-"));
		const stateRoot = path.join(tempDir, "state");
		try {
			const session = createTestSession(tempDir);
			const tool = new ReverseRuntimeSessionTool(session, { stateRoot });

			// Register with short 10s stale timeout
			const regRes = await tool.execute({
				action: "register",
				kind: "frida",
				target: "test_process",
				stale_timeout: 10,
			});
			const sessionId = regRes.details.session!.id;

			// Issue heartbeat
			const hbRes = await tool.execute({
				action: "heartbeat",
				session_id: sessionId,
				probe_result: "Hooks active and capturing traffic",
			});

			const hbText = textOf(hbRes);
			expect(hbText).toContain("Heartbeat acknowledged");
			expect(hbRes.details.session?.heartbeat_count).toBe(2);
			expect(hbRes.details.session?.status).toBe("active");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("records caller-reported status facts without unsafe process execution", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "runt-caller-"));
		const stateRoot = path.join(tempDir, "state");
		try {
			const session = createTestSession(tempDir);
			const tool = new ReverseRuntimeSessionTool(session, { stateRoot });

			const regRes = await tool.execute({
				action: "register",
				kind: "generic",
				target: "custom_runtime",
			});
			const sessionId = regRes.details.session!.id;

			// Caller reports process crashed/failed
			const statusRes = await tool.execute({
				action: "status",
				session_id: sessionId,
				caller_status: "failed",
				probe_result: "SIGSEGV observed in memory trace",
			});

			expect(statusRes.details.session?.status).toBe("failed");
			expect(statusRes.details.session?.status_source).toBe("caller_reported");
			expect(statusRes.details.probe_info?.message).toContain("SIGSEGV observed");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

// ============================================================================
// 5. Reverse Workflow Integration and Export Spilling
// ============================================================================

describe("reverse_runtime_session workflow association and artifacts", () => {
	it("associates with workflow_id and filters in list action", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "runt-wf-"));
		const stateRoot = path.join(tempDir, "state");
		try {
			const session = createTestSession(tempDir);
			const tool = new ReverseRuntimeSessionTool(session, { stateRoot });

			await tool.execute({
				action: "register",
				kind: "frida",
				target: "target1",
				workflow_id: "wf_rw_111",
			});

			await tool.execute({
				action: "register",
				kind: "browser",
				target: "https://example.com",
				workflow_id: "wf_rw_222",
			});

			const listWf1 = await tool.execute({
				action: "list",
				workflow_id: "wf_rw_111",
			});
			expect(listWf1.details.sessions?.length).toBe(1);
			expect(listWf1.details.sessions?.[0].workflow_id).toBe("wf_rw_111");

			const listAll = await tool.execute({ action: "list" });
			expect(listAll.details.sessions?.length).toBe(2);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("exports complete session report to session artifact when requested", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "runt-art-"));
		const stateRoot = path.join(tempDir, "state");
		try {
			const session = createTestSession(tempDir, { allocateArtifact: true });
			const tool = new ReverseRuntimeSessionTool(session, { stateRoot });

			const regRes = await tool.execute({
				action: "register",
				kind: "ida",
				target: "test.i64",
			});
			const sessionId = regRes.details.session!.id;

			const statusRes = await tool.execute({
				action: "status",
				session_id: sessionId,
				to_artifact: true,
			});

			expect(statusRes.details.artifactId).toBeDefined();
			expect(statusRes.details.artifactPath).toBeDefined();

			const artifactContent = await fs.readFile(statusRes.details.artifactPath!, "utf8");
			expect(artifactContent).toContain(sessionId);
			expect(artifactContent).toContain("restorePlan");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});
