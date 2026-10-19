import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "@reverse/coding-agent/config/settings";
import { createTools, ReverseRuntimeSessionTool, type ToolSession, BUILTIN_TOOLS } from "@reverse/coding-agent/tools";
import { BUILTIN_TOOL_NAMES, normalizeToolName } from "@reverse/coding-agent/tools/builtin-names";
import { removeWithRetries } from "@reverse/utils";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import {
	computeSessionStaleState,
	generateRestorePlan,
	ReverseRuntimeSessionStore,
	sanitizeMetadataObject,
	sanitizeSessionString,
	sanitizeUrlString,
	deriveTargetSummary,
	sanitizeRuntimeSessionRecord,
	type RuntimeSessionRecord,
} from "@reverse/coding-agent/reverse-runtime-session";

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

function textOf(result: { content: Array<{ type: string; text?: string } | { type: string }> }): string {
	return result.content
		.map(item => ("text" in item && typeof item.text === "string" ? item.text : ""))
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
			const regRes = await tool.execute("call_reg", {
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
			const listRes = await tool.execute("call_list", { action: "list" });
			const listRendered = textOf(listRes);
			expect(listRendered).not.toContain(rawToken);
			expect(listRendered).not.toContain(rawPassword);
			expect(JSON.stringify(listRes.details)).not.toContain(rawToken);
			expect(JSON.stringify(listRes.details)).not.toContain(rawPassword);

			// 4. Heartbeat update with probe result containing secrets
			const hbRes = await tool.execute("call_hb", {
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
			const statusRes = await tool.execute("call_status", {
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
			const derivedRegRes = await tool.execute("call_derived", {
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
			const regRes = await tool.execute("call_reg", {
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
			const statusRes = await tool.execute("call_status", {
				action: "status",
				session_id: sessionId,
			});
			const statusText = textOf(statusRes);
			expect(statusText).toContain(sessionId);
			expect(statusText).toContain("ACTIVE");
			expect(statusRes.details.restore_plan?.restore_tool).toBe("frida_session");
			expect(statusRes.details.restore_plan?.restore_action).toBe("create");

			// Restore
			const restoreRes = await tool.execute("call_restore", {
				action: "restore",
				session_id: sessionId,
			});
			const restoreText = textOf(restoreRes);
			expect(restoreText).toContain("Deterministic Restore Plan");
			expect(restoreRes.details.restore_plan?.can_restore).toBe(true);
			expect(restoreRes.details.restore_plan?.restore_params.process).toBe("com.example.bank");

			// Unregister
			const unregRes = await tool.execute("call_unreg", {
				action: "unregister",
				session_id: sessionId,
			});
			expect(textOf(unregRes)).toContain("Unregistered runtime session");

			// Verify deleted
			await expect(tool.execute("call_err", { action: "status", session_id: sessionId })).rejects.toThrow(ToolError);
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

			const regRes = await tool.execute("call_reg", {
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

			const restoreRes = await tool.execute("call_restore", {
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

			const regRes = await tool.execute("call_reg", {
				action: "register",
				kind: "ida",
				target: idbPath,
				target_details: { db: idbPath },
			});

			const sessionId = regRes.details.session!.id;

			// Safe metadata probe checks file presence on disk
			const probeRes = await tool.execute("call_probe", {
				action: "status",
				session_id: sessionId,
				probe: true,
			});

			expect(probeRes.details.probe_info?.ok).toBe(true);
			expect(probeRes.details.probe_info?.source).toBe("metadata_check");
			expect(probeRes.details.probe_info?.message).toContain("IDA target file exists on disk");

			const restoreRes = await tool.execute("call_restore", {
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

			const regRes = await tool.execute("call_reg", {
				action: "register",
				kind: "ghidra",
				target: binPath,
				target_details: { path: binPath, project_dir: path.join(tempDir, "ghidra_proj") },
			});

			const sessionId = regRes.details.session!.id;

			const probeRes = await tool.execute("call_probe", {
				action: "status",
				session_id: sessionId,
				probe: true,
			});

			expect(probeRes.details.probe_info?.ok).toBe(true);
			expect(probeRes.details.probe_info?.message).toContain("Ghidra target binary exists on disk");

			const restoreRes = await tool.execute("call_restore", {
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

	it("registers, inspects, and restores a DAP session", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "runt-dap-"));
		const stateRoot = path.join(tempDir, "state");
		try {
			const session = createTestSession(tempDir);
			const tool = new ReverseRuntimeSessionTool(session, { stateRoot });

			const programPath = path.join(tempDir, "target_elf");
			await fs.writeFile(programPath, "ELF EXEC");

			const regRes = await tool.execute("call_reg", {
				action: "register",
				kind: "dap",
				target: programPath,
				target_details: {
					program: programPath,
					adapter: "gdb",
					args: ["--arg1"],
					cwd: tempDir,
				},
				connection: { host: "127.0.0.1", port: 1234 },
			});

			const sessionId = regRes.details.session!.id;
			expect(sessionId).toStartWith("runt_dap_");
			expect(regRes.details.session?.kind).toBe("dap");

			const probeRes = await tool.execute("call_probe", {
				action: "status",
				session_id: sessionId,
				probe: true,
			});

			expect(probeRes.details.probe_info?.ok).toBe(true);
			expect(probeRes.details.probe_info?.message).toContain("DAP target program exists on disk");

			const restoreRes = await tool.execute("call_restore", {
				action: "restore",
				session_id: sessionId,
			});

			expect(restoreRes.details.restore_plan?.kind).toBe("dap");
			expect(restoreRes.details.restore_plan?.restore_tool).toBe("debug");
			expect(restoreRes.details.restore_plan?.restore_action).toBe("launch");
			expect(restoreRes.details.restore_plan?.restore_params.program).toBe(programPath);
			expect(restoreRes.details.restore_plan?.restore_params.adapter).toBe("gdb");
			expect(restoreRes.details.restore_plan?.restore_params.port).toBe(1234);
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
			recovery_hints: {
				restore_tool: "frida_session",
				restore_action: "create",
				restore_params: {},
				instructions: [],
			},
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
			const regRes = await tool.execute("call_reg", {
				action: "register",
				kind: "frida",
				target: "test_process",
				stale_timeout: 10,
			});
			const sessionId = regRes.details.session!.id;

			// Issue heartbeat
			const hbRes = await tool.execute("call_hb", {
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

			const regRes = await tool.execute("call_reg", {
				action: "register",
				kind: "generic",
				target: "custom_runtime",
			});
			const sessionId = regRes.details.session!.id;

			// Caller reports process crashed/failed
			const statusRes = await tool.execute("call_status", {
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

			await tool.execute("call_reg1", {
				action: "register",
				kind: "frida",
				target: "target1",
				workflow_id: "wf_rw_111",
			});

			await tool.execute("call_reg2", {
				action: "register",
				kind: "browser",
				target: "https://example.com",
				workflow_id: "wf_rw_222",
			});

			const listWf1 = await tool.execute("call_list1", {
				action: "list",
				workflow_id: "wf_rw_111",
			});
			expect(listWf1.details.sessions?.length).toBe(1);
			expect(listWf1.details.sessions?.[0].workflow_id).toBe("wf_rw_111");

			const listAll = await tool.execute("call_list2", { action: "list" });
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

			const regRes = await tool.execute("call_reg", {
				action: "register",
				kind: "ida",
				target: "test.i64",
			});
			const sessionId = regRes.details.session!.id;

			const statusRes = await tool.execute("call_status", {
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
// ============================================================================
// 6. Runtime Closure: DAP Sync, Restore Planner Hints, Events & Reachability
// ============================================================================

describe("runtime session closure: DAP sync, restore planner hints, events query, and reachability probe", () => {
	it("honors explicit recovery_hints.restore_tool and params preserving Browser tab_name", () => {
		// 1. Browser reverse session with explicit recovery hints
		const browserReverseRecord: RuntimeSessionRecord = {
			id: "runt_browser_rev_01",
			kind: "browser",
			status: "active",
			target_summary: "Bank Portal",
			target_details: { tab_name: "bank_tab", url: "https://bank.corp" },
			connection: {},
			recovery_hints: {
				restore_tool: "browser_reverse_session",
				restore_action: "open",
				restore_params: { tab_name: "bank_tab", url: "https://bank.corp" },
				instructions: ['Reopen browser tab "bank_tab" with url "https://bank.corp"'],
			},
			created_at: new Date().toISOString(),
			updated_at: new Date().toISOString(),
			last_heartbeat_at: new Date().toISOString(),
			heartbeat_count: 1,
			stale_timeout_sec: 300,
			status_source: "caller_reported",
		};

		const plan1 = generateRestorePlan(browserReverseRecord);
		expect(plan1.restore_tool).toBe("browser_reverse_session");
		expect(plan1.restore_action).toBe("open");
		expect(plan1.restore_params.tab_name).toBe("bank_tab");
		expect(plan1.restore_params.url).toBe("https://bank.corp");
		expect(plan1.can_restore).toBe(true);

		// 2. Browser reverse session with tab_name in target_details but no explicit hints
		const browserTabRecord: RuntimeSessionRecord = {
			id: "runt_browser_rev_02",
			kind: "browser",
			status: "idle",
			target_summary: "Portal",
			target_details: { tab_name: "portal_tab", url: "https://portal.corp" },
			connection: {},
			recovery_hints: { restore_tool: "", restore_action: "", restore_params: {}, instructions: [] },
			created_at: new Date().toISOString(),
			updated_at: new Date().toISOString(),
			last_heartbeat_at: new Date().toISOString(),
			heartbeat_count: 1,
			stale_timeout_sec: 300,
			status_source: "caller_reported",
		};

		const plan2 = generateRestorePlan(browserTabRecord);
		expect(plan2.restore_tool).toBe("browser_reverse_session");
		expect(plan2.restore_params.tab_name).toBe("portal_tab");

		// 3. Frida session with explicit custom recovery hints
		const fridaRecord: RuntimeSessionRecord = {
			id: "runt_frida_custom",
			kind: "frida",
			status: "active",
			target_summary: "Custom Target",
			target_details: { process: "target.bin" },
			connection: {},
			recovery_hints: {
				restore_tool: "custom_frida_runner",
				restore_action: "spawn",
				restore_params: { spawn: "com.custom.app", script_path: "agent.js" },
				instructions: [],
			},
			created_at: new Date().toISOString(),
			updated_at: new Date().toISOString(),
			last_heartbeat_at: new Date().toISOString(),
			heartbeat_count: 1,
			stale_timeout_sec: 300,
			status_source: "caller_reported",
		};

		const plan3 = generateRestorePlan(fridaRecord);
		expect(plan3.restore_tool).toBe("custom_frida_runner");
		expect(plan3.restore_action).toBe("spawn");
		expect(plan3.restore_params.spawn).toBe("com.custom.app");
		expect(plan3.restore_params.script_path).toBe("agent.js");

		// 4. DAP session with explicit attach recovery hints
		const dapRecord: RuntimeSessionRecord = {
			id: "debug-42",
			kind: "dap",
			status: "active",
			target_summary: "PID 5555",
			target_details: { adapter: "lldb-dap", pid: 5555 },
			connection: { adapter: "lldb-dap" },
			recovery_hints: {
				restore_tool: "debug",
				restore_action: "attach",
				restore_params: { adapter: "lldb-dap", pid: 5555 },
				instructions: [],
			},
			created_at: new Date().toISOString(),
			updated_at: new Date().toISOString(),
			last_heartbeat_at: new Date().toISOString(),
			heartbeat_count: 1,
			stale_timeout_sec: 300,
			status_source: "caller_reported",
		};

		const plan4 = generateRestorePlan(dapRecord);
		expect(plan4.restore_tool).toBe("debug");
		expect(plan4.restore_action).toBe("attach");
		expect(plan4.restore_params.pid).toBe(5555);
		expect(plan4.can_restore).toBe(true);
	});

	it("queries read-only session events from registry store metadata with filters", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "runt-events-"));
		const stateRoot = path.join(tempDir, "state");
		try {
			const session = createTestSession(tempDir);
			const tool = new ReverseRuntimeSessionTool(session, { stateRoot });
			const store = ReverseRuntimeSessionStore.forSession(tempDir, stateRoot);

			const eventsData = [
				{ seq: 1, kind: "lifecycle", timestamp: "2026-10-18T10:00:00.000Z", payload: "Session initialized" },
				{ seq: 2, kind: "stdout", timestamp: "2026-10-18T10:00:01.000Z", payload: "Loading modules..." },
				{ seq: 3, kind: "breakpoint", timestamp: "2026-10-18T10:00:02.000Z", payload: "Hit bp at main.c:42" },
				{ seq: 4, kind: "stdout", timestamp: "2026-10-18T10:00:03.000Z", payload: "Done" },
			];

			const record: RuntimeSessionRecord = {
				id: "debug-events-test",
				kind: "dap",
				status: "active",
				target_summary: "my_program",
				target_details: { adapter: "lldb-dap", program: "./my_program" },
				connection: { adapter: "lldb-dap" },
				recovery_hints: {
					restore_tool: "debug",
					restore_action: "launch",
					restore_params: { program: "./my_program" },
					instructions: [],
				},
				created_at: "2026-10-18T10:00:00.000Z",
				updated_at: "2026-10-18T10:00:03.000Z",
				last_heartbeat_at: "2026-10-18T10:00:03.000Z",
				heartbeat_count: 4,
				stale_timeout_sec: 300,
				status_source: "caller_reported",
				metadata: {
					eventsCount: 4,
					recent_events: eventsData,
				},
			};

			await store.save(record);

			// Query all events
			const allRes = await tool.execute("call_events", {
				action: "events",
				session_id: "debug-events-test",
			});
			expect(allRes.details.action).toBe("events");
			expect(allRes.details.events?.length).toBe(4);
			expect(allRes.details.total).toBe(4);
			const allText = textOf(allRes);
			expect(allText).toContain("showing 4 of 4");
			expect(allText).toContain("Hit bp at main.c:42");

			// Query with since_seq filter
			const sinceRes = await tool.execute("call_events", {
				action: "events",
				session_id: "debug-events-test",
				since_seq: 2,
			});
			expect(sinceRes.details.events?.length).toBe(2);
			const sinceSeqs = sinceRes.details.events?.map(e =>
				e && typeof e === "object" && "seq" in e && typeof e.seq === "number" ? e.seq : undefined,
			);
			expect(sinceSeqs).toEqual([3, 4]);

			// Query with event_kind filter
			const kindRes = await tool.execute("call_events", {
				action: "events",
				session_id: "debug-events-test",
				event_kind: "stdout",
			});
			expect(kindRes.details.events?.length).toBe(2);
			const kinds = kindRes.details.events?.map(e =>
				e && typeof e === "object" && "kind" in e && typeof e.kind === "string" ? e.kind : undefined,
			);
			expect(kinds).toEqual(["stdout", "stdout"]);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("distinguishes empirical reachability from stored heartbeat in status probe without spawning", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "runt-reach-"));
		const stateRoot = path.join(tempDir, "state");
		try {
			const session = createTestSession(tempDir);
			const tool = new ReverseRuntimeSessionTool(session, { stateRoot });
			const store = ReverseRuntimeSessionStore.forSession(tempDir, stateRoot);

			// 1. Session with active current process PID (empirically reachable)
			const livePid = process.pid;
			const liveRecord: RuntimeSessionRecord = {
				id: "runt_frida_live",
				kind: "frida",
				status: "active",
				target_summary: `PID ${livePid}`,
				target_details: { pid: livePid, process: "node" },
				connection: {},
				recovery_hints: {
					restore_tool: "frida_session",
					restore_action: "attach",
					restore_params: { pid: livePid },
					instructions: [],
				},
				created_at: "2026-10-18T00:00:00.000Z",
				updated_at: "2026-10-18T00:00:00.000Z",
				last_heartbeat_at: "2026-10-18T00:00:00.000Z",
				heartbeat_count: 1,
				stale_timeout_sec: 300,
				status_source: "caller_reported",
			};
			await store.save(liveRecord);

			const liveStatus = await tool.execute("call_status", {
				action: "status",
				session_id: "runt_frida_live",
				probe: true,
			});
			expect(liveStatus.details.probe_info?.ok).toBe(true);
			expect(liveStatus.details.probe_info?.reachable).toBe(true);
			expect(liveStatus.details.probe_info?.message).toContain("is reachable and running");

			// 2. Session with a non-existent PID (reachability failed despite historical heartbeat)
			const deadPid = 99999999;
			const deadRecord: RuntimeSessionRecord = {
				id: "runt_frida_dead",
				kind: "frida",
				status: "active",
				target_summary: `PID ${deadPid}`,
				target_details: { pid: deadPid },
				connection: {},
				recovery_hints: {
					restore_tool: "frida_session",
					restore_action: "attach",
					restore_params: { pid: deadPid },
					instructions: [],
				},
				created_at: "2026-10-18T00:00:00.000Z",
				updated_at: "2026-10-18T00:00:00.000Z",
				last_heartbeat_at: "2026-10-18T00:00:00.000Z",
				heartbeat_count: 1,
				stale_timeout_sec: 300,
				status_source: "caller_reported",
			};
			await store.save(deadRecord);

			const deadStatus = await tool.execute("call_status", {
				action: "status",
				session_id: "runt_frida_dead",
				probe: true,
			});
			expect(deadStatus.details.probe_info?.ok).toBe(false);
			expect(deadStatus.details.probe_info?.reachable).toBe(false);
			expect(deadStatus.details.probe_info?.message).toContain("is not running");
			expect(deadStatus.details.probe_info?.message).toContain("Stored heartbeat was at");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("DAP sessions are visible in registry with filter_kind and deterministic restore plan", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "runt-dap-reg-"));
		const stateRoot = path.join(tempDir, "state");
		try {
			const session = createTestSession(tempDir);
			const tool = new ReverseRuntimeSessionTool(session, { stateRoot });
			const store = ReverseRuntimeSessionStore.forSession(tempDir, stateRoot);

			const targetProgram = path.join(tempDir, "app_bin");
			await fs.writeFile(targetProgram, "ELF BINARY MOCK");

			const dapSessionId = "debug-session-1";
			const dapRecord: RuntimeSessionRecord = {
				id: dapSessionId,
				name: "DAP Debug lldb-dap (app_bin)",
				kind: "dap",
				status: "active",
				target_summary: targetProgram,
				target_details: { adapter: "lldb-dap", program: targetProgram, cwd: tempDir },
				connection: { adapter: "lldb-dap", cwd: tempDir },
				recovery_hints: {
					restore_tool: "debug",
					restore_action: "launch",
					restore_params: { adapter: "lldb-dap", program: targetProgram },
					instructions: [],
				},
				created_at: new Date().toISOString(),
				updated_at: new Date().toISOString(),
				last_heartbeat_at: new Date().toISOString(),
				heartbeat_count: 2,
				stale_timeout_sec: 300,
				status_source: "caller_reported",
				metadata: {
					adapter: "lldb-dap",
					dapStatus: "stopped",
					eventsCount: 2,
					recent_events: [
						{ seq: 1, kind: "lifecycle", timestamp: "2026-10-18T12:00:00.000Z", payload: "started" },
						{ seq: 2, kind: "breakpoint", timestamp: "2026-10-18T12:00:01.000Z", payload: "hit" },
					],
				},
			};

			await store.save(dapRecord);

			// 1. List action with filter_kind: "dap"
			const listRes = await tool.execute("call_list", {
				action: "list",
				filter_kind: "dap",
			});
			expect(listRes.details.sessions?.length).toBe(1);
			expect(listRes.details.sessions?.[0].id).toBe(dapSessionId);
			expect(textOf(listRes)).toContain("debug-session-1");
			expect(textOf(listRes)).toContain("dap");

			// 2. Status action checks file presence and restore plan
			const statusRes = await tool.execute("call_status", {
				action: "status",
				session_id: dapSessionId,
				probe: true,
			});
			expect(statusRes.details.probe_info?.ok).toBe(true);
			expect(statusRes.details.probe_info?.reachable).toBe(true);
			expect(statusRes.details.restore_plan?.restore_tool).toBe("debug");
			expect(statusRes.details.restore_plan?.restore_action).toBe("launch");
			expect(statusRes.details.restore_plan?.can_restore).toBe(true);

			// 3. Events action queries stored events
			const eventsRes = await tool.execute("call_events", {
				action: "events",
				session_id: dapSessionId,
			});
			expect(eventsRes.details.events?.length).toBe(2);
			expect(textOf(eventsRes)).toContain("showing 2 of 2");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});
