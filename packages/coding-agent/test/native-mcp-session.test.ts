import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { NativeMcpSessionTool, type NativeMcpSessionResult } from "../src/tools/native-mcp-session";
import type { ToolSession } from "../src/tools/index";
import { MCPManager } from "../src/mcp/manager";
import {
	getGhidraMcpInstallDir,
	getServiceVenvDir,
	getVenvBinDir,
	getVenvBinaryPath,
	getVenvPythonPath,
} from "../src/extensibility/native-mcp-install";
import { removeSyncWithRetries } from "@reverse/utils";
import type { AgentToolResult } from "@reverse/agent";

const FIXTURE_PATH = path.join(import.meta.dir, "fixtures", "mock-native-mcp.ts");

function requireDetails(res: AgentToolResult<NativeMcpSessionResult>): NativeMcpSessionResult {
	expect(res.details).toBeDefined();
	if (!res.details) {
		throw new Error("Expected res.details to be defined");
	}
	return res.details;
}

describe("NativeMcpSessionTool", () => {
	let tempDir: string;
	let agentDir: string;
	let manager: MCPManager;
	const origPath = process.env.PATH ?? "";

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "native-mcp-test-"));
		agentDir = path.join(tempDir, "agent");
		fs.mkdirSync(agentDir, { recursive: true });
		manager = new MCPManager(tempDir);
	});

	afterEach(async () => {
		await manager.disconnectAll();
		process.env.PATH = origPath;
		delete process.env.MOCK_NATIVE_MODE;
		delete process.env.MOCK_TARGET_PATH;
		delete process.env.MOCK_DEBUGGEE_DEAD;
		delete process.env.MOCK_BOOTSTRAP_FAIL;
		delete process.env.MOCK_GHIDRA_SHA256;
		delete process.env.MOCK_R2_FAIL;
		removeSyncWithRetries(tempDir);
	});

	function createMockSession(customKey?: object, mcpMgr: MCPManager | null = manager): ToolSession {
		const key = customKey ?? {};
		return {
			cwd: tempDir,
			settings: {
				getAgentDir: () => agentDir,
			},
			sessionManager: key,
			mcpManager: mcpMgr ?? undefined,
		} as unknown as ToolSession;
	}

	function setupMockServiceInstalled(service: "x64dbg" | "ghidra"): void {
		const venvDir = getServiceVenvDir(service, agentDir);
		const binDir = getVenvBinDir(venvDir);
		fs.mkdirSync(binDir, { recursive: true });
		const binName = service === "x64dbg" ? "x64dbg-automate-mcp" : "ghidra-mcp";
		const binPath = getVenvBinaryPath(venvDir, binName);
		fs.copyFileSync(FIXTURE_PATH, binPath);
		fs.chmodSync(binPath, 0o755);
		const venvPy = getVenvPythonPath(venvDir);
		if (!fs.existsSync(venvPy)) {
			fs.copyFileSync(FIXTURE_PATH, venvPy);
			fs.chmodSync(venvPy, 0o755);
		}
		if (service === "ghidra") {
			const ghidraDir = getGhidraMcpInstallDir(agentDir);
			const extDir = path.join(ghidraDir, "extension");
			fs.mkdirSync(extDir, { recursive: true });
			fs.writeFileSync(path.join(extDir, "GhidraMCP.jar"), "PK\x03\x04mockjar");
		}
	}

	function setupMockRadare2Installed(): void {
		const binDir = path.join(tempDir, "mock-bin");
		fs.mkdirSync(binDir, { recursive: true });
		const r2 = path.join(binDir, process.platform === "win32" ? "r2.cmd" : "r2");
		const r2pm = path.join(binDir, process.platform === "win32" ? "r2pm.cmd" : "r2pm");
		const r2mcp = path.join(binDir, process.platform === "win32" ? "r2mcp.cmd" : "r2mcp");
		fs.copyFileSync(FIXTURE_PATH, r2);
		fs.copyFileSync(FIXTURE_PATH, r2pm);
		fs.copyFileSync(FIXTURE_PATH, r2mcp);
		fs.chmodSync(r2, 0o755);
		fs.chmodSync(r2pm, 0o755);
		fs.chmodSync(r2mcp, 0o755);
		process.env.PATH = `${binDir}${path.delimiter}${origPath}`;
	}

	describe("Address mapping ('locate')", () => {
		it("performs exact 64-bit integer arithmetic from dynamic VA to static VA", async () => {
			const session = createMockSession();
			const tool = new NativeMcpSessionTool(session);

			const result = await tool.execute("call-1", {
				action: "locate",
				runtime_address: "0x7FF6A0001050",
				module_base: "0x7FF6A0000000",
				static_base: "0x140000000",
				module_name: "target.exe",
			});

			const details = requireDetails(result);
			expect(details.action).toBe("locate");
			const mapping = details.mapping!;
			expect(mapping.source).toBe("supplied");
			expect(mapping.computation).toBe("arithmetic");
			expect(mapping.evidence_verified).toBe(false);
			expect(mapping.runtime_address).toBe("0x7FF6A0001050");
			expect(mapping.module_base).toBe("0x7FF6A0000000");
			expect(mapping.module_offset).toBe("0x1050");
			expect(mapping.rva).toBe("0x1050");
			expect(mapping.static_base).toBe("0x140000000");
			expect(mapping.static_address).toBe("0x140001050");
			expect(mapping.module_name).toBe("target.exe");
			expect(mapping.evidence_locator).toBe("target.exe+0x1050 -> static:0x140001050");
		});

		it("handles mapping without static_base as pure RVA offset calculation", async () => {
			const session = createMockSession();
			const tool = new NativeMcpSessionTool(session);

			const result = await tool.execute("call-2", {
				action: "locate",
				runtime_address: "0x401500",
				module_base: "0x400000",
			});

			const details = requireDetails(result);
			const mapping = details.mapping!;
			expect(mapping.runtime_address).toBe("0x401500");
			expect(mapping.module_base).toBe("0x400000");
			expect(mapping.rva).toBe("0x1500");
			expect(mapping.static_base).toBeUndefined();
			expect(mapping.static_address).toBeUndefined();
			expect(mapping.evidence_locator).toBe("module+0x1500");
		});

		it("rejects runtime_address smaller than module_base", async () => {
			const session = createMockSession();
			const tool = new NativeMcpSessionTool(session);

			await expect(
				tool.execute("call-3", {
					action: "locate",
					runtime_address: "0x1000",
					module_base: "0x2000",
				}),
			).rejects.toThrow(/cannot be smaller than module_base/);
		});

		it("rejects signed or negative address strings", async () => {
			const session = createMockSession();
			const tool = new NativeMcpSessionTool(session);

			await expect(
				tool.execute("call-4", {
					action: "locate",
					runtime_address: "-0x1000",
					module_base: "0x2000",
				}),
			).rejects.toThrow(/negative or signed address/);
		});

		it("rejects malformed address expressions", async () => {
			const session = createMockSession();
			const tool = new NativeMcpSessionTool(session);

			await expect(
				tool.execute("call-5", {
					action: "locate",
					runtime_address: "not_a_hex_number",
					module_base: "0x2000",
				}),
			).rejects.toThrow(/must be a valid non-negative hexadecimal or numeric address/);
		});
	});

	describe("Dependency gating & safety", () => {
		it("fails honestly when service dependencies are missing, routing to setup", async () => {
			const session = createMockSession();
			const tool = new NativeMcpSessionTool(session);

			await expect(
				tool.execute("call-6", {
					action: "connect",
					service: "x64dbg",
					target: "sample.exe",
				}),
			).rejects.toThrow(/Native MCP service "x64dbg" is not installed.*reverse setup reverse x64dbg-mcp/);
		});

		it("enforces session isolation by requiring an active session MCPManager", async () => {
			const sessionWithoutManager = createMockSession(undefined, null);
			const tool = new NativeMcpSessionTool(sessionWithoutManager);

			await expect(
				tool.execute("call-7", {
					action: "connect",
					service: "radare2",
				}),
			).rejects.toThrow();
		});

		it("isolates owned sessions across distinct ToolSessions", async () => {
			setupMockServiceInstalled("x64dbg");

			const key1 = { id: "session-1" };
			const key2 = { id: "session-2" };

			const session1 = createMockSession(key1);
			const session2 = createMockSession(key2);

			const tool1 = new NativeMcpSessionTool(session1);
			const tool2 = new NativeMcpSessionTool(session2);

			const samplePath = path.join(tempDir, "isolation_target.exe");
			fs.writeFileSync(samplePath, "MZ\x90\x00");

			process.env.MOCK_NATIVE_MODE = "x64dbg";
			process.env.MOCK_TARGET_PATH = samplePath;

			// tool1 成功建立真实连接
			const connectRes1 = await tool1.execute("call-iso-1", {
				action: "connect",
				service: "x64dbg",
				target: samplePath,
			});
			const realSessionId = requireDetails(connectRes1).session!.sessionId;

			// tool2 查询 tool1 的真实 sessionId 时被严格拦截
			await expect(
				tool2.execute("call-iso-2", {
					action: "status",
					session_id: realSessionId,
				}),
			).rejects.toThrow(/not found in this session's active native sessions/);

			// tool2 尝试断开 tool1 的真实 sessionId 时被严格拦截
			await expect(
				tool2.execute("call-iso-3", {
					action: "disconnect",
					session_id: realSessionId,
				}),
			).rejects.toThrow(/not found in active native sessions/);

			// tool1 可以正常查询与断开自己的真实会话
			const statusRes1 = await tool1.execute("call-iso-4", {
				action: "status",
				session_id: realSessionId,
			});
			expect(requireDetails(statusRes1).session?.sessionId).toBe(realSessionId);

			const disconnectRes1 = await tool1.execute("call-iso-5", {
				action: "disconnect",
				session_id: realSessionId,
			});
			expect(requireDetails(disconnectRes1).action).toBe("disconnect");
		});
	});

	describe("x64dbg live lifecycle", () => {
		it("connects mock x64dbg, mounts tools, and detects debuggee presence truthfully", async () => {
			setupMockServiceInstalled("x64dbg");

			const session = createMockSession();
			const tool = new NativeMcpSessionTool(session);

			const samplePath = path.join(tempDir, "test_binary.exe");
			fs.writeFileSync(samplePath, "MZ\x90\x00");

			process.env.MOCK_NATIVE_MODE = "x64dbg";
			process.env.MOCK_TARGET_PATH = samplePath;

			const connectRes = await tool.execute("call-10", {
				action: "connect",
				service: "x64dbg",
				target: samplePath,
			});

			const connectDetails = requireDetails(connectRes);
			expect(connectDetails.action).toBe("connect");
			const owned = connectDetails.session!;
			expect(owned.service).toBe("x64dbg");
			expect(owned.status).toBe("connected");
			expect(owned.targetMatched).toBe(true);
			expect(owned.discoveredTools).toContain("start_session");
			expect(owned.discoveredTools).toContain("get_debugger_status");
			expect(owned.discoveredTools).toContain("get_memory_map");

			// 检查 status
			const statusRes = await tool.execute("call-11", {
				action: "status",
				session_id: owned.sessionId,
			});
			const statusDetails = requireDetails(statusRes);
			expect(statusDetails.session?.sessionId).toBe(owned.sessionId);
			expect(statusDetails.session?.targetMatched).toBe(true);

			// 执行断开
			const disconnectRes = await tool.execute("call-12", {
				action: "disconnect",
				session_id: owned.sessionId,
			});
			const disconnectDetails = requireDetails(disconnectRes);
			expect(disconnectDetails.action).toBe("disconnect");
			expect(disconnectDetails.session?.status).toBe("disconnected");
		});

		it("reports targetMatched: false when x64dbg reports no debuggee attached", async () => {
			setupMockServiceInstalled("x64dbg");

			const session = createMockSession();
			const tool = new NativeMcpSessionTool(session);

			process.env.MOCK_NATIVE_MODE = "x64dbg";
			process.env.MOCK_DEBUGGEE_DEAD = "1"; // Has debuggee: False

			const connectRes = await tool.execute("call-13", {
				action: "connect",
				service: "x64dbg",
				target: "dummy.exe",
			});

			const connectDetails = requireDetails(connectRes);
			expect(connectDetails.session?.targetMatched).toBe(false);

			const disconnectRes = await tool.execute("call-14", {
				action: "disconnect",
				session_id: connectDetails.session!.sessionId,
			});
			requireDetails(disconnectRes);
		});

		it("aborts and cleans up owned connection when x64dbg bootstrap returns an error", async () => {
			setupMockServiceInstalled("x64dbg");

			const session = createMockSession();
			const tool = new NativeMcpSessionTool(session);

			process.env.MOCK_NATIVE_MODE = "x64dbg";
			process.env.MOCK_BOOTSTRAP_FAIL = "1"; // returns Error: Failed to launch

			await expect(
				tool.execute("call-15", {
					action: "connect",
					service: "x64dbg",
					target: "nonexistent.exe",
				}),
			).rejects.toThrow(/Failed to launch executable/);

			const listRes = await tool.execute("call-16", { action: "list" });
			const listDetails = requireDetails(listRes);
			expect(listDetails.sessions?.length).toBe(0);
		});
	});

	describe("Ghidra live lifecycle & hash verification", () => {
		it("connects Ghidra headless session and validates matching sample SHA256", async () => {
			setupMockServiceInstalled("ghidra");

			const session = createMockSession();
			const tool = new NativeMcpSessionTool(session);

			const samplePath = path.join(tempDir, "ghidra_target.bin");
			const sampleContent = "ELF_MOCK_GHIDRA_TEST";
			fs.writeFileSync(samplePath, sampleContent);
			const expectedHash = crypto.createHash("sha256").update(sampleContent).digest("hex");

			process.env.MOCK_NATIVE_MODE = "ghidra";
			process.env.MOCK_TARGET_PATH = samplePath;
			process.env.MOCK_GHIDRA_SHA256 = expectedHash;

			const connectRes = await tool.execute("call-ghidra-1", {
				action: "connect",
				service: "ghidra",
				target: samplePath,
			});

			const details = requireDetails(connectRes);
			expect(details.action).toBe("connect");
			const owned = details.session!;
			expect(owned.service).toBe("ghidra");
			expect(owned.status).toBe("connected");
			expect(owned.targetMatched).toBe(true);
			expect(owned.verifiedTarget?.sha256).toBe(expectedHash);
			expect(owned.discoveredTools).toContain("get_program_info");
			expect(owned.discoveredTools).toContain("list_functions");

			// 安全断开并释放工程锁
			const disconnectRes = await tool.execute("call-ghidra-2", {
				action: "disconnect",
				session_id: owned.sessionId,
			});
			expect(requireDetails(disconnectRes).session?.status).toBe("disconnected");
		});

		it("aborts and unmounts connection when Ghidra project has a hash mismatch", async () => {
			setupMockServiceInstalled("ghidra");

			const session = createMockSession();
			const tool = new NativeMcpSessionTool(session);

			const samplePath = path.join(tempDir, "ghidra_target2.bin");
			fs.writeFileSync(samplePath, "BINARY_V2_DATA");

			process.env.MOCK_NATIVE_MODE = "ghidra";
			process.env.MOCK_TARGET_PATH = samplePath;
			process.env.MOCK_GHIDRA_SHA256 = "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff";

			await expect(
				tool.execute("call-ghidra-3", {
					action: "connect",
					service: "ghidra",
					target: samplePath,
				}),
			).rejects.toThrow(/Target hash mismatch in Ghidra project/);

			const listRes = await tool.execute("call-ghidra-4", { action: "list" });
			expect(requireDetails(listRes).sessions?.length).toBe(0);
		});
	});

	describe("radare2 live lifecycle & error handling", () => {
		it("connects radare2 r2mcp session and executes open_file + show_info", async () => {
			setupMockRadare2Installed();

			const session = createMockSession();
			const tool = new NativeMcpSessionTool(session);

			const samplePath = path.join(tempDir, "r2_target.bin");
			fs.writeFileSync(samplePath, "\x7fELF\x02\x01\x01\x00");

			process.env.MOCK_NATIVE_MODE = "radare2";
			delete process.env.MOCK_R2_FAIL;

			const connectRes = await tool.execute("call-r2-1", {
				action: "connect",
				service: "radare2",
				target: samplePath,
			});

			const details = requireDetails(connectRes);
			expect(details.action).toBe("connect");
			const owned = details.session!;
			expect(owned.service).toBe("radare2");
			expect(owned.status).toBe("connected");
			expect(owned.targetMatched).toBe(true);
			expect(owned.discoveredTools).toContain("open_file");
			expect(owned.discoveredTools).toContain("show_info");

			// 断开
			const disconnectRes = await tool.execute("call-r2-2", {
				action: "disconnect",
				session_id: owned.sessionId,
			});
			expect(requireDetails(disconnectRes).session?.status).toBe("disconnected");
		});

		it("aborts and unmounts connection when radare2 open_file returns an error", async () => {
			setupMockRadare2Installed();

			const session = createMockSession();
			const tool = new NativeMcpSessionTool(session);

			process.env.MOCK_NATIVE_MODE = "radare2";
			process.env.MOCK_R2_FAIL = "1";

			await expect(
				tool.execute("call-r2-3", {
					action: "connect",
					service: "radare2",
					target: "corrupt.bin",
				}),
			).rejects.toThrow(/Tool 'open_file' reported error: Failed to open file/);
			const listRes = await tool.execute("call-r2-4", { action: "list" });
			expect(requireDetails(listRes).sessions?.length).toBe(0);
		});
	});
});
