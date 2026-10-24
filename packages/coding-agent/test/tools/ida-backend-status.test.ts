import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { getIdaBackendStatus } from "@reverse/coding-agent/ida/install";
import { R2InspectTool, ReverseCapabilityTool, type ToolSession } from "@reverse/coding-agent/tools";
import { Settings } from "@reverse/coding-agent/config/settings";
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

function createSyntheticArm64Elf(): Buffer {
	const buf = Buffer.alloc(1024);
	buf[0] = 0x7f;
	buf[1] = 0x45;
	buf[2] = 0x4c;
	buf[3] = 0x46;
	buf[4] = 2; // ELFCLASS64
	buf[5] = 1; // ELFDATA2LSB
	buf[6] = 1; // EV_CURRENT
	buf.writeUInt16LE(3, 16); // ET_DYN
	buf.writeUInt16LE(183, 18); // EM_AARCH64 (183)
	buf.writeUInt32LE(1, 20);
	buf.write("JNI_OnLoad\0", 64, "utf8");
	return buf;
}

describe("IDA multi-backend readiness and capability integration", () => {
	it("distinguishes IDA GUI binary presence from idalib readiness", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ida-backend-test-"));
		try {
			const guiDir = path.join(tempDir, "ida-gui-only");
			await fs.mkdir(guiDir, { recursive: true });
			const idaBin = process.platform === "win32" ? "ida64.exe" : "ida64";
			await fs.writeFile(path.join(guiDir, idaBin), "");

			// Subtest 1: GUI only
			const statusGuiOnly = getIdaBackendStatus({
				platform: process.platform,
				installDir: guiDir,
				which: () => null,
			});
			expect(statusGuiOnly.guiAvailable).toBe(true);
			expect(statusGuiOnly.idalibAvailable).toBe(false);
			expect(statusGuiOnly.localDatabaseRecognized).toBe(true);
			expect(statusGuiOnly.localDatabaseBackendAvailable).toBe(false);
			expect(statusGuiOnly.localDatabaseSupported).toBe(false);
			expect(statusGuiOnly.mcpBridgeConfigured).toBe(false);
			expect(statusGuiOnly.mcpBridgeConnected).toBe(false);
			expect(statusGuiOnly.bridgeAbsentReason).toContain("ida-mcp");

			// Subtest 2: GUI + idalib
			const idalibFile =
				process.platform === "darwin"
					? "libidalib.dylib"
					: process.platform === "win32"
						? "idalib.dll"
						: "libidalib.so";
			await fs.writeFile(path.join(guiDir, idalibFile), "");

			const statusWithIdalib = getIdaBackendStatus({
				platform: process.platform,
				installDir: guiDir,
				which: () => null,
			});
			expect(statusWithIdalib.guiAvailable).toBe(true);
			expect(statusWithIdalib.idalibAvailable).toBe(true);
			expect(statusWithIdalib.localDatabaseRecognized).toBe(true);
			expect(statusWithIdalib.localDatabaseBackendAvailable).toBe(true);
			expect(statusWithIdalib.localDatabaseSupported).toBe(true);

			// Subtest 3: idalib only (no GUI binary in directory)
			const idalibOnlyDir = path.join(tempDir, "idalib-only");
			await fs.mkdir(idalibOnlyDir, { recursive: true });
			await fs.writeFile(path.join(idalibOnlyDir, idalibFile), "");
			const statusIdalibOnly = getIdaBackendStatus({
				platform: process.platform,
				installDir: idalibOnlyDir,
				which: () => null,
			});
			expect(statusIdalibOnly.guiAvailable).toBe(false);
			expect(statusIdalibOnly.idalibAvailable).toBe(true);
			expect(statusIdalibOnly.localDatabaseBackendAvailable).toBe(true);

			// Subtest 4: Neither
			const statusNeither = getIdaBackendStatus({
				platform: process.platform,
				installDir: path.join(tempDir, "missing"),
				which: () => null,
			});
			expect(statusNeither.guiAvailable).toBe(false);
			expect(statusNeither.idalibAvailable).toBe(false);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("preserves IDA presence when MCP bridge is absent", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ida-bridge-test-"));
		try {
			const installDir = path.join(tempDir, "ida-install");
			await fs.mkdir(installDir, { recursive: true });
			const idaBin = process.platform === "win32" ? "ida64.exe" : "ida64";
			await fs.writeFile(path.join(installDir, idaBin), "");

			const status = getIdaBackendStatus({
				platform: process.platform,
				installDir,
				which: () => null,
				mcpManager: {
					getConnectionStatus: () => "disconnected",
					getAllServerNames: () => [],
				},
			});
			// Bridge is unconfigured, but GUI is present: whole IDA is NOT marked absent
			expect(status.mcpBridgeConfigured).toBe(false);
			expect(status.mcpBridgeConnected).toBe(false);
			expect(status.guiAvailable).toBe(true);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("reports idaBackends in reverse_capability resolve and status details", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ida-cap-test-"));
		try {
			const tool = new ReverseCapabilityTool(createTestSession(tempDir));

			// 1. Resolve action
			const resolveRes = await tool.execute("call-1", { action: "resolve" });
			expect(resolveRes.details?.idaBackends).toBeDefined();
			expect(resolveRes.details?.idaBackends?.localDatabaseRecognized).toBe(true);

			// 2. Status action
			const statusRes = await tool.execute("call-2", { action: "status" });
			expect(statusRes.details?.idaBackends).toBeDefined();
			expect(statusRes.details?.idaBackends?.localDatabaseRecognized).toBe(true);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("executes bounded ARM64 ELF disassembly with explicit protocol fixture limitations", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "arm64-fixture-test-"));
		try {
			const elfPath = path.join(tempDir, "libnative-arm64.so");
			await fs.writeFile(elfPath, createSyntheticArm64Elf());

			const session = createTestSession(tempDir);

			// 1. Without external r2: returns missing_dependency with honest fallback
			const noR2Tool = new R2InspectTool(session, { which: () => null });
			const missingRes = await noR2Tool.execute("call-1", {
				action: "disasm",
				path: elfPath,
				symbol: "JNI_OnLoad",
			});
			expect(missingRes.details?.status).toBe("missing_dependency");
			expect(missingRes.details?.fallback?.suggestedFallback).toContain("objdump");

			// 2. With bounded ARM64 disassembly runner (protocol fixture)
			const arm64Instructions = [
				{ offset: 4198400, disasm: "stp x29, x30, [sp, -16]!", opcode: "stp", bytes: "fd7bbfa9", type: "push" },
				{ offset: 4198404, disasm: "mov x29, sp", opcode: "mov", bytes: "fd030091", type: "mov" },
				{ offset: 4198408, disasm: "mov w0, 0x10006", opcode: "mov", bytes: "00008052", type: "mov" },
				{ offset: 4198412, disasm: "ldp x29, x30, [sp], 16", opcode: "ldp", bytes: "fd7bc1a8", type: "pop" },
				{ offset: 4198416, disasm: "ret", opcode: "ret", bytes: "c0035fd6", type: "ret" },
			];
			const fixtureTool = new R2InspectTool(session, {
				which: () => "/usr/local/bin/r2",
				runner: async () => ({
					stdout: JSON.stringify(arm64Instructions),
					stderr: "",
					exitCode: 0,
					outputBytes: 250,
					truncated: false,
					timedOut: false,
					killedOnOverflow: false,
				}),
			});

			const disasmRes = await fixtureTool.execute("call-2", {
				action: "disasm",
				path: elfPath,
				symbol: "JNI_OnLoad",
				limit: 5,
			});
			expect(disasmRes.details?.status).toBe("ok");
			expect(disasmRes.details?.reference).toBe("JNI_OnLoad");
			expect(disasmRes.details?.referenceDefaulted).toBe(false);
			expect(disasmRes.details?.disasm).toHaveLength(5);
			expect(disasmRes.details?.disasm?.[0]?.opcode).toBe("stp");
			expect(textOf(disasmRes)).toContain("@ JNI_OnLoad");
			expect(textOf(disasmRes)).toContain("stp x29, x30");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});
