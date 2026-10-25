/**
 * Unit and contract tests for DexUnpackTool (runtime DEX extraction and post-dump structural census).
 */

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { getAgentDir, setAgentDir } from "@reverse/utils";
import { Settings } from "../../src/config/settings";
import type { ToolSession } from "../../src/tools";
import { DexUnpackTool } from "../../src/tools/dex-unpack";

function createMockSession(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: false,
		settings: Settings.isolated({}),
	} as unknown as ToolSession;
}

describe("DexUnpackTool", () => {
	let testDir: string;
	let session: ToolSession;
	let tool: DexUnpackTool;

	beforeEach(() => {
		testDir = fs.mkdtempSync(path.join(os.tmpdir(), "rev_test_dex_unpack_"));
		session = createMockSession(testDir);
		tool = new DexUnpackTool(session);
	});

	afterEach(() => {
		try {
			fs.rmSync(testDir, { recursive: true, force: true });
		} catch {
			// Ignore cleanup errors
		}
	});

	it("requires execution approval for dumping and malformed requests", () => {
		// Status is read tier
		expect(tool.approval({ action: "status" })).toBe("read");

		// Dump is exec tier
		expect(tool.approval({ action: "dump" })).toBe("exec");

		// Fail-closed default
		expect(tool.approval({})).toBe("exec");
		expect(tool.approval(null)).toBe("exec");
	});

	it("enforces explicit device ID requirement and rejects device-implicit calls", async () => {
		// Missing device
		await expect(
			tool.execute("call_no_device", {
				action: "dump",
				package: "com.example.target",
			}),
		).rejects.toThrow("Explicit device ID (serial or 'local') is required");
	});

	it("enforces explicit package/PID requirement and rejects foreground-implicit calls", async () => {
		// Missing package and PID
		await expect(
			tool.execute("call_no_target", {
				action: "dump",
				device: "emulator-5554",
			}),
		).rejects.toThrow("Explicit target package name or PID is required");
	});

	it("returns structured backend status for frida-dexdump", async () => {
		const fridaStatus = await tool.execute("call_status_frida", {
			action: "status",
			backend: "frida-dexdump",
		});
		expect(fridaStatus.details).toBeDefined();
		if (!fridaStatus.details) {
			throw new Error("Expected fridaStatus.details to be defined");
		}
		expect(fridaStatus.details.action).toBe("status");
		expect(fridaStatus.details.backend).toBe("frida-dexdump");
		expect(["ok", "missing_dependency"]).toContain(fridaStatus.details.status);
		expect(fridaStatus.details.dependency?.id).toBe("frida-dexdump");
	});

	it("returns structured missing_dependency when dumper executable is unavailable", async () => {
		const originalPath = process.env.PATH;
		const originalAgentDir = getAgentDir();
		const originalEnvAgentDir = process.env.REVERSE_CODING_AGENT_DIR;
		const originalPiAgentDir = process.env.PI_CODING_AGENT_DIR;
		try {
			// Isolate PATH and canonical agentDir to empty directory to deterministically trigger missing_dependency
			process.env.PATH = testDir;
			process.env.REVERSE_CODING_AGENT_DIR = testDir;
			delete process.env.PI_CODING_AGENT_DIR;
			setAgentDir(testDir);

			const res = await tool.execute("call_dump_missing", {
				action: "dump",
				device: "emulator-5554",
				package: "com.example.app",
			});

			expect(res.details).toBeDefined();
			if (!res.details) {
				throw new Error("Expected res.details to be defined");
			}
			expect(res.details.action).toBe("dump");
			expect(res.details.status).toBe("missing_dependency");
			expect(res.details.dependency?.id).toBe("frida-dexdump");
		} finally {
			process.env.PATH = originalPath;
			if (originalEnvAgentDir !== undefined) {
				process.env.REVERSE_CODING_AGENT_DIR = originalEnvAgentDir;
			} else {
				delete process.env.REVERSE_CODING_AGENT_DIR;
			}
			if (originalPiAgentDir !== undefined) {
				process.env.PI_CODING_AGENT_DIR = originalPiAgentDir;
			} else {
				delete process.env.PI_CODING_AGENT_DIR;
			}
			setAgentDir(originalAgentDir);
		}
	});
});
