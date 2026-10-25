// SPDX-License-Identifier: MIT
/**
 * Contract, approval gating, and input validation tests for DeobfuscateTool.
 */

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "../src/config/settings";
import { resolveProtectionTool } from "../src/extensibility/protection-toolchain";
import type { ToolSession } from "../src/tools";
import { DeobfuscateTool, type DeobfuscateParams } from "../src/tools/deobfuscate";

function createMockSession(cwd: string, options?: { planMode?: boolean }): ToolSession {
	return {
		cwd,
		hasUI: false,
		settings: Settings.isolated({}),
		getPlanModeState: () => ({ enabled: options?.planMode ?? false }),
	} as unknown as ToolSession;
}

describe("DeobfuscateTool Approval Gates & Plan Mode", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "deobf-test-"));
	});

	afterEach(async () => {
		try {
			await fs.promises.rm(tempDir, { recursive: true, force: true });
		} catch {}
	});

	it("assigns read approval to status and exec approval to analyze", () => {
		const session = createMockSession(tempDir);
		const tool = new DeobfuscateTool(session);

		expect(tool.approval({ action: "status" })).toBe("read");
		expect(tool.approval({ action: "status", backend: "msynth" })).toBe("read");
		expect(tool.approval({ action: "analyze", backend: "msynth", expression: "x + 1" })).toBe("exec");
		expect(tool.approval({ action: "analyze", backend: "jadx", path: "test.apk" })).toBe("exec");
	});

	it("permits status in Plan Mode but blocks analyze", async () => {
		const session = createMockSession(tempDir, { planMode: true });
		const tool = new DeobfuscateTool(session);

		// Status succeeds in plan mode
		const statusRes = await tool.execute("call-1", { action: "status", backend: "msynth" });
		expect(statusRes.details?.action).toBe("status");
		// Analyze is blocked with plan mode error
		await expect(
			tool.execute("call-2", {
				action: "analyze",
				backend: "msynth",
				expression: "(x ^ y) + 2 * (x & y)",
			}),
		).rejects.toThrow(/Plan mode: deobfuscate 'analyze' executes external reverse-engineering tools/);
	});
});

describe("DeobfuscateTool Status Probing", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "deobf-status-"));
	});

	afterEach(async () => {
		try {
			await fs.promises.rm(tempDir, { recursive: true, force: true });
		} catch {}
	});

	it("returns structured status for all backends when unscoped", async () => {
		const session = createMockSession(tempDir);
		const tool = new DeobfuscateTool(session);

		const res = await tool.execute("status-all", { action: "status" });
		expect(res.details?.action).toBe("status");
		if (res.details && res.details.action === "status") {
			const backends = res.details.backends;
			expect(backends.msynth).toBeDefined();
			expect(backends.jadx).toBeDefined();
			expect(backends["d810-ng"]).toBeDefined();
			expect(backends.simplify).toBeDefined();
			expect(backends.blackdex).toBeDefined();

			expect(typeof backends.msynth.installed).toBe("boolean");
			expect(typeof backends.jadx.installed).toBe("boolean");
			expect(typeof backends["d810-ng"].installed).toBe("boolean");
			expect(typeof backends.simplify.installed).toBe("boolean");
			expect(typeof backends.blackdex.installed).toBe("boolean");
		}
	});

	it("scopes status probing to requested backend only", async () => {
		const session = createMockSession(tempDir);
		const tool = new DeobfuscateTool(session);

		const res = await tool.execute("status-jadx", { action: "status", backend: "jadx" });
		expect(res.details?.action).toBe("status");
		if (res.details && res.details.action === "status") {
			const backends = res.details.backends;
			expect(backends.jadx).toBeDefined();
			expect(backends.msynth).toBeUndefined();
			expect(backends["d810-ng"]).toBeUndefined();
			expect(backends.simplify).toBeUndefined();
			expect(backends.blackdex).toBeUndefined();
		}
	});
});

describe("DeobfuscateTool Destination & Input Protection", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "deobf-protect-"));
	});

	afterEach(async () => {
		try {
			await fs.promises.rm(tempDir, { recursive: true, force: true });
		} catch {}
	});

	it("rejects destination path that already exists", async () => {
		const session = createMockSession(tempDir);
		const tool = new DeobfuscateTool(session);

		const dummyInput = path.join(tempDir, "input.dex");
		await fs.promises.writeFile(dummyInput, Buffer.from("dummy"));

		const existingOut = path.join(tempDir, "existing.dex");
		await fs.promises.writeFile(existingOut, Buffer.from("pre-existing"));

		await expect(
			tool.execute("simplify-overwrite", {
				action: "analyze",
				backend: "simplify",
				path: dummyInput,
				out: existingOut,
			}),
		).rejects.toThrow(/Destination path already exists/);
	});
	it("rejects destination path identical to input target", async () => {
		const session = createMockSession(tempDir);
		const tool = new DeobfuscateTool(session);

		const dummyInput = path.join(tempDir, "sample.dex");
		await fs.promises.writeFile(dummyInput, Buffer.from("dummy"));

		await expect(
			tool.execute("simplify-same-path", {
				action: "analyze",
				backend: "simplify",
				path: dummyInput,
				out: dummyInput,
			}),
		).rejects.toThrow(/Destination path cannot be the same as input target/);
	});

	it("rejects pre-existing output directory for jadx", async () => {
		const session = createMockSession(tempDir);
		const tool = new DeobfuscateTool(session);

		const dummyApk = path.join(tempDir, "sample.apk");
		await fs.promises.writeFile(dummyApk, Buffer.from("dummy_apk"));

		const existingDir = path.join(tempDir, "existing_jadx_dir");
		await fs.promises.mkdir(existingDir, { recursive: true });

		await expect(
			tool.execute("jadx-existing-dir", {
				action: "analyze",
				backend: "jadx",
				path: dummyApk,
				out: existingDir,
			}),
		).rejects.toThrow(/Destination path already exists/);
	});
});

describe("DeobfuscateTool Backend Input Validation", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "deobf-validation-"));
	});

	afterEach(async () => {
		try {
			await fs.promises.rm(tempDir, { recursive: true, force: true });
		} catch {}
	});

	it("fails when backend is omitted for analyze action", async () => {
		const session = createMockSession(tempDir);
		const tool = new DeobfuscateTool(session);

		await expect(
			tool.execute("analyze-no-backend", {
				action: "analyze",
			} as unknown as DeobfuscateParams),
		).rejects.toThrow(/Parameter 'backend' is required for action 'analyze'/);
	});
	it("fails with explicit error when target file does not exist", async () => {
		const session = createMockSession(tempDir);
		const tool = new DeobfuscateTool(session);

		const absentPath = path.join(tempDir, "non_existent.apk");

		await expect(
			tool.execute("jadx-missing-file", {
				action: "analyze",
				backend: "jadx",
				path: absentPath,
			}),
		).rejects.toThrow(/Target APK\/DEX file not found/);

		await expect(
			tool.execute("simplify-missing-file", {
				action: "analyze",
				backend: "simplify",
				path: absentPath,
			}),
		).rejects.toThrow(/Target APK\/DEX file not found/);
	});

	it("fails when d810-ng is missing target function parameter", async () => {
		const session = createMockSession(tempDir);
		const tool = new DeobfuscateTool(session);

		const dummyBin = path.join(tempDir, "test.bin");
		await fs.promises.writeFile(dummyBin, Buffer.from("dummy"));

		await expect(
			tool.execute("d810-missing-function", {
				action: "analyze",
				backend: "d810-ng",
				path: dummyBin,
			}),
		).rejects.toThrow(/requires 'function'/);
	});

	it("fails when blackdex is missing target package name", async () => {
		const session = createMockSession(tempDir);
		const tool = new DeobfuscateTool(session);

		await expect(
			tool.execute("blackdex-missing-pkg", {
				action: "analyze",
				backend: "blackdex",
			}),
		).rejects.toThrow(/requires parameter 'package_name'/);
	});

	it("fails when msynth is missing expression", async () => {
		const session = createMockSession(tempDir);
		const tool = new DeobfuscateTool(session);

		await expect(
			tool.execute("msynth-missing-expr", {
				action: "analyze",
				backend: "msynth",
			}),
		).rejects.toThrow(/requires parameter 'expression'/);
	});

	it("fails closed when msynth engine dependency is missing", async () => {
		const session = createMockSession(tempDir);
		const tool = new DeobfuscateTool(session);

		const msynthResolved = resolveProtectionTool("msynth");
		if (msynthResolved?.installed && msynthResolved?.canStart) {
			// Ambient environment has msynth provisioned; skip un-scoped missing-dependency assertion
			return;
		}

		// When msynth is not installed on host, worker fails with structured error
		await expect(
			tool.execute("msynth-missing-engine", {
				action: "analyze",
				backend: "msynth",
				expression: "(x ^ y) + 2 * (x & y)",
			}),
		).rejects.toThrow(/Required msynth/);
	});
});
