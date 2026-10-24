import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
	resolveVmpTool,
	validatePeAmd64,
	validateUnixExecutable,
	VMP_TOOL_ASSETS,
} from "../src/extensibility/vmp-toolchain";
import { getPortableToolRecipe, installPortableTool } from "../src/extensibility/portable-tool-install";
import { canInstallReverseItem, getReverseInstallPlan } from "../src/extensibility/reverse-tool-install";
import { checkReverseTools, isTrustedCatalogArgv } from "../src/cli/setup-reverse";

describe("vmp-toolchain resolver and installation behavior", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "vmp-toolchain-test-"));
	});

	afterEach(async () => {
		try {
			await fs.promises.rm(tempDir, { recursive: true, force: true });
		} catch {}
	});

	describe("binary header validations and platform guards", () => {
		it("validates PE AMD64 binaries and rejects non-AMD64 or non-PE", () => {
			const nonPeFile = path.join(tempDir, "script.sh");
			fs.writeFileSync(nonPeFile, "#!/bin/sh\necho hi\n");
			expect(validatePeAmd64(nonPeFile)).toBe(false);

			// Construct minimal valid PE header with machine = 0x8664 (AMD64)
			const validPe = Buffer.alloc(512);
			validPe[0] = 0x4d; // 'M'
			validPe[1] = 0x5a; // 'Z'
			validPe.writeInt32LE(0x80, 0x3c); // e_lfanew = 128
			validPe[0x80] = 0x50; // 'P'
			validPe[0x81] = 0x45; // 'E'
			validPe[0x82] = 0x00;
			validPe[0x83] = 0x00;
			validPe.writeUInt16LE(0x8664, 0x84); // IMAGE_FILE_MACHINE_AMD64

			const validPeFile = path.join(tempDir, "sample-x64.exe");
			fs.writeFileSync(validPeFile, validPe);
			expect(validatePeAmd64(validPeFile)).toBe(true);

			// Modify to i386 (0x014c)
			const invalidMachinePe = Buffer.from(validPe);
			invalidMachinePe.writeUInt16LE(0x014c, 0x84);
			const invalidPeFile = path.join(tempDir, "sample-x86.exe");
			fs.writeFileSync(invalidPeFile, invalidMachinePe);
			expect(validatePeAmd64(invalidPeFile)).toBe(false);
		});

		it("strictly rejects Windows PE binaries on Unix platforms", () => {
			const fakePe = Buffer.alloc(128);
			fakePe[0] = 0x4d; // 'M'
			fakePe[1] = 0x5a; // 'Z'
			const peFile = path.join(tempDir, "fake.exe");
			fs.writeFileSync(peFile, fakePe, { mode: 0o755 });

			// On darwin or linux, validateUnixExecutable must reject MZ files
			expect(validateUnixExecutable(peFile, "darwin")).toBe(false);
			expect(validateUnixExecutable(peFile, "linux")).toBe(false);
		});

		it("accepts valid script wrappers on Unix platforms", () => {
			const script = path.join(tempDir, "wrapper");
			fs.writeFileSync(script, "#!/usr/bin/env bash\necho 1\n", { mode: 0o755 });
			expect(validateUnixExecutable(script, "darwin")).toBe(true);
			expect(validateUnixExecutable(script, "linux")).toBe(true);
		});
	});

	describe("resolveVmpTool resolver behavior", () => {
		it("returns null when binary or managed venv is not present", () => {
			const agentDir = path.join(tempDir, "agent");
			expect(resolveVmpTool("triton", { agentDir, env: {}, which: () => null })).toBeNull();
			expect(resolveVmpTool("vmpdump", { agentDir, env: {}, platform: "win32", which: () => null })).toBeNull();
			expect(resolveVmpTool("mergen", { agentDir, env: {}, platform: "win32", which: () => null })).toBeNull();
			expect(resolveVmpTool("novmp", { agentDir, env: {}, platform: "win32", which: () => null })).toBeNull();
		});

		it("vmpdump always returns null on non-Windows platforms even if a file exists", () => {
			const agentDir = path.join(tempDir, "agent");
			const vmpdumpDir = path.join(agentDir, "tools", "vmp", "vmpdump");
			fs.mkdirSync(vmpdumpDir, { recursive: true });
			const dummyExe = path.join(vmpdumpDir, "VMPDump.exe");
			fs.writeFileSync(dummyExe, "dummy", { mode: 0o755 });

			expect(resolveVmpTool("vmpdump", { agentDir, platform: "darwin" })).toBeNull();
			expect(resolveVmpTool("vmpdump", { agentDir, platform: "linux" })).toBeNull();
		});

		it("resolves native tools when valid binary is placed in canonical managed directory on win32", () => {
			const agentDir = path.join(tempDir, "agent");
			const mergenDir = path.join(agentDir, "tools", "mergen");
			fs.mkdirSync(mergenDir, { recursive: true });

			const validPe = Buffer.alloc(512);
			validPe[0] = 0x4d;
			validPe[1] = 0x5a;
			validPe.writeInt32LE(0x80, 0x3c);
			validPe[0x80] = 0x50;
			validPe[0x81] = 0x45;
			validPe.writeUInt16LE(0x8664, 0x84);

			const mergenBin = path.join(mergenDir, "lifter-windows-iced.exe");
			fs.writeFileSync(mergenBin, validPe);

			const resolved = resolveVmpTool("mergen", { agentDir, platform: "win32" });
			expect(resolved).toBe(mergenBin);
		});

		it("honors canonical environment variable overrides on win32", () => {
			const customBin = path.join(tempDir, "custom-novmp.exe");
			const validPe = Buffer.alloc(512);
			validPe[0] = 0x4d;
			validPe[1] = 0x5a;
			validPe.writeInt32LE(0x80, 0x3c);
			validPe[0x80] = 0x50;
			validPe[0x81] = 0x45;
			validPe.writeUInt16LE(0x8664, 0x84);
			fs.writeFileSync(customBin, validPe);

			const resolved = resolveVmpTool("novmp", {
				env: { NOVMP_PATH: customBin },
				platform: "win32",
			});
			expect(resolved).toBe(customBin);
		});
	});

	describe("portable installer recipes and platform constraints", () => {
		it("declares vetted recipes with official release hashes", () => {
			const vmpdumpRecipe = getPortableToolRecipe("vmpdump");
			expect(vmpdumpRecipe).toBeDefined();
			expect(vmpdumpRecipe?.files[0].sha256).toBe(VMP_TOOL_ASSETS.vmpdump.sha256);
			expect(vmpdumpRecipe?.supportedPlatforms).toEqual(["win32"]);

			const mergenRecipe = getPortableToolRecipe("mergen");
			expect(mergenRecipe).toBeDefined();
			expect(mergenRecipe?.files[0].sha256).toBe(VMP_TOOL_ASSETS.mergen.sha256);
			expect(mergenRecipe?.format).toBe("exe");
			expect(mergenRecipe?.supportedPlatforms).toEqual(["win32"]);

			const novmpRecipe = getPortableToolRecipe("novmp");
			expect(novmpRecipe).toBeDefined();
			expect(novmpRecipe?.files[0].sha256).toBe(VMP_TOOL_ASSETS.novmp.sha256);
			expect(novmpRecipe?.format).toBe("exe");
			expect(novmpRecipe?.supportedPlatforms).toEqual(["win32"]);
		});

		it("portable installer aborts early on unsupported platform without downloading", async () => {
			let fetchCalled = false;
			const res = await installPortableTool("mergen", {
				platform: "darwin",
				agentDir: tempDir,
				fetch: async () => {
					fetchCalled = true;
					return new Response("dummy");
				},
			});

			expect(res.success).toBe(false);
			expect(res.message).toContain("only supported on [win32]");
			expect(fetchCalled).toBe(false);
		});

		it("aborts when downloaded payload checksum fails", async () => {
			const res = await installPortableTool("mergen", {
				platform: "win32",
				agentDir: tempDir,
				fetch: async () => new Response("corrupted-data"),
			});

			expect(res.success).toBe(false);
			expect(res.message).toContain("Checksum verification failed");
		});
	});

	describe("reverse-tool-install planner integration", () => {
		it("plans portable installation on Windows for vmpdump, mergen, and novmp", () => {
			const report = checkReverseTools({
				platform: "win32",
				which: () => null,
				env: { PATH: "" },
			});

			const vmpdump = report.tools.find(t => t.id === "vmpdump");
			expect(vmpdump).toBeDefined();
			const planVmpdump = getReverseInstallPlan(vmpdump!, { platform: "win32" });
			expect(planVmpdump.canInstall).toBe(true);
			expect(planVmpdump.steps[0].installer).toBe("portable");
			expect(isTrustedCatalogArgv(vmpdump!)).toBe(true);

			const mergen = report.tools.find(t => t.id === "mergen");
			expect(mergen).toBeDefined();
			const planMergen = getReverseInstallPlan(mergen!, { platform: "win32" });
			expect(planMergen.canInstall).toBe(true);
			expect(planMergen.steps[0].installer).toBe("portable");

			const novmp = report.tools.find(t => t.id === "novmp");
			expect(novmp).toBeDefined();
			const planNovmp = getReverseInstallPlan(novmp!, { platform: "win32" });
			expect(planNovmp.canInstall).toBe(true);
			expect(planNovmp.steps[0].installer).toBe("portable");
		});
		it("strictly rejects tampered or mutated argv in isTrustedCatalogArgv", () => {
			const report = checkReverseTools({
				platform: "win32",
				which: () => null,
				env: { PATH: "" },
			});

			const mergen = report.tools.find(t => t.id === "mergen");
			expect(mergen).toBeDefined();
			expect(isTrustedCatalogArgv(mergen!)).toBe(true);

			// Mutated argv with injected flags is rejected
			const mutated = {
				...mergen!,
				installArgv: ["reverse", "setup", "reverse", "mergen", "--execute", "--extra"],
			};
			expect(isTrustedCatalogArgv(mutated)).toBe(false);

			// Replaced argv with arbitrary command is rejected
			const injected = {
				...mergen!,
				installArgv: ["sh", "-c", "echo hello"],
			};
			expect(isTrustedCatalogArgv(injected)).toBe(false);
		});

		it("reports honest unsupported reason on darwin/linux for Windows native tools", () => {
			const report = checkReverseTools({
				platform: "darwin",
				which: () => null,
				env: { PATH: "" },
			});

			const vmpdump = report.tools.find(t => t.id === "vmpdump");
			expect(vmpdump).toBeDefined();
			const planVmpdump = getReverseInstallPlan(vmpdump!, { platform: "darwin" });
			expect(planVmpdump.canInstall).toBe(false);
			expect(planVmpdump.reason).toContain("Windows");

			const mergen = report.tools.find(t => t.id === "mergen");
			expect(mergen).toBeDefined();
			const planMergen = getReverseInstallPlan(mergen!, { platform: "darwin" });
			expect(planMergen.canInstall).toBe(false);
			expect(planMergen.reason).toContain("Windows");

			const novmp = report.tools.find(t => t.id === "novmp");
			expect(novmp).toBeDefined();
			const planNovmp = getReverseInstallPlan(novmp!, { platform: "darwin" });
			expect(planNovmp.canInstall).toBe(false);
			expect(planNovmp.reason).toContain("Windows");
		});

		it("plans managed virtual environment installation for triton", () => {
			const report = checkReverseTools({
				platform: "darwin",
				which: cmd => (cmd === "python3" ? "/usr/bin/python3" : null),
				env: { PATH: "" },
			});

			const triton = report.tools.find(t => t.id === "triton");
			expect(triton).toBeDefined();

			const plan = getReverseInstallPlan(triton!, { platform: "darwin", env: { PATH: "" } });
			expect(plan.canInstall).toBe(true);
			expect(plan.steps).toHaveLength(1);
			expect(plan.steps[0].id).toBe("triton");
			expect(plan.steps[0].installer).toBe("triton");
			expect(isTrustedCatalogArgv(triton!)).toBe(true);
			expect(canInstallReverseItem(triton!, { platform: "darwin", env: { PATH: "" } })).toBe(true);
		});

		it("populates installCommand and installArgv for triton so TUI displays [ ]", () => {
			const report = checkReverseTools({
				platform: "darwin",
				which: () => null,
				env: { PATH: "" },
			});

			const triton = report.tools.find(t => t.id === "triton");
			expect(triton?.installCommand).toBeDefined();
			expect(triton?.installArgv).toEqual(["reverse", "setup", "reverse", "triton", "--execute"]);
			expect(canInstallReverseItem(triton!, { platform: "darwin", env: { PATH: "" } })).toBe(true);
		});

		it("respects custom agentDir when passed to checkReverseTools", () => {
			const customAgentDir = path.join(tempDir, "custom-agent");
			const report = checkReverseTools({
				platform: "darwin",
				agentDir: customAgentDir,
				which: () => null,
				env: { PATH: "" },
			});
			expect(report).toBeDefined();
		});
	});
});
