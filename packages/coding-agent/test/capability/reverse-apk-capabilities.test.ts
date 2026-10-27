import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { checkReverseTools } from "../../src/cli/setup-reverse";
import { probePythonTool, resolveReverseCapabilities } from "../../src/extensibility/skill-tool-catalog";
import type { SkillRequirementWhich } from "../../src/extensibility/skill-requirements";

function mockWhich(lookup: Record<string, string | null>): SkillRequirementWhich {
	return command => lookup[command] ?? null;
}

describe("Reverse APK Capabilities & Readiness State Transitions", () => {
	describe("apk_artifact_generation dependency combinations", () => {
		interface TestCase {
			desc: string;
			tools: Record<string, "installed" | "missing">;
			expectedReady: boolean;
			expectedStatus: "ready" | "available_with_fallbacks" | "missing";
			expectedOfflineReady: boolean;
			expectedSigningReady: boolean;
			expectedBlockedContains: string[];
			expectedSetupCommand: string;
		}

		const cases: TestCase[] = [
			{
				desc: "all dependencies missing",
				tools: { python: "missing", zipalign: "missing", apksigner: "missing", java: "missing" },
				expectedReady: false,
				expectedStatus: "available_with_fallbacks",
				expectedOfflineReady: false,
				expectedSigningReady: false,
				expectedBlockedContains: ["python", "zipalign", "apksigner", "java"],
				expectedSetupCommand: "reverse setup reverse python",
			},
			{
				desc: "python alone installed (offline ready, signing blocked)",
				tools: { python: "installed", zipalign: "missing", apksigner: "missing", java: "missing" },
				expectedReady: false,
				expectedStatus: "available_with_fallbacks",
				expectedOfflineReady: true,
				expectedSigningReady: false,
				expectedBlockedContains: ["zipalign", "apksigner", "java"],
				expectedSetupCommand: "reverse setup reverse apksigner",
			},
			{
				desc: "all signing tools present but python missing (signing requires python runtime)",
				tools: { python: "missing", zipalign: "installed", apksigner: "installed", java: "installed" },
				expectedReady: false,
				expectedStatus: "available_with_fallbacks",
				expectedOfflineReady: false,
				expectedSigningReady: false,
				expectedBlockedContains: ["python"],
				expectedSetupCommand: "reverse setup reverse python",
			},
			{
				desc: "python and signers installed but java missing (apksigner wrapper blocked)",
				tools: { python: "installed", zipalign: "installed", apksigner: "installed", java: "missing" },
				expectedReady: false,
				expectedStatus: "available_with_fallbacks",
				expectedOfflineReady: true,
				expectedSigningReady: false,
				expectedBlockedContains: ["java"],
				expectedSetupCommand: "reverse setup reverse java",
			},
			{
				desc: "complete pipeline toolchain (python + zipalign + apksigner + java)",
				tools: { python: "installed", zipalign: "installed", apksigner: "installed", java: "installed" },
				expectedReady: true,
				expectedStatus: "ready",
				expectedOfflineReady: true,
				expectedSigningReady: true,
				expectedBlockedContains: [],
				expectedSetupCommand: "reverse setup reverse apksigner",
			},
		];

		it.each(cases)(
			"resolves $desc correctly",
			({
				tools,
				expectedReady,
				expectedStatus,
				expectedOfflineReady,
				expectedSigningReady,
				expectedBlockedContains,
				expectedSetupCommand,
			}) => {
				const toolStatuses = Object.entries(tools).map(([id, status]) => ({ id, status }));
				const resolved = resolveReverseCapabilities({
					platform: "darwin",
					toolStatuses,
				});
				const cap = resolved.find(c => c.id === "apk_artifact_generation");
				expect(cap).toBeDefined();
				expect(cap?.ready).toBe(expectedReady);
				expect(cap?.status).toBe(expectedStatus);
				expect(cap?.pipelineStages?.offline.ready).toBe(expectedOfflineReady);
				expect(cap?.pipelineStages?.signing.ready).toBe(expectedSigningReady);

				if (expectedBlockedContains.length > 0) {
					for (const blocked of expectedBlockedContains) {
						expect(cap?.blockedRequirements).toContain(blocked);
					}
					expect(cap?.setupCommand).toBe(expectedSetupCommand);
				} else {
					expect(cap?.blockedRequirements).toBeUndefined();
				}
			},
		);

		it("distinguishes device host prerequisites from unverified connected device runtime", () => {
			const resolvedWithAdb = resolveReverseCapabilities({
				platform: "darwin",
				toolStatuses: [
					{ id: "python", status: "installed" },
					{ id: "zipalign", status: "installed" },
					{ id: "apksigner", status: "installed" },
					{ id: "java", status: "installed" },
					{ id: "adb", status: "installed" },
				],
			});
			const capWithAdb = resolvedWithAdb.find(c => c.id === "apk_artifact_generation");
			expect(capWithAdb?.pipelineStages?.device.hostPrerequisitesReady).toBe(true);
			expect(capWithAdb?.pipelineStages?.device.ready).toBe(false); // Connected device runtime remains unverified in static catalog
			expect(capWithAdb?.pipelineStages?.device.deviceConnected).toBe(false);

			const resolvedWithoutAdb = resolveReverseCapabilities({
				platform: "darwin",
				toolStatuses: [
					{ id: "python", status: "installed" },
					{ id: "zipalign", status: "installed" },
					{ id: "apksigner", status: "installed" },
					{ id: "java", status: "installed" },
					{ id: "adb", status: "missing" },
				],
			});
			const capWithoutAdb = resolvedWithoutAdb.find(c => c.id === "apk_artifact_generation");
			expect(capWithoutAdb?.pipelineStages?.device.hostPrerequisitesReady).toBe(false);
			expect(capWithoutAdb?.pipelineStages?.device.missingTools).toContain("adb");
		});
	});

	describe("dex_patching readiness state transitions", () => {
		it("transitions to ready when python becomes installed", () => {
			const missing = resolveReverseCapabilities({
				platform: "darwin",
				toolStatuses: [{ id: "python", status: "missing" }],
			});
			const capMissing = missing.find(c => c.id === "dex_patching");
			expect(capMissing?.ready).toBe(false);
			expect(capMissing?.status).toBe("available_with_fallbacks");
			expect(capMissing?.blockedRequirements).toEqual(["python"]);
			expect(capMissing?.setupCommand).toBe("reverse setup reverse python");

			const installed = resolveReverseCapabilities({
				platform: "darwin",
				toolStatuses: [{ id: "python", status: "installed" }],
			});
			const capInstalled = installed.find(c => c.id === "dex_patching");
			expect(capInstalled?.ready).toBe(true);
			expect(capInstalled?.status).toBe("ready");
			expect(capInstalled?.blockedRequirements).toBeUndefined();
			expect(capInstalled?.pipelineStages?.offline.ready).toBe(true);
		});

		it("rejects readiness when only jadx is installed without python runtime", () => {
			const resolved = resolveReverseCapabilities({
				platform: "darwin",
				toolStatuses: [
					{ id: "jadx", status: "installed" },
					{ id: "python", status: "missing" },
				],
			});
			const cap = resolved.find(c => c.id === "dex_patching");
			expect(cap?.ready).toBe(false);
			expect(cap?.status).toBe("available_with_fallbacks");
			expect(cap?.blockedRequirements).toContain("python");
		});
	});

	describe("apk_unpacking baseline preservation", () => {
		it("maintains jadx and full unpacking readiness independent of dex patch python state", () => {
			const withJadxAndJava = resolveReverseCapabilities({
				platform: "darwin",
				toolStatuses: [
					{ id: "jadx", status: "installed" },
					{ id: "java", status: "installed" },
					{ id: "python", status: "missing" },
				],
			});
			const jadxUnpackingCap = withJadxAndJava.find(c => c.id === "apk_unpacking");
			expect(jadxUnpackingCap?.canStart).toBe(true);
			expect(jadxUnpackingCap?.unpackingStages?.baseline.ready).toBe(true);
			expect(jadxUnpackingCap?.unpackingStages?.javaDecompile.ready).toBe(true);
			expect(jadxUnpackingCap?.unpackingStages?.smali.ready).toBe(false);
			expect(jadxUnpackingCap?.ready).toBe(false);
			expect(jadxUnpackingCap?.status).toBe("available_with_fallbacks");
			expect(jadxUnpackingCap?.blockedRequirements).toEqual(["apktool"]);
			expect(jadxUnpackingCap?.blockedRequirements).not.toContain("python");

			const fullUnpackingToolchain = resolveReverseCapabilities({
				platform: "darwin",
				toolStatuses: [
					{ id: "jadx", status: "installed" },
					{ id: "apktool", status: "installed" },
					{ id: "java", status: "installed" },
					{ id: "python", status: "missing" },
				],
			});
			const fullUnpackingCap = fullUnpackingToolchain.find(c => c.id === "apk_unpacking");
			const patchCap = fullUnpackingToolchain.find(c => c.id === "dex_patching");
			expect(fullUnpackingCap?.canStart).toBe(true);
			expect(fullUnpackingCap?.ready).toBe(true);
			expect(fullUnpackingCap?.status).toBe("ready");
			expect(fullUnpackingCap?.blockedRequirements).toBeUndefined();
			expect(fullUnpackingCap?.unpackingStages?.baseline.ready).toBe(true);
			expect(fullUnpackingCap?.unpackingStages?.javaDecompile.ready).toBe(true);
			expect(fullUnpackingCap?.unpackingStages?.smali.ready).toBe(true);
			expect(patchCap?.ready).toBe(false);
			expect(patchCap?.blockedRequirements).toContain("python");
		});

		it("blocks jadx and apktool stages when java runtime is missing while keeping baseline ready", () => {
			const jadxWithoutJava = resolveReverseCapabilities({
				platform: "darwin",
				toolStatuses: [
					{ id: "jadx", status: "installed" },
					{ id: "python", status: "missing" },
				],
			});
			const unpackingCap = jadxWithoutJava.find(c => c.id === "apk_unpacking");
			expect(unpackingCap?.canStart).toBe(true);
			expect(unpackingCap?.ready).toBe(false);
			expect(unpackingCap?.status).toBe("available_with_fallbacks");
			expect(unpackingCap?.unpackingStages?.baseline.ready).toBe(true);
			expect(unpackingCap?.unpackingStages?.javaDecompile.ready).toBe(false);
			expect(unpackingCap?.unpackingStages?.javaDecompile.missingTools).toContain("java");
			expect(unpackingCap?.unpackingStages?.smali.ready).toBe(false);
			expect(unpackingCap?.blockedRequirements).toEqual(["java", "apktool"]);
			expect(unpackingCap?.blockedRequirements).not.toContain("python");
		});
	});

	describe("real Python runtime probing and rejection behavior", () => {
		let tempDir: string;

		beforeEach(() => {
			tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "rev-py-test-"));
		});

		afterEach(() => {
			try {
				fs.rmSync(tempDir, { recursive: true, force: true });
			} catch {}
		});

		it("returns null when candidate path does not physically exist on disk", () => {
			const result = probePythonTool({
				candidates: [path.join(tempDir, "nonexistent-python3")],
			});
			expect(result).toBeNull();
		});

		it("returns null when explicit candidates list is empty", () => {
			const result = probePythonTool({ candidates: [] });
			expect(result).toBeNull();
		});

		it("rejects candidate when real execution check exits with non-zero (Python < 3.9)", () => {
			const fakePy = path.join(tempDir, "python-old");
			fs.writeFileSync(fakePy, "#!/bin/sh\nexit 1\n", { mode: 0o755 });

			const result = probePythonTool({ candidates: [fakePy] });
			expect(result).toBeNull();
		});

		it("rejects candidate when execution hangs past the timeout watchdog", () => {
			const hungPy = path.join(tempDir, "python-hung");
			fs.writeFileSync(hungPy, "#!/bin/sh\nsleep 5\nexit 0\n", { mode: 0o755 });

			const result = probePythonTool({ candidates: [hungPy] });
			expect(result).toBeNull();
		});

		it("accepts candidate when real execution check confirms version 0 status code", () => {
			const realPy = path.join(tempDir, "python-ok");
			fs.writeFileSync(realPy, "#!/bin/sh\nexit 0\n", { mode: 0o755 });

			const result = probePythonTool({ candidates: [realPy] });
			expect(result).toBe(realPy);
		});

		it("discovers installed python in checkReverseTools without relying on command string pinning", () => {
			const realPy = path.join(tempDir, "python3");
			fs.writeFileSync(realPy, "#!/bin/sh\nexit 0\n", { mode: 0o755 });

			const which = mockWhich({
				strings: "/usr/bin/strings",
				file: "/usr/bin/file",
				python3: realPy,
			});
			const report = checkReverseTools({
				platform: "darwin",
				which,
			});
			const tool = report.tools.find(t => t.id === "python");
			expect(tool).toBeDefined();
			expect(tool?.status).toBe("installed");
			expect(tool?.foundPath).toBeTruthy();
			expect(fs.existsSync(tool!.foundPath!)).toBe(true);
		});
	});
});
