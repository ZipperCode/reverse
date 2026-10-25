import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { getAgentDir, setAgentDir } from "@reverse/utils";
import {
	ALL_PROTECTION_TOOL_IDS,
	inspectProtectionTool,
	installProtectionTool,
	isValidZipHeader,
	resolveProtectionTool,
} from "../src/extensibility/protection-toolchain";
import { getReverseInstallPlan } from "../src/extensibility/reverse-tool-install";
import { checkReverseTools, isTrustedCatalogArgv } from "../src/cli/setup-reverse";

describe("Protection Toolchain Resolver and Catalog Integration", () => {
	let tempAgentDir: string;
	let originalAgentDir: string;

	beforeEach(async () => {
		tempAgentDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "rev-protection-test-"));
		originalAgentDir = getAgentDir();
		setAgentDir(tempAgentDir);
	});

	afterEach(async () => {
		setAgentDir(originalAgentDir);
		try {
			await fs.promises.rm(tempAgentDir, { recursive: true, force: true });
		} catch {}
	});

	describe("Protection tool resolution", () => {
		it("probes return null when tools are missing in isolated agentDir", () => {
			for (const id of ALL_PROTECTION_TOOL_IDS) {
				const resolved = resolveProtectionTool(id, { agentDir: tempAgentDir, allowMissing: false });
				// In an empty temp directory without host PATH presence, resolution should not report fake success
				if (resolved) {
					// If resolved via host PATH (e.g. if frida-dexdump is installed on host system), it must be marked installed
					expect(resolved.installed).toBe(true);
				} else {
					expect(resolved).toBeNull();
				}
			}
		});
	});

	describe("Host vs Device detection semantics", () => {
		it("rejects malformed or sub-threshold APK archive for BlackDex without reporting fake ready", async () => {
			const blackdexDir = path.join(tempAgentDir, "tools", "blackdex");
			await fs.promises.mkdir(blackdexDir, { recursive: true });

			// 1. Corrupt non-ZIP file
			const corruptPath = path.join(blackdexDir, "app-BlackDex64.apk");
			await fs.promises.writeFile(corruptPath, Buffer.from("NOT_A_VALID_ZIP_ARCHIVE_HEADER"));
			expect(isValidZipHeader(corruptPath)).toBe(false);

			const resolvedCorrupt = resolveProtectionTool("blackdex", { agentDir: tempAgentDir });
			expect(resolvedCorrupt).toBeNull();

			// 2. Sub-threshold archive (< 1MB) must not claim installed/ready
			const truncatedZip = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.alloc(26)]);
			await fs.promises.writeFile(corruptPath, truncatedZip);
			expect(isValidZipHeader(corruptPath)).toBe(true);

			const resolvedTruncated = resolveProtectionTool("blackdex", { agentDir: tempAgentDir });
			expect(resolvedTruncated).toBeNull();

			const inspected = inspectProtectionTool("blackdex", { agentDir: tempAgentDir });
			expect(inspected.installed).toBe(false);
			expect(inspected.canStart).toBe(false);
		});

		it("inspectProtectionTool returns uninstalled status when files are absent", () => {
			const inspected = inspectProtectionTool("dexkit", { agentDir: tempAgentDir });
			expect(inspected).toBeDefined();
			expect(inspected.id).toBe("dexkit");
			expect(inspected.installed).toBe(false);
			expect(inspected.canStart).toBe(false);
		});
	});

	describe("Installation planning and trusted argv verification", () => {
		const mockPrereqWhich = (bin: string): string | null => {
			switch (bin) {
				case "python":
				case "python3":
					return "/usr/bin/python3";
				case "frida":
					return "/usr/local/bin/frida";
				case "java":
					return "/usr/bin/java";
				case "javac":
					return "/usr/bin/javac";
				case "jar":
					return "/usr/bin/jar";
				case "jadx":
					return "/usr/local/bin/jadx";
				case "adb":
					return "/usr/local/bin/adb";
				case "cmake":
					return "/usr/local/bin/cmake";
				case "git":
					return "/usr/bin/git";
				default:
					return null;
			}
		};

		it("plans managed installation for protection tools with reverse setup reverse <id> --execute", () => {
			// Negative case: missing python/runtime prerequisites should block installation
			const missingReport = checkReverseTools({
				platform: "darwin",
				which: () => null,
				agentDir: tempAgentDir,
			});
			const missingDexdump = missingReport.tools.find(t => t.id === "frida-dexdump");
			expect(missingDexdump).toBeDefined();
			if (missingDexdump) {
				const blockedPlan = getReverseInstallPlan(missingDexdump, {
					report: missingReport,
					platform: "darwin",
					which: () => null,
					agentDir: tempAgentDir,
				});
				expect(blockedPlan.canInstall).toBe(false);
			}

			// Positive case: with valid supplied prerequisites, installation is planned
			const report = checkReverseTools({
				platform: "darwin",
				which: mockPrereqWhich,
				agentDir: tempAgentDir,
			});

			const dexdumpItem = report.tools.find(t => t.id === "frida-dexdump");
			expect(dexdumpItem).toBeDefined();
			if (dexdumpItem) {
				const plan = getReverseInstallPlan(dexdumpItem, {
					report,
					platform: "darwin",
					which: mockPrereqWhich,
					agentDir: tempAgentDir,
				});

				expect(plan.canInstall).toBe(true);
				const dexdumpStep = plan.steps.find(s => s.id === "frida-dexdump");
				expect(dexdumpStep).toBeDefined();
				expect(dexdumpStep?.installer).toBe("protection-toolchain");
				expect(dexdumpStep?.packageManager).toBe("managed");

				if (dexdumpStep && dexdumpStep.argv) {
					const trusted = isTrustedCatalogArgv(
						{
							...dexdumpItem,
							installArgv: dexdumpStep.argv,
						},
						{},
					);
					expect(trusted).toBe(true);
				}
			}
		});
	});

	describe("Deterministic install with mock fetch", () => {
		it("rejects a JADX plugin with a mismatched pinned SHA-256", async () => {
			// Create deterministic test buffer
			const testJarBuffer = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.alloc(50, 0x42)]);
			// Mock fetch returning test jar
			const mockFetch: typeof globalThis.fetch = Object.assign(
				async () => {
					return new Response(testJarBuffer, {
						status: 200,
						headers: { "Content-Type": "application/java-archive" },
					});
				},
				{ preconnect: globalThis.fetch.preconnect },
			);

			// Attempting with wrong hash must throw
			const failedResult = await installProtectionTool("jadx-string-decrypt", {
				agentDir: tempAgentDir,
				fetch: mockFetch,
			});
			// Should fail because testJarBuffer hash does not match pinned JADX_STRING_DECRYPT_SHA256
			expect(failedResult.success).toBe(false);
			expect(failedResult.error).toContain("SHA256 mismatch");
		});

		it("rejects BlackDex download failing ZIP integrity check without fake ready", async () => {
			const corruptBuffer = Buffer.from("CORRUPT_OR_SUBTHRESHOLD_DATA");
			const mockFetch: typeof globalThis.fetch = Object.assign(
				async () => {
					return new Response(corruptBuffer, { status: 200 });
				},
				{ preconnect: globalThis.fetch.preconnect },
			);

			const result = await installProtectionTool("blackdex", {
				agentDir: tempAgentDir,
				fetch: mockFetch,
			});

			expect(result.success).toBe(false);
			expect(result.error).toContain("integrity check");

			const resolved = resolveProtectionTool("blackdex", { agentDir: tempAgentDir });
			expect(resolved).toBeNull();
		});
	});
});
