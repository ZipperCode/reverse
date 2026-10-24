import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { locateIdaInstall, probeIdaTool } from "../src/ida/install";
import { locateUnidbg, inspectUnidbg } from "../src/extensibility/unidbg-detect";
import { getPortableToolRecipe, installPortableTool } from "../src/extensibility/portable-tool-install";
import { getReverseInstallPlan } from "../src/extensibility/reverse-tool-install";
import { SKILL_TOOL_CATALOG } from "../src/extensibility/skill-tool-catalog";
import type { SkillRequirementWhich } from "../src/extensibility/skill-requirements";
import { encodeArchive } from "@reverse/utils/ar";

async function buildMockJar(mainClass = "com.example.Main"): Promise<Buffer> {
	const manifestContent = `Manifest-Version: 1.0\r\nMain-Class: ${mainClass}\r\n\r\n`;
	const classContent = Buffer.from([0xca, 0xfe, 0xba, 0xbe]);
	const entries = [
		["META-INF/MANIFEST.MF", manifestContent],
		[mainClass.replace(/\./g, "/") + ".class", classContent],
	] as const;
	const encoded = await encodeArchive("zip", entries);
	return Buffer.from(encoded);
}

describe("Issue #1 Regression Tests", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "issue1-regression-test-"));
	});

	afterEach(async () => {
		try {
			await fs.promises.rm(tempDir, { recursive: true, force: true });
		} catch {}
	});

	describe("1. IDA 9 / PATH / Consistency Detection", () => {
		it("detects IDA 9 unified binary in custom install directory via env or options", () => {
			const fakeIdaDir = path.join(tempDir, "IDA Professional 9.3");
			fs.mkdirSync(fakeIdaDir, { recursive: true });
			fs.writeFileSync(path.join(fakeIdaDir, "ida.exe"), "MZ fake binary");
			fs.writeFileSync(path.join(fakeIdaDir, "idat.exe"), "MZ fake binary");
			fs.writeFileSync(path.join(fakeIdaDir, "idalib.dll"), "MZ fake idalib");

			const detected = locateIdaInstall(undefined, {
				env: { IDADIR: fakeIdaDir },
				platform: "win32",
			});
			expect(detected).toBe(fakeIdaDir);
		});

		it("detects IDA via launcher script on PATH", () => {
			const binDir = path.join(tempDir, "bin");
			fs.mkdirSync(binDir, { recursive: true });
			const launcherPath = path.join(binDir, "ida.bat");
			fs.writeFileSync(launcherPath, "@echo off\r\nstart ida.exe\r\n");

			const mockWhich: SkillRequirementWhich = (cmd, _options) => {
				if (cmd === "ida" || cmd === "ida.exe") return launcherPath;
				return null;
			};

			const detected = probeIdaTool({
				which: mockWhich,
				platform: "win32",
			});
			expect(detected).toBe(launcherPath);
		});
	});

	describe("2. Unidbg Java / Source / JAR-aware Detection", () => {
		it("detects unidbg source directory via pom.xml and unidbg-api subfolder", () => {
			const fakeRepo = path.join(tempDir, "unidbg-repo");
			fs.mkdirSync(path.join(fakeRepo, "unidbg-api"), { recursive: true });
			fs.writeFileSync(
				path.join(fakeRepo, "pom.xml"),
				"<project><groupId>com.github.zhkl0228</groupId><artifactId>unidbg</artifactId></project>",
			);

			const inspection = inspectUnidbg({
				env: { UNIDBG_HOME: fakeRepo },
			});
			expect(inspection.hasPom).toBe(true);
			expect(inspection.unidbgDir).toBe(fakeRepo);
			expect(inspection.foundPath).toBe(fakeRepo);

			const found = locateUnidbg({ env: { UNIDBG_HOME: fakeRepo } });
			expect(found).toBe(fakeRepo);
		});

		it("detects unidbg built JAR in submodule target", async () => {
			const fakeRepo = path.join(tempDir, "unidbg-built");
			const targetDir = path.join(fakeRepo, "unidbg-api", "target");
			fs.mkdirSync(targetDir, { recursive: true });

			const jarPath = path.join(targetDir, "unidbg-api-0.9.9.jar");
			fs.writeFileSync(jarPath, await buildMockJar("com.github.unidbg.Emulator"));

			const inspection = inspectUnidbg({
				env: { UNIDBG_HOME: fakeRepo },
			});
			expect(inspection.built).toBe(true);
			expect(inspection.jars).toContain(jarPath);
			expect(inspection.foundPath).toBe(jarPath);
		});
	});

	describe("3. Portable Windows Installs for wabt / bundletool / smali / vbindiff / il2cppdumper", () => {
		it("provides portable recipes for all 5 tools", () => {
			const expectedTools = ["wabt", "bundletool", "baksmali", "vbindiff", "il2cppdumper"];
			for (const id of expectedTools) {
				const recipe = getPortableToolRecipe(id);
				expect(recipe).toBeDefined();
				expect(recipe?.files.length).toBeGreaterThan(0);
				expect(recipe?.requiredCommandGroups.length).toBeGreaterThan(0);
			}
		});

		it("correctly requires missing Java prerequisite for bundletool on win32", () => {
			const plan = getReverseInstallPlan(
				{
					kind: "cli",
					id: "bundletool",
					name: "bundletool",
					category: "android",
					description: "",
					optional: true,
					systemTool: false,
					status: "missing",
					foundPath: null,
					packageManager: "portable",
					installCommand: "reverse setup reverse bundletool",
					installArgv: ["reverse", "setup", "reverse", "bundletool", "--execute"],
					riskNote: null,
					manualUrl: "",
					manualInstructions: "",
				},
				{
					platform: "win32",
					which: () => null,
				},
			);
			expect(plan.canInstall).toBe(false);
			expect(plan.missingDependencies).toContain("java");
		});

		it("honors native package managers on macOS and does not misroute to portable", () => {
			const plan = getReverseInstallPlan(
				{
					kind: "cli",
					id: "wabt",
					name: "WABT",
					category: "web",
					description: "",
					optional: true,
					systemTool: false,
					status: "missing",
					foundPath: null,
					packageManager: "brew",
					installCommand: "brew install wabt",
					installArgv: ["brew", "install", "wabt"],
					riskNote: null,
					manualUrl: "",
					manualInstructions: "",
				},
				{
					platform: "darwin",
					which: cmd => (cmd === "brew" ? "/opt/homebrew/bin/brew" : null),
				},
			);
			expect(plan.canInstall).toBe(true);
			expect(plan.steps[0].packageManager).toBe("brew");
			expect(plan.steps[0].installer).toBeUndefined();
			expect(plan.steps[0].command).toBe("brew install wabt");
		});

		it("can download and extract portable tool with wrapper shims", async () => {
			const toolsDir = path.join(tempDir, "tools");

			const mockJarContent = await buildMockJar("com.android.tools.build.bundletool.BundleToolMain");
			const mockFetch = async () => {
				return new Response(mockJarContent, {
					status: 200,
					statusText: "OK",
				});
			};

			const result = await installPortableTool("bundletool", {
				targetDir: toolsDir,
				fetch: mockFetch,
			});

			expect(result.success).toBe(true);
			const expectedBat = path.join(toolsDir, "bundletool", "bundletool.bat");
			expect(fs.existsSync(expectedBat)).toBe(true);
			const batContent = fs.readFileSync(expectedBat, "utf8");
			expect(batContent).toContain("bundletool-all.jar");
		});
	});

	describe("4. Binwalk Cargo Route", () => {
		it("configures cargo install for binwalk and avoids broken pip", () => {
			const binwalk = SKILL_TOOL_CATALOG.binwalk;
			expect(binwalk).toBeDefined();

			const win32Cmds = binwalk.installCommands?.win32 ?? [];
			expect(win32Cmds.some(c => c.manager === "cargo")).toBe(true);
			expect(win32Cmds.some(c => c.manager === "pip")).toBe(false);

			expect(binwalk.installHints?.win32?.join(" ")).toContain("cargo install binwalk");
		});
	});
});
