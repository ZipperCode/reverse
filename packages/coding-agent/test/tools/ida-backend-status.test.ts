import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as fsSync from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { execFileSync } from "node:child_process";
import { getIdaBackendStatus } from "@reverse/coding-agent/ida/install";
import { clearIdaRuntimeCache, IdaUnavailableError, resolveIdaRuntime } from "@reverse/coding-agent/ida/runtime";
import { checkReverseTools } from "@reverse/coding-agent/cli/setup-reverse";
import { getReverseInstallPlan, installReverseItem } from "@reverse/coding-agent/extensibility/reverse-tool-install";
import {
	checkToolRequirements,
	missingRequirementNotice,
} from "@reverse/coding-agent/extensibility/skill-requirements";
import { R2InspectTool, ReverseCapabilityTool, type ToolSession } from "@reverse/coding-agent/tools";
import { Settings } from "@reverse/coding-agent/config/settings";
import { $which, removeWithRetries } from "@reverse/utils";

function findCompatiblePython(): string | null {
	const envPy = process.env.PYTHON ?? Bun.env.PYTHON;
	if (envPy && fsSync.existsSync(envPy)) return envPy;
	for (const candidate of [
		"/opt/homebrew/bin/python3.12",
		"/usr/local/bin/python3.12",
		"/opt/homebrew/bin/python3.11",
		"/opt/homebrew/bin/python3.10",
	]) {
		if (fsSync.existsSync(candidate)) return candidate;
	}
	const whichPy3 = $which("python3");
	if (whichPy3) return whichPy3;
	return null;
}

function createStubs(dir: string, failOnImport = false): void {
	const stubPy = "class _Any: pass\n";
	fsSync.writeFileSync(path.join(dir, "_reverse_ida_stub.py"), stubPy);
	fsSync.writeFileSync(path.join(dir, "idapro.py"), "from _reverse_ida_stub import _Any\n");
	const domainDir = path.join(dir, "ida_domain");
	fsSync.mkdirSync(domainDir, { recursive: true });
	if (failOnImport) {
		fsSync.writeFileSync(
			path.join(domainDir, "__init__.py"),
			"raise RuntimeError('License verification failed for idalib')\n",
		);
	} else {
		fsSync.writeFileSync(path.join(domainDir, "__init__.py"), "import idapro\nclass Database: pass\n");
	}
}
function createSyntheticWheels(wheelsDir: string): void {
	fsSync.mkdirSync(wheelsDir, { recursive: true });
	execFileSync("python3", [
		"-c",
		`
import zipfile, os
w1 = os.path.join('${wheelsDir}', 'ida_domain-0.5.1-py3-none-any.whl')
with zipfile.ZipFile(w1, 'w') as z:
    z.writestr('ida_domain/__init__.py', 'import idapro\\nclass Database: pass\\n')
    z.writestr('ida_domain-0.5.1.dist-info/METADATA', 'Metadata-Version: 2.1\\nName: ida-domain\\nVersion: 0.5.1\\nRequires-Dist: idapro>=0.0.10\\n')
    z.writestr('ida_domain-0.5.1.dist-info/WHEEL', 'Wheel-Version: 1.0\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n')
    z.writestr('ida_domain-0.5.1.dist-info/RECORD', 'ida_domain/__init__.py,,\\nida_domain-0.5.1.dist-info/METADATA,,\\nida_domain-0.5.1.dist-info/WHEEL,,\\nida_domain-0.5.1.dist-info/RECORD,,\\n')

w2 = os.path.join('${wheelsDir}', 'idapro-0.0.12-py3-none-any.whl')
with zipfile.ZipFile(w2, 'w') as z:
    z.writestr('idapro.py', 'class _Any: pass\\n')
    z.writestr('idapro-0.0.12.dist-info/METADATA', 'Metadata-Version: 2.1\\nName: idapro\\nVersion: 0.0.12\\n')
    z.writestr('idapro-0.0.12.dist-info/WHEEL', 'Wheel-Version: 1.0\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n')
    z.writestr('idapro-0.0.12.dist-info/RECORD', 'idapro.py,,\\nidapro-0.0.12.dist-info/METADATA,,\\nidapro-0.0.12.dist-info/WHEEL,,\\nidapro-0.0.12.dist-info/RECORD,,\\n')
`,
	]);
}

function getSitePackagesDir(pythonPath: string): string {
	return execFileSync(pythonPath, ["-c", "import site; print(site.getsitepackages()[0])"], {
		encoding: "utf-8",
	}).trim();
}
function createTestSession(cwd: string, customSettings: Record<string, unknown> = {}): ToolSession {
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false, ...customSettings }),
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
			// Library presence alone does NOT make backend available when Python packages are missing:
			expect(statusWithIdalib.pythonAdapterReady).toBe(false);
			expect(statusWithIdalib.localDatabaseBackendAvailable).toBe(false);
			expect(statusWithIdalib.localDatabaseSupported).toBe(false);

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
			expect(statusIdalibOnly.pythonAdapterReady).toBe(false);
			expect(statusIdalibOnly.localDatabaseBackendAvailable).toBe(false);

			// Subtest 4: Neither
			const statusNeither = getIdaBackendStatus({
				platform: process.platform,
				installDir: path.join(tempDir, "missing"),
				which: () => null,
			});
			expect(statusNeither.guiAvailable).toBe(false);
			expect(statusNeither.idalibAvailable).toBe(false);

			// Subtest 5: GUI + idalib + Python adapter packages present
			const stubsDir = path.join(tempDir, "test-stubs");
			await fs.mkdir(stubsDir, { recursive: true });
			createStubs(stubsDir, false);
			const compPy = findCompatiblePython();
			if (compPy) {
				const statusReady = getIdaBackendStatus({
					platform: process.platform,
					installDir: guiDir,
					which: () => null,
					python: compPy,
					env: { PYTHONPATH: stubsDir },
				});
				expect(statusReady.guiAvailable).toBe(true);
				expect(statusReady.idalibAvailable).toBe(true);
				expect(statusReady.pythonAdapterReady).toBe(true);
				expect(statusReady.localDatabaseBackendAvailable).toBe(true);
				expect(statusReady.localDatabaseSupported).toBe(true);
			}
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
	it("enforces explicit interpreter precedence over ambient discovery", async () => {
		const basePython = findCompatiblePython();
		if (!basePython) return;

		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ida-precedence-test-"));
		try {
			const idaDir = path.join(tempDir, "ida");
			await fs.mkdir(idaDir, { recursive: true });
			const idalibFile =
				process.platform === "darwin"
					? "libidalib.dylib"
					: process.platform === "win32"
						? "idalib.dll"
						: "libidalib.so";
			await fs.writeFile(path.join(idaDir, idalibFile), "");

			const venvADir = path.join(tempDir, "venvA");
			const venvBDir = path.join(tempDir, "venvB");
			execFileSync(basePython, ["-m", "venv", venvADir, "--without-pip"]);
			execFileSync(basePython, ["-m", "venv", venvBDir, "--without-pip"]);

			const venvAPython = path.join(venvADir, "bin", process.platform === "win32" ? "python.exe" : "python");
			const venvBPython = path.join(venvBDir, "bin", process.platform === "win32" ? "python.exe" : "python");

			// Venv B has stubs, Venv A is empty
			const sitePackagesB = getSitePackagesDir(venvBPython);
			createStubs(sitePackagesB, false);

			// Probe targeting Venv B -> ready
			const statusB = getIdaBackendStatus({
				platform: process.platform,
				installDir: idaDir,
				python: venvBPython,
			});
			expect(statusB.pythonPath).toBe(venvBPython);
			expect(statusB.pythonAdapterReady).toBe(true);
			expect(statusB.localDatabaseBackendAvailable).toBe(true);

			// Probe targeting Venv A -> missing adapter
			const statusA = getIdaBackendStatus({
				platform: process.platform,
				installDir: idaDir,
				python: venvAPython,
			});
			expect(statusA.pythonPath).toBe(venvAPython);
			expect(statusA.pythonAdapterReady).toBe(false);
			expect(statusA.localDatabaseBackendAvailable).toBe(false);

			// Setup reverse check targets configured ida.python explicitly
			const settings = Settings.isolated({ "ida.installDir": idaDir, "ida.python": venvAPython });
			const report = checkReverseTools({ settings, cwd: tempDir });
			const idaTool = report.tools.find(t => t.id === "ida");
			expect(idaTool?.status).toBe("missing");
			expect(idaTool?.packageManager).toBe("pip");
			expect(idaTool?.installArgv).toEqual([venvAPython, "-m", "pip", "install", "ida-domain==0.5.1"]);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("distinguishes module import failure from missing packages without claiming pip fixes it", async () => {
		const basePython = findCompatiblePython();
		if (!basePython) return;

		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ida-import-error-test-"));
		try {
			const idaDir = path.join(tempDir, "ida");
			await fs.mkdir(idaDir, { recursive: true });
			const idalibFile =
				process.platform === "darwin"
					? "libidalib.dylib"
					: process.platform === "win32"
						? "idalib.dll"
						: "libidalib.so";
			await fs.writeFile(path.join(idaDir, idalibFile), "");

			const venvDir = path.join(tempDir, "venv");
			execFileSync(basePython, ["-m", "venv", venvDir, "--without-pip"]);
			const venvPython = path.join(venvDir, "bin", process.platform === "win32" ? "python.exe" : "python");

			// Stubs throw runtime error during import
			const sitePackages = getSitePackagesDir(venvPython);
			createStubs(sitePackages, true);
			// Stubs throw runtime error during import
			const status = getIdaBackendStatus({
				platform: process.platform,
				installDir: idaDir,
				python: venvPython,
			});
			expect(status.idalibAvailable).toBe(true);
			expect(status.pythonAdapterReady).toBe(false);
			expect(status.localDatabaseBackendAvailable).toBe(false);
			expect(status.adapterErrorType).toBe("import_error");
			expect(status.adapterError).toContain("License verification failed for idalib");
			expect(status.missingPackages).toBeUndefined();

			// Setup report must NOT offer a pip repair command for import failures
			const settings = Settings.isolated({ "ida.installDir": idaDir, "ida.python": venvPython });
			const report = checkReverseTools({ settings, cwd: tempDir });
			const idaTool = report.tools.find(t => t.id === "ida");
			expect(idaTool?.status).toBe("missing");
			expect(idaTool?.packageManager).toBeNull();
			expect(idaTool?.installCommand).toBeNull();
			expect(idaTool?.manualInstructions).toContain("License verification failed for idalib");

			// Plan must report canInstall: false
			const plan = getReverseInstallPlan(idaTool!, { report });
			expect(plan.canInstall).toBe(false);
			expect(plan.reason).toContain("License verification failed for idalib");

			// Native resolveIdaRuntime throws IdaUnavailableError with license diagnostic
			clearIdaRuntimeCache();
			const session = createTestSession(tempDir, { "ida.installDir": idaDir, "ida.python": venvPython });
			await expect(resolveIdaRuntime(session)).rejects.toThrow(IdaUnavailableError);
			try {
				await resolveIdaRuntime(session);
			} catch (err) {
				expect((err as Error).message).toContain("License verification failed for idalib");
				expect((err as Error).message).toContain("Verify IDA license");
			}
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("generates actionable repair plan and successfully reprobes after repair", async () => {
		const basePython = findCompatiblePython();
		if (!basePython) return;

		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ida-repair-flow-test-"));
		try {
			const idaDir = path.join(tempDir, "ida");
			await fs.mkdir(idaDir, { recursive: true });
			const idalibFile =
				process.platform === "darwin"
					? "libidalib.dylib"
					: process.platform === "win32"
						? "idalib.dll"
						: "libidalib.so";
			await fs.writeFile(path.join(idaDir, idalibFile), "");

			const venvDir = path.join(tempDir, "venv");
			execFileSync(basePython, ["-m", "venv", venvDir]);
			const venvPython = path.join(venvDir, "bin", process.platform === "win32" ? "python.exe" : "python");
			const wheelsDir = path.join(tempDir, "wheels");
			createSyntheticWheels(wheelsDir);

			// 1. Initial state: missing packages
			clearIdaRuntimeCache();
			const settings = Settings.isolated({ "ida.installDir": idaDir, "ida.python": venvPython });
			const initialReport = checkReverseTools({ settings, cwd: tempDir });
			const toolItem = initialReport.tools.find(t => t.id === "ida")!;
			expect(toolItem.status).toBe("missing");
			expect(toolItem.packageManager).toBe("pip");
			expect(toolItem.installArgv).toEqual([venvPython, "-m", "pip", "install", "ida-domain==0.5.1"]);

			// 2. Generate install plan
			const plan = getReverseInstallPlan(toolItem, { report: initialReport });
			expect(plan.canInstall).toBe(true);
			expect(plan.steps).toHaveLength(1);
			expect(plan.steps[0].id).toBe("ida");
			expect(plan.steps[0].packageManager).toBe("pip");
			expect(plan.steps[0].argv).toEqual([venvPython, "-m", "pip", "install", "ida-domain==0.5.1"]);

			// 3. Native resolve before repair: surfaces repair route
			const session = createTestSession(tempDir, { "ida.installDir": idaDir, "ida.python": venvPython });
			try {
				await resolveIdaRuntime(session);
				expect.unreachable("resolveIdaRuntime should have thrown");
			} catch (err) {
				expect(err).toBeInstanceOf(IdaUnavailableError);
				expect((err as Error).message).toContain(`${venvPython} -m pip install ida-domain==0.5.1`);
			}

			// 4. Execute repair action into target venv via real pip subprocess
			const installResult = await installReverseItem(toolItem, {
				plan,
				settings,
				cwd: tempDir,
				env: {
					...process.env,
					PIP_NO_INDEX: "1",
					PIP_FIND_LINKS: wheelsDir,
				},
			});
			expect(installResult.success).toBe(true);
			// 5. Reprobe after repair confirms tool is installed and backend is available
			const repairedReport = checkReverseTools({ settings, cwd: tempDir });
			const repairedTool = repairedReport.tools.find(t => t.id === "ida")!;
			expect(repairedTool.status).toBe("installed");
			expect(repairedTool.secondaryMissing).toBeUndefined();

			const repairedBackend = getIdaBackendStatus({
				platform: process.platform,
				installDir: idaDir,
				python: venvPython,
			});
			expect(repairedBackend.idalibAvailable).toBe(true);
			expect(repairedBackend.pythonAdapterReady).toBe(true);
			expect(repairedBackend.localDatabaseBackendAvailable).toBe(true);
			expect(repairedBackend.localDatabaseSupported).toBe(true);

			// 6. Native runtime resolves successfully
			clearIdaRuntimeCache();
			const runtime = await resolveIdaRuntime(session);
			expect(runtime.pythonPath).toBe(venvPython);
			expect(runtime.env.IDADIR).toBe(idaDir);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("does not offer automated pip repair when IDA install is GUI-only without idalib", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ida-gui-only-test-"));
		try {
			const guiDir = path.join(tempDir, "ida-gui");
			await fs.mkdir(guiDir, { recursive: true });
			const idaBin = process.platform === "win32" ? "ida64.exe" : "ida64";
			await fs.writeFile(path.join(guiDir, idaBin), "");

			const settings = Settings.isolated({ "ida.installDir": guiDir });
			const report = checkReverseTools({ settings, cwd: tempDir });
			const idaTool = report.tools.find(t => t.id === "ida");

			expect(idaTool?.status).toBe("missing");
			expect(idaTool?.packageManager).toBeNull();
			expect(idaTool?.installCommand).toBeNull();
			expect(idaTool?.installArgv).toBeNull();
			expect(idaTool?.manualInstructions).toContain("Commercial software");

			const plan = getReverseInstallPlan(idaTool!, { report, settings });
			expect(plan.canInstall).toBe(false);
			expect(plan.steps).toHaveLength(0);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("preserves original import failure detail on RequirementStatus and missingRequirementNotice", async () => {
		const basePython = findCompatiblePython();
		if (!basePython) return;

		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ida-notice-test-"));
		try {
			const idaDir = path.join(tempDir, "ida");
			await fs.mkdir(idaDir, { recursive: true });
			const idalibFile =
				process.platform === "darwin"
					? "libidalib.dylib"
					: process.platform === "win32"
						? "idalib.dll"
						: "libidalib.so";
			await fs.writeFile(path.join(idaDir, idalibFile), "");

			const venvDir = path.join(tempDir, "venv");
			execFileSync(basePython, ["-m", "venv", venvDir, "--without-pip"]);
			const venvPython = path.join(venvDir, "bin", process.platform === "win32" ? "python.exe" : "python");
			const sitePackages = getSitePackagesDir(venvPython);

			createStubs(sitePackages, true);

			const settings = Settings.isolated({ "ida.installDir": idaDir, "ida.python": venvPython });
			const [status] = checkToolRequirements([{ id: "ida", optional: false }], {
				settings,
				cwd: tempDir,
			});

			expect(status.foundPath).toBe(idaDir);
			expect(status.secondaryMissing).toContain("ida-python-adapter");
			expect(status.adapterError).toContain("License verification failed for idalib");

			const notice = missingRequirementNotice([status]);
			expect(notice).toBeDefined();
			expect(notice).toContain(
				"ida unavailable: Failed to import ida_domain: License verification failed for idalib",
			);
			expect(notice).not.toContain("install: ida-domain");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("shares session settings shell environment for candidate resolution by default", async () => {
		const basePython = findCompatiblePython();
		if (!basePython) return;

		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ida-session-shell-env-"));
		try {
			const idaDir = path.join(tempDir, "ida");
			await fs.mkdir(idaDir, { recursive: true });
			const idalibFile =
				process.platform === "darwin"
					? "libidalib.dylib"
					: process.platform === "win32"
						? "idalib.dll"
						: "libidalib.so";
			await fs.writeFile(path.join(idaDir, idalibFile), "");

			const venvDir = path.join(tempDir, "venv");
			execFileSync(basePython, ["-m", "venv", venvDir, "--without-pip"]);
			const venvPython = path.join(venvDir, "bin", process.platform === "win32" ? "python.exe" : "python");

			const settings = Settings.isolated({ "ida.installDir": idaDir, "ida.python": venvPython });
			const report = checkReverseTools({ settings, cwd: tempDir });
			const idaTool = report.tools.find(t => t.id === "ida");

			expect(idaTool?.status).toBe("missing");
			expect(idaTool?.foundPath).toBe(idaDir);
			expect(idaTool?.packageManager).toBe("pip");
			expect(idaTool?.installArgv).toEqual([venvPython, "-m", "pip", "install", "ida-domain==0.5.1"]);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});
