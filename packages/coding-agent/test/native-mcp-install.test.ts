import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import {
	GHIDRA_MCP_VERSION,
	X64DBG_AUTOMATE_VERSION,
	checkPythonCompatibility,
	detectPeCrtFamily,
	getGhidraMcpInstallDir,
	getNativeMcpServer,
	getServiceVenvDir,
	getVenvBinaryPath,
	getVenvPythonPath,
	inspectNativeMcp,
	inspectPeImportedDlls,
	inspectWindowsRadare2CrtCompatibility,
	installNativeMcpService,
	isServerConfigIdentical,
	parsePythonVersion,
	parseTrustedR2mcpGitUrl,
	verifySha256,
} from "../src/extensibility/native-mcp-install";
import { checkReverseTools } from "../src/cli/setup-reverse";
import { writeMCPConfigFile } from "../src/mcp/config-writer";
import { getReverseInstallPlan } from "../src/extensibility/reverse-tool-install";
import type { MCPServerConfig, MCPServerConnection, MCPTransport } from "../src/mcp/types";

function createMockConnection(name: string, config: MCPServerConfig): MCPServerConnection {
	const transport: MCPTransport = {
		connected: true,
		request: async <T = unknown>() => ({}) as T,
		notify: async () => {},
		close: async () => {},
	};
	return {
		name,
		config,
		transport,
		serverInfo: {
			name,
			version: "1.0.0",
		},
		capabilities: {
			tools: {},
		},
	};
}

describe("native MCP Python compatibility check", () => {
	it("parses valid python version output strings", () => {
		expect(parsePythonVersion("Python 3.11.4")).toEqual({ major: 3, minor: 11, micro: 4 });
		expect(parsePythonVersion("Python 3.12.0rc1")).toEqual({ major: 3, minor: 12, micro: 0 });
		expect(parsePythonVersion("3.10.9")).toEqual({ major: 3, minor: 10, micro: 9 });
		expect(parsePythonVersion("invalid text")).toBeNull();
	});

	it("accepts supported Python >= 3.10 runtimes", () => {
		expect(checkPythonCompatibility("Python 3.10.12").compatible).toBe(true);
		expect(checkPythonCompatibility("Python 3.11.8").compatible).toBe(true);
		expect(checkPythonCompatibility("Python 3.12.3").compatible).toBe(true);
		expect(checkPythonCompatibility("Python 3.13.0").compatible).toBe(true);
		expect(checkPythonCompatibility("Python 3.14.0a1").compatible).toBe(true);
	});

	it("rejects unsupported Python versions (< 3.10)", () => {
		const oldPy = checkPythonCompatibility("Python 3.9.18");
		expect(oldPy.compatible).toBe(false);
		expect(oldPy.error).toContain(">= 3.10");

		const ancientPy = checkPythonCompatibility("Python 2.7.18");
		expect(ancientPy.compatible).toBe(false);
	});
});

describe("native MCP filesystem inspection (inspectNativeMcp)", () => {
	let tmpDir: string;

	beforeEach(async () => {
		tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "native-mcp-test-"));
	});

	afterEach(async () => {
		await fs.promises.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
	});

	it("returns installed: false when agent directory has no managed tools", () => {
		const x64Result = inspectNativeMcp("x64dbg", { agentDir: tmpDir });
		expect(x64Result.installed).toBe(false);
		expect(x64Result.missing).toContain("x64dbg_automate[mcp]");
		expect(x64Result.command).toBeUndefined();

		const ghidraResult = inspectNativeMcp("ghidra", { agentDir: tmpDir });
		expect(ghidraResult.installed).toBe(false);
		expect(ghidraResult.missing).toContain("ghidra_mcp");
		expect(ghidraResult.missing).toContain("GhidraMCP.jar");
		expect(ghidraResult.extensionJar).toBeUndefined();
	});

	it("detects installed x64dbg bridge when entrypoint exists in managed venv", async () => {
		const venvDir = getServiceVenvDir("x64dbg", tmpDir);
		const venvPy = getVenvPythonPath(venvDir);
		const binPath = getVenvBinaryPath(venvDir, "x64dbg-automate-mcp");
		await fs.promises.mkdir(path.dirname(venvPy), { recursive: true });
		await fs.promises.writeFile(venvPy, "#!/bin/sh\nexit 0;\n", { mode: 0o755 });
		await fs.promises.writeFile(binPath, "#!/bin/sh\nexit 0;\n", { mode: 0o755 });
		const result = inspectNativeMcp("x64dbg", { agentDir: tmpDir });
		expect(result.installed).toBe(true);
		expect(result.version).toBe(X64DBG_AUTOMATE_VERSION);
		expect(result.command).toBe(binPath);
		expect(result.missing.length).toBe(0);
	});

	it("requires both bridge executable and extension JAR for Ghidra MCP installation", async () => {
		const venvDir = getServiceVenvDir("ghidra", tmpDir);
		const venvPy = getVenvPythonPath(venvDir);
		const binPath = getVenvBinaryPath(venvDir, "ghidra-mcp");
		await fs.promises.mkdir(path.dirname(venvPy), { recursive: true });
		await fs.promises.writeFile(venvPy, "#!/bin/sh\nexit 0;\n", { mode: 0o755 });
		await fs.promises.writeFile(binPath, "#!/bin/sh\nexit 0;\n", { mode: 0o755 });
		const partialResult = inspectNativeMcp("ghidra", { agentDir: tmpDir });
		expect(partialResult.installed).toBe(false);
		expect(partialResult.missing).toContain("GhidraMCP.jar");

		// Add extension JAR
		const ghidraDir = getGhidraMcpInstallDir(tmpDir);
		const jarPath = path.join(ghidraDir, "extension", "GhidraMCP.jar");
		await fs.promises.mkdir(path.dirname(jarPath), { recursive: true });
		await fs.promises.writeFile(jarPath, Buffer.from("PK\x03\x04mockjar"));

		const fullResult = inspectNativeMcp("ghidra", { agentDir: tmpDir });
		expect(fullResult.installed).toBe(true);
		expect(fullResult.version).toBe(GHIDRA_MCP_VERSION);
		expect(fullResult.extensionJar).toBe(jarPath);
		expect(fullResult.missing.length).toBe(0);
	});
});

describe("checksum verification", () => {
	it("correctly verifies SHA256 hash match", () => {
		const data = Buffer.from("test payload for sha256");
		const hash = crypto.createHash("sha256").update(data).digest("hex");
		expect(verifySha256(data, hash)).toBe(true);
		expect(verifySha256(data, hash.toUpperCase())).toBe(true);
		expect(verifySha256(data, "0000000000000000000000000000000000000000000000000000000000000000")).toBe(false);
	});
});

describe("native MCP installation flow guards", () => {
	let tmpDir: string;

	beforeEach(async () => {
		tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "native-install-guard-"));
	});

	afterEach(async () => {
		await fs.promises.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
	});

	it("aborts immediately when AbortSignal is pre-triggered without downloading", async () => {
		const controller = new AbortController();
		controller.abort(new Error("Operation cancelled by user"));

		let fetchCalled = false;
		await expect(
			installNativeMcpService("ghidra", {
				agentDir: tmpDir,
				signal: controller.signal,
				fetch: async () => {
					fetchCalled = true;
					throw new Error("Should not fetch when aborted");
				},
			}),
		).rejects.toThrow("Operation cancelled by user");

		expect(fetchCalled).toBe(false);
	});

	it("rejects installation if server name is disabled in disabledServers", async () => {
		const mcpJsonPath = path.join(tmpDir, "mcp.json");
		await writeMCPConfigFile(mcpJsonPath, {
			mcpServers: {},
			disabledServers: ["x64dbg"],
		});

		await expect(
			installNativeMcpService("x64dbg", {
				agentDir: tmpDir,
			}),
		).rejects.toThrow('MCP server "x64dbg" is currently disabled');
	});

	it("rejects installation if conflicting server configuration already exists", async () => {
		const mcpJsonPath = path.join(tmpDir, "mcp.json");
		await writeMCPConfigFile(mcpJsonPath, {
			mcpServers: {
				ghidra: {
					type: "stdio",
					command: "/custom/unrelated/ghidra_mcp",
					args: ["--custom"],
				},
			},
		});

		await expect(
			installNativeMcpService("ghidra", {
				agentDir: tmpDir,
			}),
		).rejects.toThrow('Server "ghidra" already exists in');
	});

	it("fails installation if verification handshake returns zero tools", async () => {
		const mockExec = async (cmd: string, args: string[]) => {
			if (args.includes("-V")) {
				return { exitCode: 0, stdout: "Python 3.12.2\n", stderr: "" };
			}
			// Simulate venv creation and entrypoint in service-isolated venv
			const venvDir = getServiceVenvDir("x64dbg", tmpDir);
			const venvPy = getVenvPythonPath(venvDir);
			const binPath = getVenvBinaryPath(venvDir, "x64dbg-automate-mcp");
			await fs.promises.mkdir(path.dirname(venvPy), { recursive: true });
			await fs.promises.writeFile(venvPy, "#!/bin/sh\nexit 0;\n", { mode: 0o755 });
			await fs.promises.writeFile(binPath, "#!/bin/sh\nexit 0;\n", { mode: 0o755 });
			return { exitCode: 0, stdout: "Successfully installed\n", stderr: "" };
		};

		await expect(
			installNativeMcpService("x64dbg", {
				agentDir: tmpDir,
				execCommand: mockExec,
				mcpConnect: async (name, config) => createMockConnection(name, config),
				mcpListTools: async () => [], // Empty tools array
				mcpDisconnect: async () => {},
			}),
		).rejects.toThrow("exposed zero tools");

		// Config file should NOT be written if handshake failed
		const configExists = fs.existsSync(path.join(tmpDir, "mcp.json"));
		expect(configExists).toBe(false);
	});
});

describe("isServerConfigIdentical normalization and conflict detection", () => {
	it("treats active config with enabled: true identical to default omitted enabled", () => {
		const targetConfig = getNativeMcpServer("x64dbg", { agentDir: "/mock/agent" });
		const persistedConfig = {
			...targetConfig,
			enabled: true,
		};

		expect(isServerConfigIdentical(persistedConfig, targetConfig)).toBe(true);
		expect(isServerConfigIdentical(targetConfig, persistedConfig)).toBe(true);
	});

	it("detects conflict when command or arguments differ", () => {
		const targetConfig = getNativeMcpServer("x64dbg", { agentDir: "/mock/agent" });
		const conflictingCommand = {
			...targetConfig,
			command: "/different/python",
		};
		const conflictingArgs = {
			...targetConfig,
			args: ["-c", "from malicious import exploit"],
		};

		expect(isServerConfigIdentical(conflictingCommand, targetConfig)).toBe(false);
		expect(isServerConfigIdentical(conflictingArgs, targetConfig)).toBe(false);
	});

	it("detects conflict when environment variables differ", () => {
		const targetConfig = getNativeMcpServer("x64dbg", { agentDir: "/mock/agent" });
		const withCustomEnv = {
			...targetConfig,
			env: {
				X64DBG_PATH: "C:\\custom\\x64dbg.exe",
			},
		};

		expect(isServerConfigIdentical(withCustomEnv, targetConfig)).toBe(false);
	});
});

describe("checkReverseTools inspection for native MCP", () => {
	it("checkReverseTools reports truthful read-only inspection for native services without spawning network", () => {
		const report = checkReverseTools({ agentDir: "/nonexistent/test/agent/dir" });
		const x64dbgStatus = report.services.find(s => s.id === "x64dbg-mcp");
		const ghidraStatus = report.services.find(s => s.id === "ghidra-mcp");
		const r2mcpStatus = report.services.find(s => s.id === "r2mcp");

		expect(x64dbgStatus).toBeDefined();
		expect(x64dbgStatus?.installed).toBe(false);
		expect(x64dbgStatus?.connection).toBe("unknown");

		expect(ghidraStatus).toBeDefined();
		expect(ghidraStatus?.installed).toBe(false);
		expect(ghidraStatus?.connection).toBe("unknown");

		expect(r2mcpStatus).toBeDefined();
		expect(r2mcpStatus?.connection).toBe("unknown");
	});
});
describe("Reverse Install Planner preflight checks for native MCP", () => {
	let tmpDir: string;

	beforeEach(async () => {
		tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "native-plan-preflight-"));
	});

	afterEach(async () => {
		await fs.promises.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
	});

	it("preflight catches disabled server in config before downloading dependencies", async () => {
		const userConfigPath = path.join(tmpDir, "mcp.json");
		await writeMCPConfigFile(userConfigPath, {
			mcpServers: {},
			disabledServers: ["x64dbg"],
		});

		const report = checkReverseTools({ agentDir: tmpDir });
		const serviceItem = report.services.find(s => s.id === "x64dbg-mcp")!;
		const plan = getReverseInstallPlan(serviceItem, { agentDir: tmpDir });

		expect(plan.canInstall).toBe(false);
		expect(plan.reason).toContain("disabled in MCP config");
		expect(plan.steps.length).toBe(0);
	});

	it("preflight catches conflicting existing configuration before planning install steps", async () => {
		const userConfigPath = path.join(tmpDir, "mcp.json");
		await writeMCPConfigFile(userConfigPath, {
			mcpServers: {
				ghidra: {
					type: "stdio",
					command: "/conflicting/path/to/ghidra",
					args: ["--foreign"],
				},
			},
		});

		const report = checkReverseTools({ agentDir: tmpDir });
		const serviceItem = report.services.find(s => s.id === "ghidra-mcp")!;
		const plan = getReverseInstallPlan(serviceItem, { agentDir: tmpDir });

		expect(plan.canInstall).toBe(false);
		expect(plan.reason).toContain("conflicting configuration");
		expect(plan.steps.length).toBe(0);
	});
});

function buildSyntheticPe64WithImports(dllNames: string[]): Buffer {
	const buf = Buffer.alloc(0x600, 0);
	// DOS header
	buf[0] = 0x4d; // 'M'
	buf[1] = 0x5a; // 'Z'
	const peOffset = 0x80;
	buf.writeUInt32LE(peOffset, 0x3c);

	// PE signature + COFF header (24 bytes)
	buf[peOffset] = 0x50; // 'P'
	buf[peOffset + 1] = 0x45; // 'E'
	buf.writeUInt16LE(0x8664, peOffset + 4); // Machine = AMD64
	buf.writeUInt16LE(1, peOffset + 6); // NumberOfSections = 1
	const optHeaderSize = 240;
	buf.writeUInt16LE(optHeaderSize, peOffset + 20);

	// Optional header PE32+ (240 bytes)
	const optBase = peOffset + 24;
	buf.writeUInt16LE(0x20b, optBase); // Magic = PE32+
	buf.writeUInt32LE(16, optBase + 108); // NumberOfRvaAndSizes = 16
	const sectionRva = 0x2000;
	const sectionRawOffset = 0x200;
	const sectionRawSize = 0x400;
	buf.writeUInt32LE(sectionRva, optBase + 112 + 8); // DataDirectory[1].VirtualAddress (Import Table)
	buf.writeUInt32LE((dllNames.length + 1) * 20, optBase + 112 + 12);

	// Section header (.idata)
	const secBase = optBase + optHeaderSize;
	buf.write(".idata", secBase, "ascii");
	buf.writeUInt32LE(sectionRawSize, secBase + 8); // VirtualSize
	buf.writeUInt32LE(sectionRva, secBase + 12); // VirtualAddress
	buf.writeUInt32LE(sectionRawSize, secBase + 16); // SizeOfRawData
	buf.writeUInt32LE(sectionRawOffset, secBase + 20); // PointerToRawData

	// Import descriptors + DLL strings inside .idata
	let stringCursor = sectionRawOffset + (dllNames.length + 1) * 20;
	for (let i = 0; i < dllNames.length; i++) {
		const descOffset = sectionRawOffset + i * 20;
		const nameRva = sectionRva + (stringCursor - sectionRawOffset);
		buf.writeUInt32LE(nameRva, descOffset + 12); // Name RVA
		buf.writeUInt32LE(sectionRva + 0x300 + i * 8, descOffset + 16); // FirstThunk
		const written = buf.write(dllNames[i], stringCursor, "ascii");
		buf[stringCursor + written] = 0;
		stringCursor += written + 1;
	}

	return buf;
}

describe("Windows radare2 / r2mcp PE CRT inspection and remediation (#4)", () => {
	let tmpDir: string;

	beforeEach(async () => {
		tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "r2mcp-crt-test-"));
	});

	afterEach(async () => {
		await fs.promises.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
	});

	it("detects msvcrt vs UCRT mismatch from PE import descriptors and marks inspectNativeMcp not installed", async () => {
		const r2BinDir = path.join(tmpDir, "radare2", "bin");
		const r2pmBinDir = path.join(tmpDir, "r2pm-bin");
		await fs.promises.mkdir(r2BinDir, { recursive: true });
		await fs.promises.mkdir(r2pmBinDir, { recursive: true });

		const r2Exe = path.join(r2BinDir, "r2.exe");
		const r2pmExe = path.join(r2BinDir, "r2pm.exe");
		const rUtilDll = path.join(r2BinDir, "r_util.dll");
		const r2mcpExe = path.join(r2pmBinDir, "r2mcp.exe");

		const ucrtPe = buildSyntheticPe64WithImports([
			"KERNEL32.dll",
			"api-ms-win-crt-heap-l1-1-0.dll",
			"api-ms-win-crt-runtime-l1-1-0.dll",
			"vcruntime140.dll",
		]);
		const msvcrtPe = buildSyntheticPe64WithImports(["KERNEL32.dll", "msvcrt.dll", "r_core.dll", "r_util.dll"]);

		await fs.promises.writeFile(r2Exe, ucrtPe);
		await fs.promises.writeFile(r2pmExe, ucrtPe);
		await fs.promises.writeFile(rUtilDll, ucrtPe);
		await fs.promises.writeFile(r2mcpExe, msvcrtPe);

		expect(inspectPeImportedDlls(rUtilDll)).toEqual({
			isPe: true,
			importedDlls: [
				"kernel32.dll",
				"api-ms-win-crt-heap-l1-1-0.dll",
				"api-ms-win-crt-runtime-l1-1-0.dll",
				"vcruntime140.dll",
			],
			crtFamily: "ucrt",
		});
		expect(inspectPeImportedDlls(r2mcpExe).crtFamily).toBe("msvcrt");

		const compat = inspectWindowsRadare2CrtCompatibility(r2Exe, r2mcpExe);
		expect(compat.compatible).toBe(false);
		expect(compat.r2Crt).toBe("ucrt");
		expect(compat.pluginCrt).toBe("msvcrt");
		expect(compat.reason).toContain("-mcrtdll=ucrt");

		const whichMap: Record<string, string> = {
			r2: r2Exe,
			r2pm: r2pmExe,
			r2mcp: r2mcpExe,
		};
		const mismatchInspect = inspectNativeMcp("radare2", {
			agentDir: tmpDir,
			platform: "win32",
			env: { R2PM_BINDIR: r2pmBinDir, HOME: tmpDir },
			which: cmd => whichMap[cmd] ?? null,
		});
		expect(mismatchInspect.installed).toBe(false);
		expect(mismatchInspect.missing).toContain("r2mcp (CRT mismatch: r2mcp=msvcrt vs radare2=ucrt)");
		expect(mismatchInspect.details?.crtCompatible).toBe(false);

		// Replace r2mcp.exe with UCRT-linked PE
		await fs.promises.writeFile(
			r2mcpExe,
			buildSyntheticPe64WithImports(["KERNEL32.dll", "api-ms-win-crt-heap-l1-1-0.dll", "r_core.dll", "r_util.dll"]),
		);
		const matchedInspect = inspectNativeMcp("radare2", {
			agentDir: tmpDir,
			platform: "win32",
			env: { R2PM_BINDIR: r2pmBinDir, HOME: tmpDir },
			which: cmd => whichMap[cmd] ?? null,
		});
		expect(matchedInspect.installed).toBe(true);
		expect(matchedInspect.missing).toEqual([]);
		expect(matchedInspect.details?.crtCompatible).toBe(true);
	});

	it("does not classify non-PE or importless binaries as verified compatible", async () => {
		const fakeBin = path.join(tmpDir, "not-a-pe.bin");
		await fs.promises.writeFile(fakeBin, "#!/bin/sh\nexit 0\n");
		expect(inspectPeImportedDlls(fakeBin)).toEqual({
			isPe: false,
			importedDlls: [],
			crtFamily: "unknown",
		});
		expect(detectPeCrtFamily(["kernel32.dll", "user32.dll"])).toBe("unknown");
		expect(detectPeCrtFamily(["msvcrt.dll", "ucrtbase.dll"])).toBe("mixed");
		expect(parseTrustedR2mcpGitUrl('R2PM_GIT "https://github.com/dnakov/radare2-mcp"\n')).toBe(
			"https://github.com/dnakov/radare2-mcp",
		);
		expect(parseTrustedR2mcpGitUrl('R2PM_GIT "https://evil.example.com/radare2-mcp"\n')).toBeNull();
	});

	it("rebuilds r2mcp on Windows with Meson -mcrtdll=ucrt when r2pm deploys msvcrt-linked exe", async () => {
		const r2Prefix = path.join(tmpDir, "radare2");
		const r2BinDir = path.join(r2Prefix, "bin");
		const r2pmGitDir = path.join(tmpDir, "r2pm", "git");
		const r2pmBinDir = path.join(tmpDir, "r2pm", "bin");
		const r2mcpSrcDir = path.join(r2pmGitDir, "r2mcp");
		await fs.promises.mkdir(r2BinDir, { recursive: true });
		await fs.promises.mkdir(r2pmBinDir, { recursive: true });
		await fs.promises.mkdir(r2mcpSrcDir, { recursive: true });
		await fs.promises.writeFile(path.join(r2mcpSrcDir, "meson.build"), "project('r2mcp', 'c')\n");

		const r2Exe = path.join(r2BinDir, "r2.exe");
		const r2pmExe = path.join(r2BinDir, "r2pm.exe");
		const rUtilDll = path.join(r2BinDir, "r_util.dll");
		const mesonExe = path.join(r2BinDir, "meson.exe");

		const ucrtPe = buildSyntheticPe64WithImports([
			"KERNEL32.dll",
			"api-ms-win-crt-heap-l1-1-0.dll",
			"api-ms-win-crt-runtime-l1-1-0.dll",
		]);
		const msvcrtPe = buildSyntheticPe64WithImports(["KERNEL32.dll", "msvcrt.dll", "r_util.dll"]);

		await fs.promises.writeFile(r2Exe, ucrtPe);
		await fs.promises.writeFile(r2pmExe, ucrtPe);
		await fs.promises.writeFile(rUtilDll, ucrtPe);
		await fs.promises.writeFile(mesonExe, ucrtPe);

		const recordedCalls: Array<{ cmd: string; args: string[]; env?: Record<string, string | undefined> }> = [];
		const mockExec = async (
			cmd: string,
			args: string[],
			opts?: { cwd?: string; env?: Record<string, string | undefined> },
		) => {
			recordedCalls.push({ cmd, args, env: opts?.env });
			if (cmd === r2pmExe && args[0] === "-Uci" && args[1] === "r2mcp") {
				// Simulate r2pm deploying an incompatible msvcrt-linked r2mcp.exe
				await fs.promises.writeFile(path.join(r2pmBinDir, "r2mcp.exe"), msvcrtPe);
				return { exitCode: 0, stdout: "Installed r2mcp\n", stderr: "" };
			}
			if (cmd === r2pmExe && args[0] === "-H" && args[1] === "R2PM_GITDIR") {
				return { exitCode: 0, stdout: `${r2pmGitDir}\n`, stderr: "" };
			}
			if (cmd === r2pmExe && args[0] === "-H" && args[1] === "R2PM_BINDIR") {
				return { exitCode: 0, stdout: `${r2pmBinDir}\n`, stderr: "" };
			}
			if (cmd === r2Exe && args[0] === "-H" && args[1] === "R2_PREFIX") {
				return { exitCode: 0, stdout: `${r2Prefix}\n`, stderr: "" };
			}
			if (cmd === mesonExe && args[0] === "setup") {
				const buildDir = path.join(r2mcpSrcDir, "build-ucrt");
				await fs.promises.mkdir(buildDir, { recursive: true });
				await fs.promises.writeFile(path.join(buildDir, "build.ninja"), "# ninja\n");
				return { exitCode: 0, stdout: "The Meson build system\n", stderr: "" };
			}
			if (cmd === mesonExe && args[0] === "compile") {
				const buildDir = path.join(r2mcpSrcDir, "build-ucrt");
				await fs.promises.writeFile(path.join(buildDir, "r2mcp.exe"), ucrtPe);
				return { exitCode: 0, stdout: "[1/1] Linking target r2mcp.exe\n", stderr: "" };
			}
			return { exitCode: 1, stdout: "", stderr: `Unexpected command: ${cmd} ${args.join(" ")}` };
		};

		const whichMap: Record<string, string> = {
			r2: r2Exe,
			r2pm: r2pmExe,
			meson: mesonExe,
		};
		const result = await installNativeMcpService("radare2", {
			agentDir: tmpDir,
			cwd: tmpDir,
			platform: "win32",
			env: { R2PM_BINDIR: r2pmBinDir, HOME: tmpDir },
			which: cmd => whichMap[cmd] ?? null,
			execCommand: mockExec,
			mcpConnect: async (name, config) => createMockConnection(name, config),
			mcpListTools: async () => [
				{ name: "open_file", description: "Open file", inputSchema: { type: "object", properties: {} } },
			],
			mcpDisconnect: async () => {},
		});

		expect(result.installed).toBe(true);
		expect(result.tools).toEqual(["open_file"]);

		const r2pmCall = recordedCalls.find(c => c.cmd === r2pmExe && c.args[0] === "-Uci");
		expect(r2pmCall?.env?.CFLAGS).toContain("-mcrtdll=ucrt");
		expect(r2pmCall?.env?.LDFLAGS).toContain("-mcrtdll=ucrt");

		const mesonSetupCall = recordedCalls.find(c => c.cmd === mesonExe && c.args[0] === "setup");
		expect(mesonSetupCall).toBeDefined();
		expect(mesonSetupCall?.args).not.toContain("--reconfigure");
		expect(mesonSetupCall?.args).toContain("build-ucrt");
		expect(mesonSetupCall?.args).toContain("-Dc_args=-mcrtdll=ucrt");
		expect(mesonSetupCall?.args).toContain("-Dc_link_args=-mcrtdll=ucrt");

		// Rebuilt binary in R2PM_BINDIR is now UCRT-compatible
		expect(inspectPeImportedDlls(path.join(r2pmBinDir, "r2mcp.exe")).crtFamily).toBe("ucrt");

		// Second run with existing build-ucrt/build.ninja uses meson setup --reconfigure
		recordedCalls.length = 0;
		await installNativeMcpService("radare2", {
			agentDir: tmpDir,
			cwd: tmpDir,
			platform: "win32",
			env: { R2PM_BINDIR: r2pmBinDir, HOME: tmpDir },
			which: cmd => whichMap[cmd] ?? null,
			execCommand: mockExec,
			mcpConnect: async (name, config) => createMockConnection(name, config),
			mcpListTools: async () => [
				{ name: "open_file", description: "Open file", inputSchema: { type: "object", properties: {} } },
			],
			mcpDisconnect: async () => {},
		});
		const secondSetupCall = recordedCalls.find(c => c.cmd === mesonExe && c.args[0] === "setup");
		expect(secondSetupCall?.args.slice(0, 3)).toEqual(["setup", "--reconfigure", "build-ucrt"]);
	});

	it("verifies radare2 MCP readiness via real child-process stdio handshake and rejects pre-initialize crash (exit 116)", async () => {
		const binDir = path.join(tmpDir, "bin");
		await fs.promises.mkdir(binDir, { recursive: true });

		const r2Script = path.join(binDir, "r2");
		const r2pmScript = path.join(binDir, "r2pm");
		const r2mcpScript = path.join(binDir, "r2mcp");
		const fixturePath = path.resolve(import.meta.dir, "fixtures/mock-native-mcp.ts");

		await fs.promises.writeFile(r2Script, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
		await fs.promises.writeFile(r2mcpScript, "#!/bin/sh\nexit 0\n", { mode: 0o755 });

		// 1. Simulate #4 pre-initialize crash (exit code 116 after logging sandbox grain to stderr)
		await fs.promises.writeFile(
			r2pmScript,
			`#!/bin/sh
if [ "$1" = "-Uci" ]; then
  exit 0
fi
if [ "$1" = "-r" ] && [ "$2" = "r2mcp" ]; then
  echo "INFO: [R2MCP] r2mcp starting" >&2
  echo "INFO: [R2MCP] sandbox grain: exec,socket" >&2
  exit 116
fi
exit 1
`,
			{ mode: 0o755 },
		);

		const isolatedEnv = {
			...process.env,
			PATH: `${binDir}${path.delimiter}${process.env.PATH ?? ""}`,
			R2PM_BINDIR: binDir,
			HOME: tmpDir,
		};
		const whichLookup = (cmd: string) => {
			if (cmd === "r2") return r2Script;
			if (cmd === "r2pm") return r2pmScript;
			if (cmd === "r2mcp") return r2mcpScript;
			return null;
		};

		await expect(
			installNativeMcpService("radare2", {
				agentDir: tmpDir,
				cwd: tmpDir,
				platform: "darwin",
				env: isolatedEnv,
				which: whichLookup,
			}),
		).rejects.toThrow(/116|sandbox grain: exec,socket/);

		// Config must NOT be written when real handshake fails
		expect(fs.existsSync(path.join(tmpDir, "mcp.json"))).toBe(false);

		// 2. Replace r2pm -r r2mcp with real stdio MCP server child process (mock-native-mcp.ts)
		await fs.promises.writeFile(
			r2pmScript,
			`#!/bin/sh
if [ "$1" = "-Uci" ]; then
  exit 0
fi
if [ "$1" = "-r" ] && [ "$2" = "r2mcp" ]; then
  MOCK_NATIVE_MODE=radare2 exec "${process.execPath}" "${fixturePath}"
fi
exit 1
`,
			{ mode: 0o755 },
		);

		const okResult = await installNativeMcpService("radare2", {
			agentDir: tmpDir,
			cwd: tmpDir,
			platform: "darwin",
			env: isolatedEnv,
			which: whichLookup,
		});

		expect(okResult.installed).toBe(true);
		expect(okResult.tools).toEqual(["open_file", "show_info"]);
		expect(okResult.server).toEqual({
			type: "stdio",
			command: "r2pm",
			args: ["-r", "r2mcp"],
		});

		const persisted = JSON.parse(await fs.promises.readFile(path.join(tmpDir, "mcp.json"), "utf-8"));
		expect(persisted.mcpServers.radare2).toEqual({
			type: "stdio",
			command: "r2pm",
			args: ["-r", "r2mcp"],
		});
	});
});
