/**
 * Runtime Toolchain Resolver and Installer for Flutter (Blutter),
 * React Native (hbctool, hermes-dec), and Unity (Il2CppDumper).
 *
 * Provides authoritative resolution, pinned versions, verified recipes,
 * and executable wrapper generation for CLI and TUI setup surfaces.
 *
 * Pinned releases and licenses:
 * - Blutter: worawit/blutter (commit 43763784, MIT)
 * - hbctool: bongtrop/hbctool (v0.1.6, MIT)
 * - hermes-dec: P1sec/hermes-dec (v0.1.8, GPL-3.0)
 * - Il2CppDumper: Perfare/Il2CppDumper (v6.7.46, MIT)
 */

import * as fs from "node:fs/promises";
import * as fsSync from "node:fs";
import * as path from "node:path";
import { $which, getAgentDir } from "@reverse/utils";
import type { SkillRequirementWhich } from "./skill-requirements";
import type { SkillToolPlatform } from "./skill-tool-catalog";
import { runSubprocess } from "./triton-source-install";
import { ZipParser } from "../tools/android-package-inspect";
// ============================================================================
export const BLUTTER_VERSION = "0.1.0";
export const BLUTTER_COMMIT = "4a60ac648bf448c5a7596437243bcd0b9376fdf0";
export const BLUTTER_REPO_URL = "https://github.com/worawit/blutter.git";
export const BLUTTER_LICENSE = "MIT";

export const HBCTOOL_VERSION = "0.1.5";
export const HBCTOOL_PYPI_SPEC = `hbctool==${HBCTOOL_VERSION}`;
export const HBCTOOL_LICENSE = "MIT";
export const HERMES_DEC_VERSION = "0.1.8";
export const HERMES_DEC_PYPI_SPEC = `hermes-dec==${HERMES_DEC_VERSION}`;
export const HERMES_DEC_LICENSE = "AGPL-3.0-or-later";

export const IL2CPP_DUMPER_VERSION = "6.7.46";
export const IL2CPP_DUMPER_RELEASE_TAG = `v${IL2CPP_DUMPER_VERSION}`;
export const IL2CPP_DUMPER_NET6_ZIP_URL = `https://github.com/Perfare/Il2CppDumper/releases/download/${IL2CPP_DUMPER_RELEASE_TAG}/Il2CppDumper-net6-${IL2CPP_DUMPER_RELEASE_TAG}.zip`;
export const IL2CPP_DUMPER_WIN_ZIP_URL = `https://github.com/Perfare/Il2CppDumper/releases/download/${IL2CPP_DUMPER_RELEASE_TAG}/Il2CppDumper-win-${IL2CPP_DUMPER_RELEASE_TAG}.zip`;
export const IL2CPP_DUMPER_LICENSE = "MIT";

export type RuntimeToolId = "blutter" | "hbctool" | "hermes-dec" | "il2cppdumper";

// ============================================================================
// Interfaces
// ============================================================================

export interface RuntimeToolResolveOptions {
	agentDir?: string;
	which?: SkillRequirementWhich;
	platform?: SkillToolPlatform;
	env?: Record<string, string | undefined>;
}

export interface RuntimeToolResolved {
	id: RuntimeToolId;
	path: string;
	version?: string;
	binDir: string;
	managed: boolean;
}

export interface RuntimeToolInstallOptions {
	agentDir?: string;
	onLog?: (message: string) => void;
	signal?: AbortSignal;
	timeoutMs?: number;
	which?: SkillRequirementWhich;
	platform?: SkillToolPlatform;
	env?: Record<string, string | undefined>;
}

export interface RuntimeToolInstallResult {
	success: boolean;
	id: RuntimeToolId;
	installDir: string;
	executablePath: string;
	error?: string;
}

// ============================================================================
// File & Process Helpers
// ============================================================================

function isExecutableRegularFile(filePath: string): boolean {
	try {
		const st = fsSync.statSync(filePath);
		if (!st.isFile()) return false;
		if (process.platform === "win32") return true;
		return (st.mode & 0o111) !== 0;
	} catch {
		return false;
	}
}

async function runCheckedSubprocess(
	argv: readonly string[],
	options?: {
		cwd?: string;
		env?: Record<string, string | undefined>;
		onLog?: (chunk: string) => void;
		signal?: AbortSignal;
		timeoutMs?: number;
	},
): Promise<string> {
	const res = await runSubprocess(argv, {
		cwd: options?.cwd,
		env: options?.env,
		onChunk: options?.onLog,
		signal: options?.signal,
		timeoutMs: options?.timeoutMs,
	});

	if (res.exitCode !== 0) {
		const errText = res.stderr.trim() || res.stdout.trim() || `Exit code ${res.exitCode}`;
		throw new Error(`Command failed [${argv.join(" ")}]: ${errText}`);
	}

	return res.stdout;
}

// ============================================================================
// Resolvers
// ============================================================================

/**
 * 解析 Blutter 可执行文件。
 * 若在 managed 目录找到带 manifest 的安装，返回 pinned 版本；
 * 若在 PATH 找到外部安装，不捏造版本 (返回 undefined)。
 */
export function resolveBlutter(options: RuntimeToolResolveOptions = {}): RuntimeToolResolved | null {
	const agentDir = options.agentDir ?? getAgentDir();
	const isWindows = (options.platform ?? process.platform) === "win32";

	// 1. Managed 工具目录
	const managedBin = path.join(agentDir, "tools", "blutter", "bin", isWindows ? "blutter.cmd" : "blutter");
	if (isExecutableRegularFile(managedBin)) {
		return {
			id: "blutter",
			path: managedBin,
			version: BLUTTER_VERSION,
			binDir: path.dirname(managedBin),
			managed: true,
		};
	}

	// 2. 环境变量 BLUTTER_HOME
	const env = options.env ?? process.env;
	const envHome = env.BLUTTER_HOME;
	if (envHome) {
		const envBin = path.join(envHome, "bin", isWindows ? "blutter.cmd" : "blutter");
		const envScript = path.join(envHome, "blutter.py");
		if (isExecutableRegularFile(envBin)) {
			return {
				id: "blutter",
				path: envBin,
				binDir: path.dirname(envBin),
				managed: false,
			};
		}
		if (isExecutableRegularFile(envScript)) {
			return {
				id: "blutter",
				path: envScript,
				binDir: envHome,
				managed: false,
			};
		}
	}

	// 3. 系统 PATH
	const whichFn = options.which ?? ((cmd, opts) => $which(cmd, opts));
	for (const candidate of isWindows ? ["blutter.cmd", "blutter.exe", "blutter.py"] : ["blutter", "blutter.py"]) {
		const found = whichFn(candidate);
		if (found && isExecutableRegularFile(found)) {
			return {
				id: "blutter",
				path: found,
				binDir: path.dirname(found),
				managed: false,
			};
		}
	}

	return null;
}

/** 解析 hbctool 可执行文件 */
export function resolveHbctool(options: RuntimeToolResolveOptions = {}): RuntimeToolResolved | null {
	const agentDir = options.agentDir ?? getAgentDir();
	const isWindows = (options.platform ?? process.platform) === "win32";

	// 1. Managed venv
	const venvBinDir = path.join(agentDir, "tools", "hbctool", ".venv", isWindows ? "Scripts" : "bin");
	const managedExe = path.join(venvBinDir, isWindows ? "hbctool.exe" : "hbctool");
	if (isExecutableRegularFile(managedExe)) {
		return {
			id: "hbctool",
			path: managedExe,
			version: HBCTOOL_VERSION,
			binDir: venvBinDir,
			managed: true,
		};
	}

	const managedWrapper = path.join(agentDir, "tools", "hbctool", "bin", isWindows ? "hbctool.cmd" : "hbctool");
	if (isExecutableRegularFile(managedWrapper)) {
		return {
			id: "hbctool",
			path: managedWrapper,
			version: HBCTOOL_VERSION,
			binDir: path.dirname(managedWrapper),
			managed: true,
		};
	}

	// 2. 系统 PATH (不假定版本)
	const whichFn = options.which ?? ((cmd, opts) => $which(cmd, opts));
	const pathBin = whichFn("hbctool");
	if (pathBin && isExecutableRegularFile(pathBin)) {
		return {
			id: "hbctool",
			path: pathBin,
			binDir: path.dirname(pathBin),
			managed: false,
		};
	}

	return null;
}

/** 解析 hermes-dec (hbc-disassembler) 可执行文件 */
export function resolveHermesDec(options: RuntimeToolResolveOptions = {}): RuntimeToolResolved | null {
	const agentDir = options.agentDir ?? getAgentDir();
	const isWindows = (options.platform ?? process.platform) === "win32";

	// 1. Managed venv
	const venvBinDir = path.join(agentDir, "tools", "hermes-dec", ".venv", isWindows ? "Scripts" : "bin");
	const managedExe = path.join(venvBinDir, isWindows ? "hbc-disassembler.exe" : "hbc-disassembler");
	if (isExecutableRegularFile(managedExe)) {
		return {
			id: "hermes-dec",
			path: managedExe,
			version: HERMES_DEC_VERSION,
			binDir: venvBinDir,
			managed: true,
		};
	}

	const managedWrapper = path.join(
		agentDir,
		"tools",
		"hermes-dec",
		"bin",
		isWindows ? "hbc-disassembler.cmd" : "hbc-disassembler",
	);
	if (isExecutableRegularFile(managedWrapper)) {
		return {
			id: "hermes-dec",
			path: managedWrapper,
			version: HERMES_DEC_VERSION,
			binDir: path.dirname(managedWrapper),
			managed: true,
		};
	}

	// 2. 系统 PATH (绝不把 hbctool 误认作 hermes-dec)
	const whichFn = options.which ?? ((cmd, opts) => $which(cmd, opts));
	for (const alt of ["hbc-disassembler", "hermes-dec.hbc-disassembler", "hermes-dec"]) {
		const found = whichFn(alt);
		if (found && isExecutableRegularFile(found) && !path.basename(found).toLowerCase().startsWith("hbctool")) {
			return {
				id: "hermes-dec",
				path: found,
				binDir: path.dirname(found),
				managed: false,
			};
		}
	}

	return null;
}

/** 解析 Il2CppDumper 可执行文件 */
export function resolveIl2CppDumper(options: RuntimeToolResolveOptions = {}): RuntimeToolResolved | null {
	const agentDir = options.agentDir ?? getAgentDir();
	const isWindows = (options.platform ?? process.platform) === "win32";

	// 1. Managed tools 目录
	const managedCandidates = [
		path.join(agentDir, "tools", "Il2CppDumper", "bin", isWindows ? "il2cppdumper.cmd" : "il2cppdumper"),
		path.join(agentDir, "tools", "Il2CppDumper", "Il2CppDumper.exe"),
		path.join(agentDir, "tools", "Il2CppDumper", "Il2CppDumper"),
	];

	for (const cand of managedCandidates) {
		if (isExecutableRegularFile(cand)) {
			return {
				id: "il2cppdumper",
				path: cand,
				version: IL2CPP_DUMPER_VERSION,
				binDir: path.dirname(cand),
				managed: true,
			};
		}
	}

	// 2. 系统 PATH
	const whichFn = options.which ?? ((cmd, opts) => $which(cmd, opts));
	for (const binName of ["Il2CppDumper", "il2cppdumper", "Il2CppDumper.exe"]) {
		const found = whichFn(binName);
		if (found && isExecutableRegularFile(found)) {
			return {
				id: "il2cppdumper",
				path: found,
				binDir: path.dirname(found),
				managed: false,
			};
		}
	}

	return null;
}

/** 统一解析 Runtime 工具 */
export function resolveRuntimeTool(
	id: RuntimeToolId,
	options: RuntimeToolResolveOptions = {},
): RuntimeToolResolved | null {
	switch (id) {
		case "blutter":
			return resolveBlutter(options);
		case "hbctool":
			return resolveHbctool(options);
		case "hermes-dec":
			return resolveHermesDec(options);
		case "il2cppdumper":
			return resolveIl2CppDumper(options);
	}
}

// ============================================================================
// Installers (带明确成功校验，绝不吞错假冒成功)
// ============================================================================

/** 安装 Blutter 到 managed tools 目录，创建专属 venv 并生成包装脚本 */
export async function installBlutter(options: RuntimeToolInstallOptions = {}): Promise<RuntimeToolInstallResult> {
	const agentDir = options.agentDir ?? getAgentDir();
	const installDir = path.join(agentDir, "tools", "blutter");
	const binDir = path.join(installDir, "bin");
	const isWindows = (options.platform ?? process.platform) === "win32";
	const log = options.onLog ?? (() => {});

	try {
		// 1. 若目录不存在，先创建父目录并克隆到目标目录 (不要在 clone 前预建 binDir 导致目标目录非空报错)
		if (!fsSync.existsSync(path.join(installDir, ".git"))) {
			await fs.mkdir(path.dirname(installDir), { recursive: true });
			log(`Cloning Blutter repository (pinned commit ${BLUTTER_COMMIT.slice(0, 8)})...`);
			await runCheckedSubprocess(["git", "clone", BLUTTER_REPO_URL, installDir], {
				onLog: log,
				signal: options.signal,
			});
		}

		log(`Checking out pinned commit ${BLUTTER_COMMIT}...`);
		await runCheckedSubprocess(["git", "checkout", BLUTTER_COMMIT], {
			cwd: installDir,
			onLog: log,
			signal: options.signal,
		});

		// 2. 创建独立 Python venv
		const venvDir = path.join(installDir, ".venv");
		const venvBinDir = path.join(venvDir, isWindows ? "Scripts" : "bin");
		const venvPy = path.join(venvBinDir, isWindows ? "python.exe" : "python3");
		const venvPip = path.join(venvBinDir, isWindows ? "pip.exe" : "pip");

		if (!fsSync.existsSync(venvPy)) {
			log("Setting up isolated Python virtual environment for Blutter...");
			await runCheckedSubprocess(["python3", "-m", "venv", venvDir], {
				onLog: log,
				signal: options.signal,
			});
		}

		log("Installing Python dependencies (pyelftools, requests)...");
		await runCheckedSubprocess([venvPip, "install", "--upgrade", "pyelftools", "requests"], {
			onLog: log,
			signal: options.signal,
		});

		// 3. 生成包装脚本
		await fs.mkdir(binDir, { recursive: true });
		const wrapperPath = path.join(binDir, isWindows ? "blutter.cmd" : "blutter");
		const scriptPath = path.join(installDir, "blutter.py");

		if (isWindows) {
			const batContent = `@echo off\r\n"${venvPy}" "${scriptPath}" %*\r\n`;
			await fs.writeFile(wrapperPath, batContent);
		} else {
			const shContent = `#!/usr/bin/env bash\nexec "${venvPy}" "${scriptPath}" "$@"\n`;
			await fs.writeFile(wrapperPath, shContent, { mode: 0o755 });
		}

		// 4. 实际校验执行 (Windows 下直接调用 python.exe，避免 child_process.spawn 不带 shell 无法执行 .cmd)
		log("Verifying Blutter executable wrapper...");
		if (isWindows) {
			await runCheckedSubprocess([venvPy, scriptPath, "--help"], {
				signal: options.signal,
			});
		} else {
			await runCheckedSubprocess([wrapperPath, "--help"], {
				signal: options.signal,
			});
		}

		return {
			success: true,
			id: "blutter",
			installDir,
			executablePath: wrapperPath,
		};
	} catch (err: unknown) {
		const message = err instanceof Error ? err.message : String(err);
		return {
			success: false,
			id: "blutter",
			installDir,
			executablePath: "",
			error: `Blutter installation failed: ${message}`,
		};
	}
}

/** 安装 hbctool 到 managed tools 独立虚拟环境 */
export async function installHbctool(options: RuntimeToolInstallOptions = {}): Promise<RuntimeToolInstallResult> {
	const agentDir = options.agentDir ?? getAgentDir();
	const installDir = path.join(agentDir, "tools", "hbctool");
	const isWindows = (options.platform ?? process.platform) === "win32";
	const log = options.onLog ?? (() => {});

	try {
		await fs.mkdir(installDir, { recursive: true });
		const venvDir = path.join(installDir, ".venv");
		const venvBinDir = path.join(venvDir, isWindows ? "Scripts" : "bin");
		const venvPy = path.join(venvBinDir, isWindows ? "python.exe" : "python3");
		const venvPip = path.join(venvBinDir, isWindows ? "pip.exe" : "pip");
		const venvHbctool = path.join(venvBinDir, isWindows ? "hbctool.exe" : "hbctool");

		if (!fsSync.existsSync(venvPy)) {
			log(`Creating isolated Python environment for hbctool (${HBCTOOL_PYPI_SPEC})...`);
			await runCheckedSubprocess(["python3", "-m", "venv", venvDir], {
				onLog: log,
				signal: options.signal,
			});
		}

		log(`Installing ${HBCTOOL_PYPI_SPEC}...`);
		await runCheckedSubprocess([venvPip, "install", HBCTOOL_PYPI_SPEC], {
			onLog: log,
			signal: options.signal,
		});

		// 实际校验执行
		log("Verifying hbctool installation...");
		await runCheckedSubprocess([venvHbctool, "--help"], {
			signal: options.signal,
		});

		return {
			success: true,
			id: "hbctool",
			installDir,
			executablePath: venvHbctool,
		};
	} catch (err: unknown) {
		const message = err instanceof Error ? err.message : String(err);
		return {
			success: false,
			id: "hbctool",
			installDir,
			executablePath: "",
			error: `hbctool installation failed: ${message}`,
		};
	}
}

/** 安装 hermes-dec 到 managed tools 独立虚拟环境 */
export async function installHermesDec(options: RuntimeToolInstallOptions = {}): Promise<RuntimeToolInstallResult> {
	const agentDir = options.agentDir ?? getAgentDir();
	const installDir = path.join(agentDir, "tools", "hermes-dec");
	const isWindows = (options.platform ?? process.platform) === "win32";
	const log = options.onLog ?? (() => {});

	try {
		await fs.mkdir(installDir, { recursive: true });
		const venvDir = path.join(installDir, ".venv");
		const venvBinDir = path.join(venvDir, isWindows ? "Scripts" : "bin");
		const venvPy = path.join(venvBinDir, isWindows ? "python.exe" : "python3");
		const venvPip = path.join(venvBinDir, isWindows ? "pip.exe" : "pip");
		const venvDisasm = path.join(venvBinDir, isWindows ? "hbc-disassembler.exe" : "hbc-disassembler");

		if (!fsSync.existsSync(venvPy)) {
			log(`Creating isolated Python environment for hermes-dec (${HERMES_DEC_PYPI_SPEC})...`);
			await runCheckedSubprocess(["python3", "-m", "venv", venvDir], {
				onLog: log,
				signal: options.signal,
			});
		}

		log(`Installing ${HERMES_DEC_PYPI_SPEC}...`);
		await runCheckedSubprocess([venvPip, "install", HERMES_DEC_PYPI_SPEC], {
			onLog: log,
			signal: options.signal,
		});

		// 实际校验执行
		log("Verifying hbc-disassembler installation...");
		await runCheckedSubprocess([venvDisasm, "--help"], {
			signal: options.signal,
		});

		return {
			success: true,
			id: "hermes-dec",
			installDir,
			executablePath: venvDisasm,
		};
	} catch (err: unknown) {
		const message = err instanceof Error ? err.message : String(err);
		return {
			success: false,
			id: "hermes-dec",
			installDir,
			executablePath: "",
			error: `hermes-dec installation failed: ${message}`,
		};
	}
}

/** 安装 Il2CppDumper 跨平台发布包并生成包装器与默认 config.json */
export async function installIl2CppDumper(options: RuntimeToolInstallOptions = {}): Promise<RuntimeToolInstallResult> {
	const agentDir = options.agentDir ?? getAgentDir();
	const installDir = path.join(agentDir, "tools", "Il2CppDumper");
	const binDir = path.join(installDir, "bin");
	const isWindows = (options.platform ?? process.platform) === "win32";
	const log = options.onLog ?? (() => {});

	try {
		await fs.mkdir(installDir, { recursive: true });
		await fs.mkdir(binDir, { recursive: true });

		// 选择平台专属发行包
		const downloadUrl = isWindows ? IL2CPP_DUMPER_WIN_ZIP_URL : IL2CPP_DUMPER_NET6_ZIP_URL;
		log(`Downloading Il2CppDumper (${IL2CPP_DUMPER_RELEASE_TAG}) from ${downloadUrl}...`);

		const resp = await fetch(downloadUrl, { signal: options.signal });
		if (!resp.ok) {
			throw new Error(`Failed to download Il2CppDumper: HTTP ${resp.status} ${resp.statusText}`);
		}
		const zipBuffer = Buffer.from(await resp.arrayBuffer());

		// 解压 ZIP 包
		const zip = new ZipParser(zipBuffer);
		for (const entry of zip.entries) {
			if (entry.name.endsWith("/")) continue;
			const dest = path.join(installDir, path.basename(entry.name));
			const data = zip.readFile(entry);
			if (data) {
				await fs.writeFile(dest, data);
			}
		}

		// 写入默认 config.json (配置 RequireAnyKey: false，杜绝非交互式运行等待按键)
		const configPath = path.join(installDir, "config.json");
		const defaultConfig = {
			DumpMethod: true,
			DumpField: true,
			DumpProperty: true,
			DumpAttribute: true,
			DumpFieldOffset: true,
			DumpMethodOffset: true,
			DumpTypeDefIndex: true,
			GenerateDummyDll: true,
			GenerateStruct: true,
			DummyDllAddToken: true,
			RequireAnyKey: false,
		};
		await fs.writeFile(configPath, JSON.stringify(defaultConfig, null, 2));

		let executablePath = "";
		if (isWindows) {
			executablePath = path.join(installDir, "Il2CppDumper.exe");
		} else {
			// 在非 Windows 平台生成基于 dotnet 运行时的可执行包装脚本
			const wrapperPath = path.join(binDir, "il2cppdumper");
			const dllPath = path.join(installDir, "Il2CppDumper.dll");
			const shContent = `#!/usr/bin/env bash\nexec dotnet "${dllPath}" "$@"\n`;
			await fs.writeFile(wrapperPath, shContent, { mode: 0o755 });
			executablePath = wrapperPath;
		}

		// 实际校验执行
		log("Verifying Il2CppDumper installation...");
		await runCheckedSubprocess([executablePath, "--help"], {
			signal: options.signal,
		});

		return {
			success: true,
			id: "il2cppdumper",
			installDir,
			executablePath,
		};
	} catch (err: unknown) {
		const message = err instanceof Error ? err.message : String(err);
		return {
			success: false,
			id: "il2cppdumper",
			installDir,
			executablePath: "",
			error: `Il2CppDumper installation failed: ${message}`,
		};
	}
}

/** 统一安装入口 */
export async function installRuntimeTool(
	id: RuntimeToolId,
	options: RuntimeToolInstallOptions = {},
): Promise<RuntimeToolInstallResult> {
	switch (id) {
		case "blutter":
			return installBlutter(options);
		case "hbctool":
			return installHbctool(options);
		case "hermes-dec":
			return installHermesDec(options);
		case "il2cppdumper":
			return installIl2CppDumper(options);
	}
}
