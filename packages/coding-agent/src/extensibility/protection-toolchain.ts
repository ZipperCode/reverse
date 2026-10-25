/**
 * Protection Toolchain Resolver and Managed Environment Installer.
 *
 * Provides authoritative resolution, pinned releases, verified recipes,
 * and executable/assets discovery for:
 * - frida-dexdump: Fast Dalvik/ART memory DEX dumper CLI via Frida (hluwa/frida-dexdump v2.0.1, GPL-3.0)
 * - qbdi: QuarkslaB Dynamic Binary Instrumentation native libraries and Frida bindings (QBDI/QBDI v0.12.1, Apache-2.0)
 * - jadx-string-decrypt: JADX string decryption and deobfuscation plugin JAR (Arsylk/jadx-string-decrypt v1.14.0, Apache-2.0)
 * - dexkit: High-performance DEX structural search engine (LuckyPray/DexKit v2.3.0, LGPL-3.0 Core, Apache-2.0 bridge)
 * - d810-ng: De-obfuscation framework for IDA Pro / microcode CFG normalization (w00tzenheimer/d810-ng v0.6.6, AGPL-3.0)
 * - blackdex: ART runtime dynamic unpacker APK for Android (CodingGay/BlackDex v3.2, Apache-2.0)
 * - simplify: Android Dalvik virtual machine de-obfuscator JAR (CalebFenton/simplify v1.3.0, GPL-3.0)
 * - msynth: Program synthesis for Mixed Boolean-Arithmetic (MBA) deobfuscation (mrphrazer/msynth v1.0.0, GPL-2.0)
 * - tritondse: Triton-based dynamic symbolic execution library (quarkslab/tritondse v0.1.14, Apache-2.0)
 * - fart: Optional offline codeitem repair reference assets (hanbinglengyue/FART, Apache-2.0)
 *
 * Platform guards:
 * - Host executable vs device APK distinguish installed/compatible/canStart,
 *   with no mandatory active adb/device connection required for host detection.
 * - canStart rigorously verifies ABI matching native libraries, valid JAR headers,
 *   and runtime prerequisites (such as JVM for Java tools and Python for venvs).
 * - Managed virtual environments in agent tools directory prevent global system mutation.
 */

import * as child_process from "node:child_process";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as fsPromises from "node:fs/promises";
import * as path from "node:path";
import { $which, getAgentDir, WhichCachePolicy } from "@reverse/utils";
import { extractArchive } from "@reverse/utils/ar";
import type { SkillRequirementWhich } from "./skill-requirements";
import type { SkillToolPlatform } from "./skill-tool-catalog";
import { runSubprocess } from "./triton-source-install";

import {
	installProtectionPythonTool,
	FRIDA_DEXDUMP_VERSION,
	FRIDA_DEXDUMP_PYPI_SPEC,
	FRIDA_DEXDUMP_LICENSE,
	FRIDA_DEXDUMP_UPSTREAM_URL,
	MSYNTH_VERSION,
	MSYNTH_COMMIT,
	MSYNTH_LICENSE,
	MSYNTH_UPSTREAM_URL,
	D810_NG_VERSION,
	D810_NG_COMMIT,
	D810_NG_PYPI_SPEC,
	D810_NG_LICENSE,
	D810_NG_UPSTREAM_URL,
	TRITONDSE_VERSION,
	TRITONDSE_COMMIT,
	TRITONDSE_PYPI_SPEC,
	TRITONDSE_LICENSE,
	TRITONDSE_UPSTREAM_URL,
} from "./protection-python-install";

import {
	installDexKit,
	resolveDexKitInstallation,
	isSupportedHostPlatform,
	DEXKIT_VERSION,
	DEXKIT_TAG,
	DEXKIT_COMMIT,
	DEXKIT_REPO_URL,
	DEXKIT_LICENSE_CORE,
	DEXKIT_LICENSE_WRAPPER,
} from "./dexkit-install";

export {
	FRIDA_DEXDUMP_VERSION,
	FRIDA_DEXDUMP_PYPI_SPEC,
	FRIDA_DEXDUMP_LICENSE,
	FRIDA_DEXDUMP_UPSTREAM_URL,
	MSYNTH_VERSION,
	MSYNTH_COMMIT,
	MSYNTH_LICENSE,
	MSYNTH_UPSTREAM_URL,
	D810_NG_VERSION,
	D810_NG_COMMIT,
	D810_NG_PYPI_SPEC,
	D810_NG_LICENSE,
	D810_NG_UPSTREAM_URL,
	TRITONDSE_VERSION,
	TRITONDSE_COMMIT,
	TRITONDSE_PYPI_SPEC,
	TRITONDSE_LICENSE,
	TRITONDSE_UPSTREAM_URL,
	DEXKIT_VERSION,
	DEXKIT_TAG,
	DEXKIT_COMMIT,
	DEXKIT_REPO_URL,
	DEXKIT_LICENSE_CORE,
	DEXKIT_LICENSE_WRAPPER,
};

// ============================================================================
// Authoritative Release & Version Pins (Fact-Checked Primary Sources)
// ============================================================================

export const FART_VERSION = "1.0.0";
export const FART_COMMIT = "50d49f97850e2ff95e9715c6c63699c9566cd6e6";
export const FART_LICENSE = "Apache-2.0";
export const FART_UPSTREAM_URL = "https://github.com/hanbinglengyue/FART.git";
export const FART_ARCHIVE_URL = `https://github.com/hanbinglengyue/FART/archive/${FART_COMMIT}.tar.gz`;

export const QBDI_VERSION = "0.12.1";
export const QBDI_TAG = "v0.12.1";
export const QBDI_COMMIT = "09b2efb66d242b3616a4723e4b487f623b0e93d7";
export const QBDI_LICENSE = "Apache-2.0";
export const QBDI_UPSTREAM_URL = "https://github.com/QBDI/QBDI.git";
export const QBDI_FRIDA_BINDING_URL = `https://raw.githubusercontent.com/QBDI/QBDI/${QBDI_TAG}/tools/frida-qbdi.js`;

export const QBDI_RELEASE_ASSETS = {
	darwin_arm64: {
		url: `https://github.com/QBDI/QBDI/releases/download/${QBDI_TAG}/QBDI-${QBDI_VERSION}-osx-AARCH64.pkg`,
		sha256: "6555cf8a72af41f069ca2d2617469adc02a1ae502246150c7529d8963f789b34",
	},
	darwin_x64: {
		url: `https://github.com/QBDI/QBDI/releases/download/${QBDI_TAG}/QBDI-${QBDI_VERSION}-osx-X86_64.pkg`,
		sha256: "5fc095acd69f0417db9fad58e75061d391413301d6a19d6d39636d1199d9c7d3",
	},
	android_arm64: {
		url: `https://github.com/QBDI/QBDI/releases/download/${QBDI_TAG}/QBDI-${QBDI_VERSION}-android-AARCH64.tar.gz`,
		sha256: "c72ee67c5939cff32f047b32012b6cbd879324c3272fa788a1b1d686b10a8e8d",
	},
	android_arm32: {
		url: `https://github.com/QBDI/QBDI/releases/download/${QBDI_TAG}/QBDI-${QBDI_VERSION}-android-ARM.tar.gz`,
		sha256: "585966825a336eb4155d38426573c42a80b60ba2f440e6a2d05468b5b73beb68",
	},
} as const;

export const JADX_STRING_DECRYPT_VERSION = "1.14.0";
export const JADX_STRING_DECRYPT_TAG = "v1.14.0";
export const JADX_STRING_DECRYPT_COMMIT = "22a03bb268e925debf27ecb8aff89a22b050944c";
export const JADX_STRING_DECRYPT_LICENSE = "Apache-2.0";
export const JADX_STRING_DECRYPT_UPSTREAM_URL = "https://github.com/Arsylk/jadx-string-decrypt.git";
export const JADX_STRING_DECRYPT_JAR_URL = `https://github.com/Arsylk/jadx-string-decrypt/releases/download/${JADX_STRING_DECRYPT_TAG}/jadx-string-decrypt-${JADX_STRING_DECRYPT_VERSION}.jar`;
export const JADX_STRING_DECRYPT_SHA256 = "23ac54326a4ceabb4fae4c7591e0f480bf4e3c5260e6cff8204da402dd19772a";

export const BLACKDEX_VERSION = "3.2";
export const BLACKDEX_TAG = "v3.2";
export const BLACKDEX_COMMIT = "5580fa8f5d658afae4eb667f8c8d6632be5b9aaf";
export const BLACKDEX_LICENSE = "Apache-2.0";
export const BLACKDEX_UPSTREAM_URL = "https://github.com/CodingGay/BlackDex.git";
export const BLACKDEX_URL_32 = `https://github.com/CodingGay/BlackDex/releases/download/${BLACKDEX_TAG}/app-BlackDex32.apk`;
export const BLACKDEX_URL_64 = `https://github.com/CodingGay/BlackDex/releases/download/${BLACKDEX_TAG}/app-BlackDex64.apk`;

export const SIMPLIFY_VERSION = "1.3.0";
export const SIMPLIFY_TAG = "v1.3.0";
export const SIMPLIFY_COMMIT = "29fb25d624aecf0b075dea5c6029b2541474ddfe";
export const SIMPLIFY_LICENSE = "GPL-3.0";
export const SIMPLIFY_UPSTREAM_URL = "https://github.com/CalebFenton/simplify.git";
export const SIMPLIFY_JAR_URL = `https://github.com/CalebFenton/simplify/releases/download/${SIMPLIFY_TAG}/simplify-${SIMPLIFY_VERSION}.jar`;

// ============================================================================
// Types & Interfaces
// ============================================================================

export type ProtectionToolId =
	| "frida-dexdump"
	| "fart"
	| "qbdi"
	| "jadx-string-decrypt"
	| "dexkit"
	| "d810-ng"
	| "blackdex"
	| "simplify"
	| "msynth"
	| "tritondse";

export type ProtectionToolKind = "cli" | "python-package" | "java-jar" | "native-lib" | "device-apk";

export const ALL_PROTECTION_TOOL_IDS: readonly ProtectionToolId[] = [
	"frida-dexdump",
	"fart",
	"qbdi",
	"jadx-string-decrypt",
	"dexkit",
	"d810-ng",
	"blackdex",
	"simplify",
	"msynth",
	"tritondse",
] as const;

export function isProtectionToolId(id: string): id is ProtectionToolId {
	return (ALL_PROTECTION_TOOL_IDS as readonly string[]).includes(id);
}

export interface ProtectionToolMetadata {
	executablePath?: string;
	interpreter?: string;
	pythonPath?: string;
	jarPath?: string;
	pluginPath?: string;
	dropinDir?: string;
	configDir?: string;
	assetsDir?: string;
	libPath?: string;
	nativeLibPath?: string;
	androidArm64Lib?: string;
	androidArmLib?: string;
	fridaBinding?: string;
	apkPath?: string;
	apk32?: string;
	apk64?: string;
	packageDir?: string;
	sitePackages?: string;
	bridgeScript?: string;
	version?: string;
	license?: string;
	[key: string]: unknown;
}

export interface ProtectionToolResolved {
	id: ProtectionToolId;
	kind: ProtectionToolKind;
	path: string;
	binDir: string;
	version?: string;
	managed: boolean;
	installed: boolean;
	compatible: boolean;
	canStart: boolean;
	metadata: ProtectionToolMetadata;
}

export interface ProtectionToolResolveOptions {
	agentDir?: string;
	which?: SkillRequirementWhich;
	platform?: SkillToolPlatform;
	env?: Record<string, string | undefined>;
	allowMissing?: boolean;
}

export interface ProtectionToolInstallOptions {
	agentDir?: string;
	onChunk?: (chunk: string) => void;
	onLog?: (chunk: string) => void;
	signal?: AbortSignal;
	timeoutMs?: number;
	which?: SkillRequirementWhich;
	platform?: SkillToolPlatform;
	env?: Record<string, string | undefined>;
	fetch?: typeof globalThis.fetch;
}

export interface ProtectionToolInstallResult {
	success: boolean;
	id: ProtectionToolId;
	installDir: string;
	executablePath: string;
	error?: string;
	message?: string;
}

// ============================================================================
// File & Validation Helpers
// ============================================================================

export function isValidZipHeader(filePath: string): boolean {
	try {
		if (!fs.existsSync(filePath)) return false;
		const stat = fs.statSync(filePath);
		if (!stat.isFile() || stat.size < 22) return false;
		const fd = fs.openSync(filePath, "r");
		const buf = Buffer.alloc(4);
		const read = fs.readSync(fd, buf, 0, 4, 0);
		fs.closeSync(fd);
		if (read < 4) return false;
		return (
			buf[0] === 0x50 &&
			buf[1] === 0x4b &&
			((buf[2] === 0x03 && buf[3] === 0x04) ||
				(buf[2] === 0x05 && buf[3] === 0x06) ||
				(buf[2] === 0x07 && buf[3] === 0x08))
		);
	} catch {
		return false;
	}
}

export function isExecutableRegularFile(filePath: string): boolean {
	try {
		const st = fs.statSync(filePath);
		if (!st.isFile()) return false;
		if (process.platform === "win32") return true;
		return (st.mode & 0o111) !== 0;
	} catch {
		return false;
	}
}

export function validateNativeLibraryArchitecture(
	filePath: string,
	platform: NodeJS.Platform = process.platform,
	arch: string = process.arch,
): boolean {
	try {
		if (!fs.existsSync(filePath)) return false;
		const stat = fs.statSync(filePath);
		if (!stat.isFile() || stat.size < 1000) return false;

		const fd = fs.openSync(filePath, "r");
		const buf = Buffer.alloc(24);
		const bytesRead = fs.readSync(fd, buf, 0, 24, 0);
		fs.closeSync(fd);
		if (bytesRead < 20) return false;

		if (platform === "darwin") {
			const magicLE = buf.readUInt32LE(0);
			const magicBE = buf.readUInt32BE(0);
			const isMachO64LE = magicLE === 0xfeedfacf;
			const isMachO32LE = magicLE === 0xfeedface;
			const isMachOFat = magicBE === 0xcafebabe || magicLE === 0xbebafeca;
			if (isMachOFat) return true;
			if (isMachO64LE) {
				const cputype = buf.readInt32LE(4);
				if (arch === "arm64") return cputype === 0x0100000c;
				if (arch === "x64") return cputype === 0x01000007;
				return true;
			}
			return isMachO64LE || isMachO32LE;
		}

		if (platform === "linux" || platform === "android") {
			if (buf[0] !== 0x7f || buf[1] !== 0x45 || buf[2] !== 0x4c || buf[3] !== 0x46) {
				return false;
			}
			const machine = buf.readUInt16LE(18);
			if (arch === "arm64" || arch === "aarch64") return machine === 0xb7 || machine === 0x28;
			if (arch === "x64") return machine === 0x3e;
			return true;
		}

		if (platform === "win32") {
			return buf[0] === 0x4d && buf[1] === 0x5a;
		}

		return true;
	} catch {
		return false;
	}
}

function isJavaAvailable(options: ProtectionToolResolveOptions = {}): boolean {
	const whichFn = options.which ?? ((bin, opts) => $which(bin, opts));
	const env = options.env ?? process.env;
	if (env.JAVA_HOME && fs.existsSync(env.JAVA_HOME)) {
		const javaBin = path.join(env.JAVA_HOME, "bin", process.platform === "win32" ? "java.exe" : "java");
		if (fs.existsSync(javaBin)) return true;
	}
	const found = whichFn("java", { cache: WhichCachePolicy.Bypass });
	return found !== null && isExecutableRegularFile(found);
}
function isJava11OrHigherAvailable(options: ProtectionToolResolveOptions = {}): boolean {
	const whichFn = options.which ?? ((bin, opts) => $which(bin, opts));
	const env = options.env ?? process.env;
	let javaBin = whichFn("java", { cache: WhichCachePolicy.Bypass });
	if (env.JAVA_HOME && fs.existsSync(env.JAVA_HOME)) {
		const cand = path.join(env.JAVA_HOME, "bin", process.platform === "win32" ? "java.exe" : "java");
		if (fs.existsSync(cand)) javaBin = cand;
	}
	if (!javaBin || !isExecutableRegularFile(javaBin)) return false;
	try {
		const res = child_process.spawnSync(javaBin, ["-version"], {
			timeout: 2000,
			windowsHide: true,
			encoding: "utf8",
		});
		if (res.status !== 0 || res.error) return false;
		const out = res.stderr || res.stdout;
		const match = out.match(/version\s*"?(\d+)(?:\.(\d+))?/i);
		if (match) {
			const major = parseInt(match[1] === "1" ? match[2] : match[1], 10);
			return !Number.isNaN(major) && major >= 11;
		}
		return false;
	} catch {
		return false;
	}
}
function isCompatibleJadxAvailable(options: ProtectionToolResolveOptions = {}): {
	compatible: boolean;
	jadxBin: string | null;
	version?: string;
} {
	const whichFn = options.which ?? ((bin, opts) => $which(bin, opts));
	const jadxBin = whichFn("jadx", { cache: WhichCachePolicy.Bypass });
	if (!jadxBin || !isExecutableRegularFile(jadxBin)) {
		return { compatible: false, jadxBin: null };
	}
	try {
		const res = child_process.spawnSync(jadxBin, ["--version"], {
			timeout: 2500,
			windowsHide: true,
			encoding: "utf8",
		});
		if (res.status !== 0 || res.error) {
			return { compatible: false, jadxBin: null };
		}
		const out = (res.stdout || res.stderr).trim();
		const match = out.match(/(\d+)\.(\d+)(?:\.(\d+))?/);
		if (match) {
			const major = parseInt(match[1], 10);
			const minor = parseInt(match[2], 10);
			const patch = parseInt(match[3] ?? "0", 10);
			const isGe152 = major > 1 || (major === 1 && (minor > 5 || (minor === 5 && patch >= 2)));
			return { compatible: isGe152, jadxBin, version: out };
		}
		return { compatible: false, jadxBin };
	} catch {
		return { compatible: false, jadxBin };
	}
}

async function extractTarMemberByPattern(
	tarPath: string,
	stagingDir: string,
	targetFileName: string,
	outputFilePath: string,
	options?: { signal?: AbortSignal; onLog?: (chunk: string) => void },
): Promise<string> {
	const listRes = await runCheckedSubprocess(["tar", "-tzf", tarPath], {
		signal: options?.signal,
	});
	const lines = listRes
		.split("\n")
		.map(l => l.trim())
		.filter(Boolean);
	const member = lines.find(
		l =>
			l.endsWith(`/${targetFileName}`) || l === targetFileName || (l.includes(targetFileName) && !l.endsWith(".a")),
	);
	if (!member) {
		throw new Error(`Target member ${targetFileName} was not found in archive ${tarPath}`);
	}
	await fsPromises.mkdir(stagingDir, { recursive: true });
	await runCheckedSubprocess(["tar", "-xzf", tarPath, "-C", stagingDir, member], {
		signal: options?.signal,
		onLog: options?.onLog,
	});
	const extractedPath = path.join(stagingDir, member);
	if (!fs.existsSync(extractedPath)) {
		throw new Error(`Extraction succeeded but file missing at ${extractedPath}`);
	}
	await fsPromises.mkdir(path.dirname(outputFilePath), { recursive: true });
	await fsPromises.copyFile(extractedPath, outputFilePath);
	return outputFilePath;
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

async function stageBufferToFile(targetPath: string, buffer: Buffer): Promise<void> {
	await fsPromises.mkdir(path.dirname(targetPath), { recursive: true });
	const tempPath = `${targetPath}.tmp.${Date.now()}`;
	await fsPromises.writeFile(tempPath, buffer);
	await fsPromises.rename(tempPath, targetPath);
}

async function downloadFileWithSha256(
	url: string,
	targetPath: string,
	expectedSha256?: string,
	options?: {
		signal?: AbortSignal;
		fetch?: typeof globalThis.fetch;
		onLog?: (chunk: string) => void;
		timeoutMs?: number;
		maxBytes?: number;
	},
): Promise<void> {
	options?.onLog?.(`Downloading ${url}...\n`);
	const fetchFn = options?.fetch ?? globalThis.fetch;
	const timeoutSignal = AbortSignal.timeout(options?.timeoutMs ?? 60_000);
	const signal = options?.signal ? AbortSignal.any([options.signal, timeoutSignal]) : timeoutSignal;

	const resp = await fetchFn(url, { signal });
	if (!resp.ok) {
		throw new Error(`Failed to download ${url}: HTTP ${resp.status} ${resp.statusText}`);
	}
	const maxBytes = options?.maxBytes ?? 150 * 1024 * 1024; // 150 MiB safety cap
	const chunks: Uint8Array[] = [];
	let totalBytes = 0;

	if (resp.body) {
		const reader = resp.body.getReader();
		try {
			while (true) {
				const { done, value } = await reader.read();
				if (done) break;
				if (value) {
					totalBytes += value.byteLength;
					if (totalBytes > maxBytes) {
						await reader.cancel();
						throw new Error(`Download of ${url} exceeded safety cap of ${maxBytes} bytes`);
					}
					chunks.push(value);
				}
			}
		} finally {
			reader.releaseLock();
		}
	} else {
		const arrayBuf = await resp.arrayBuffer();
		if (arrayBuf.byteLength > maxBytes) {
			throw new Error(`Download of ${url} exceeded safety cap of ${maxBytes} bytes`);
		}
		chunks.push(new Uint8Array(arrayBuf));
		totalBytes = arrayBuf.byteLength;
	}

	const combined = Buffer.concat(chunks, totalBytes);
	if (expectedSha256) {
		const hash = crypto.createHash("sha256").update(combined).digest("hex");
		if (hash.toLowerCase() !== expectedSha256.toLowerCase()) {
			throw new Error(`SHA256 mismatch for ${url}: expected ${expectedSha256}, got ${hash}`);
		}
	}
	await stageBufferToFile(targetPath, combined);
}

// ============================================================================
// Tool-Specific Resolvers
// ============================================================================

export function resolveFridaDexdump(options: ProtectionToolResolveOptions = {}): ProtectionToolResolved | null {
	const agentDir = options.agentDir ?? getAgentDir();
	const isWindows = (options.platform ?? process.platform) === "win32";
	const whichFn = options.which ?? ((bin, opts) => $which(bin, opts));

	const managedBin = path.join(
		agentDir,
		"tools",
		"frida-dexdump",
		"bin",
		isWindows ? "frida-dexdump.cmd" : "frida-dexdump",
	);
	const venvBin = path.join(
		agentDir,
		"tools",
		"frida-dexdump",
		".venv",
		isWindows ? "Scripts" : "bin",
		isWindows ? "frida-dexdump.exe" : "frida-dexdump",
	);

	if (isExecutableRegularFile(managedBin)) {
		return {
			id: "frida-dexdump",
			kind: "cli",
			path: managedBin,
			binDir: path.dirname(managedBin),
			version: FRIDA_DEXDUMP_VERSION,
			managed: true,
			installed: true,
			compatible: true,
			canStart: true,
			metadata: {
				executablePath: managedBin,
				version: FRIDA_DEXDUMP_VERSION,
				license: FRIDA_DEXDUMP_LICENSE,
			},
		};
	}

	if (isExecutableRegularFile(venvBin)) {
		return {
			id: "frida-dexdump",
			kind: "cli",
			path: venvBin,
			binDir: path.dirname(venvBin),
			version: FRIDA_DEXDUMP_VERSION,
			managed: true,
			installed: true,
			compatible: true,
			canStart: true,
			metadata: {
				executablePath: venvBin,
				version: FRIDA_DEXDUMP_VERSION,
				license: FRIDA_DEXDUMP_LICENSE,
			},
		};
	}

	const pathBin = whichFn("frida-dexdump", { cache: WhichCachePolicy.Bypass });
	if (pathBin && isExecutableRegularFile(pathBin)) {
		return {
			id: "frida-dexdump",
			kind: "cli",
			path: pathBin,
			binDir: path.dirname(pathBin),
			managed: false,
			installed: true,
			compatible: true,
			canStart: true,
			metadata: {
				executablePath: pathBin,
				license: FRIDA_DEXDUMP_LICENSE,
			},
		};
	}

	if (options.allowMissing) {
		return {
			id: "frida-dexdump",
			kind: "cli",
			path: "",
			binDir: path.join(agentDir, "tools", "frida-dexdump", "bin"),
			managed: false,
			installed: false,
			compatible: true,
			canStart: false,
			metadata: { license: FRIDA_DEXDUMP_LICENSE },
		};
	}

	return null;
}

export function resolveFart(options: ProtectionToolResolveOptions = {}): ProtectionToolResolved | null {
	const agentDir = options.agentDir ?? getAgentDir();
	const env = options.env ?? process.env;

	const managedDir = path.join(agentDir, "tools", "fart");
	const envDir = env.FART_DIR ?? (env.FART_HOME ? env.FART_HOME : undefined);
	const targetDir = envDir && fs.existsSync(envDir) ? envDir : managedDir;

	const hasSource =
		fs.existsSync(path.join(targetDir, "fart.cpp")) || fs.existsSync(path.join(targetDir, "README.md"));
	const isInstalled = hasSource;

	if (isInstalled) {
		return {
			id: "fart",
			kind: "device-apk",
			path: targetDir,
			binDir: targetDir,
			version: FART_VERSION,
			managed: targetDir === managedDir,
			installed: true,
			compatible: true,
			canStart: true,
			metadata: {
				assetsDir: targetDir,
				version: FART_VERSION,
				license: FART_LICENSE,
			},
		};
	}

	if (options.allowMissing) {
		return {
			id: "fart",
			kind: "device-apk",
			path: managedDir,
			binDir: managedDir,
			managed: false,
			installed: false,
			compatible: true,
			canStart: false,
			metadata: { license: FART_LICENSE },
		};
	}

	return null;
}

export function resolveQbdi(options: ProtectionToolResolveOptions = {}): ProtectionToolResolved | null {
	const agentDir = options.agentDir ?? getAgentDir();
	const platform = options.platform ?? process.platform;
	const arch = process.arch;
	const qbdiDir = path.join(agentDir, "tools", "qbdi");

	const libName = platform === "darwin" ? "libQBDI.dylib" : platform === "win32" ? "QBDI.dll" : "libQBDI.so";
	const hostLibCandidates = [path.join(qbdiDir, libName), path.join(qbdiDir, "lib", libName)];
	const libPath = hostLibCandidates.find(p => fs.existsSync(p)) ?? path.join(qbdiDir, libName);
	const fridaBinding = path.join(qbdiDir, "frida-qbdi.js");
	const androidArm64Lib = [
		path.join(qbdiDir, "android-arm64", "libQBDI.so"),
		path.join(qbdiDir, "android-arm64", "lib", "libQBDI.so"),
	].find(p => fs.existsSync(p));
	const androidArmLib = [
		path.join(qbdiDir, "android-arm", "libQBDI.so"),
		path.join(qbdiDir, "android-arm", "lib", "libQBDI.so"),
	].find(p => fs.existsSync(p));

	const hasLib = fs.existsSync(libPath);
	const hasBinding = fs.existsSync(fridaBinding);
	const hasAndroidArm64 = androidArm64Lib !== undefined && fs.existsSync(androidArm64Lib);
	const hasAndroidArm = androidArmLib !== undefined && fs.existsSync(androidArmLib);
	const isInstalled = hasLib || hasBinding || hasAndroidArm64 || hasAndroidArm;

	// canStart strictly requires a genuine native library matching host ABI AND the Frida binding
	const isLibValid =
		hasLib && isExecutableRegularFile(libPath) && validateNativeLibraryArchitecture(libPath, platform, arch);
	const canStart = isLibValid && hasBinding;

	if (isInstalled) {
		return {
			id: "qbdi",
			kind: "native-lib",
			path: hasLib ? libPath : fridaBinding,
			binDir: qbdiDir,
			version: QBDI_VERSION,
			managed: true,
			installed: true,
			compatible: isLibValid || hasAndroidArm64,
			canStart,
			metadata: {
				assetsDir: qbdiDir,
				libPath: hasLib ? libPath : undefined,
				nativeLibPath: hasLib ? libPath : undefined,
				androidArm64Lib: hasAndroidArm64 ? androidArm64Lib : undefined,
				androidArmLib: hasAndroidArm ? androidArmLib : undefined,
				fridaBinding: hasBinding ? fridaBinding : undefined,
				version: QBDI_VERSION,
				license: QBDI_LICENSE,
			},
		};
	}

	if (options.allowMissing) {
		return {
			id: "qbdi",
			kind: "native-lib",
			path: libPath,
			binDir: qbdiDir,
			managed: false,
			installed: false,
			compatible: true,
			canStart: false,
			metadata: {
				assetsDir: qbdiDir,
				license: QBDI_LICENSE,
			},
		};
	}

	return null;
}

export function resolveJadxStringDecrypt(options: ProtectionToolResolveOptions = {}): ProtectionToolResolved | null {
	const agentDir = options.agentDir ?? getAgentDir();
	const pluginsDir = path.join(agentDir, "tools", "jadx-plugins");
	const dropinsDir = path.join(agentDir, "tools", "jadx-config", "plugins", "dropins");
	const jarVersioned = path.join(pluginsDir, `jadx-string-decrypt-${JADX_STRING_DECRYPT_VERSION}.jar`);
	const jarStandard = path.join(pluginsDir, "jadx-string-decrypt.jar");
	const jarDropin = path.join(dropinsDir, "jadx-string-decrypt.jar");

	const candidateJar = isValidZipHeader(jarVersioned)
		? jarVersioned
		: isValidZipHeader(jarStandard)
			? jarStandard
			: isValidZipHeader(jarDropin)
				? jarDropin
				: null;

	let isInstalled = false;
	if (candidateJar) {
		try {
			const stat = fs.statSync(candidateJar);
			if (stat.size >= 50_000) {
				isInstalled = true;
			}
		} catch {}
	}
	const java11Ok = isJava11OrHigherAvailable(options);
	const jadxInfo = isCompatibleJadxAvailable(options);
	let pluginActive = false;

	if (jadxInfo.compatible && jadxInfo.jadxBin) {
		try {
			const listRes = child_process.spawnSync(jadxInfo.jadxBin, ["plugins", "--list-all"], {
				timeout: 3000,
				windowsHide: true,
				encoding: "utf8",
				env: {
					...(options.env ?? process.env),
					JADX_CONFIG_DIR: path.join(agentDir, "tools", "jadx-config"),
				},
			});
			if (listRes.status === 0 && !listRes.error) {
				const stdout = listRes.stdout || "";
				const lines = stdout.split("\n");
				for (const line of lines) {
					if (line.includes("string-decrypt") && !line.includes("(disabled)") && !line.includes("[disabled]")) {
						pluginActive = true;
						break;
					}
				}
			}
		} catch {}
	}

	const canStart = isInstalled && java11Ok && Boolean(jadxInfo.jadxBin) && jadxInfo.compatible && pluginActive;
	if (isInstalled && candidateJar) {
		return {
			id: "jadx-string-decrypt",
			kind: "java-jar",
			path: candidateJar,
			binDir: pluginsDir,
			version: JADX_STRING_DECRYPT_VERSION,
			managed: true,
			installed: true,
			compatible: true,
			canStart,
			metadata: {
				jarPath: candidateJar,
				pluginPath: candidateJar,
				dropinDir: dropinsDir,
				configDir: path.join(agentDir, "tools", "jadx-config"),
				version: JADX_STRING_DECRYPT_VERSION,
				license: JADX_STRING_DECRYPT_LICENSE,
			},
		};
	}

	if (options.allowMissing) {
		return {
			id: "jadx-string-decrypt",
			kind: "java-jar",
			path: jarStandard,
			binDir: pluginsDir,
			managed: false,
			installed: false,
			compatible: true,
			canStart: false,
			metadata: {
				dropinDir: dropinsDir,
				configDir: path.join(agentDir, "tools", "jadx-config"),
				license: JADX_STRING_DECRYPT_LICENSE,
			},
		};
	}

	return null;
}

export function resolveDexKit(options: ProtectionToolResolveOptions = {}): ProtectionToolResolved | null {
	// Delegate to authoritative resolveDexKitInstallation in dexkit-install.ts
	const platform = options.platform ?? process.platform;
	const resolved = resolveDexKitInstallation(options);
	const compatible = isSupportedHostPlatform(platform, process.arch);
	const execPath = resolved.wrapperBin || resolved.bridgeJar || "";

	if (resolved.installed || options.allowMissing) {
		return {
			id: "dexkit",
			kind: "native-lib",
			path: execPath,
			binDir: resolved.installDir,
			version: DEXKIT_VERSION,
			managed: true,
			installed: resolved.installed,
			compatible,
			canStart: resolved.canStart && compatible && isJavaAvailable(options),
			metadata: {
				jarPath: resolved.bridgeJar,
				nativeLibPath: resolved.libPath,
				libPath: resolved.libPath,
				libDir: resolved.installDir,
				bridgeScript: resolved.wrapperBin,
				executablePath: resolved.wrapperBin,
				dexkitJar: resolved.dexkitJar,
				flatbuffersJar: resolved.flatbuffersJar,
				kotlinStdlibJar: resolved.kotlinStdlibJar,
				version: DEXKIT_VERSION,
				license: DEXKIT_LICENSE_CORE,
			},
		};
	}
	return null;
}

export function resolveD810Ng(options: ProtectionToolResolveOptions = {}): ProtectionToolResolved | null {
	const agentDir = options.agentDir ?? getAgentDir();
	const isWindows = (options.platform ?? process.platform) === "win32";
	const installDir = path.join(agentDir, "tools", "d810-ng");
	const venvDir = path.join(installDir, ".venv");
	const venvPy = path.join(venvDir, isWindows ? "Scripts/python.exe" : "bin/python");

	const hasVenv = isExecutableRegularFile(venvPy);
	const hasRepo = fs.existsSync(path.join(installDir, "d810"));
	const isInstalled = hasVenv || hasRepo;

	let sitePackages: string | undefined;
	if (hasVenv) {
		const libDir = path.join(venvDir, isWindows ? "Lib" : "lib");
		if (fs.existsSync(libDir)) {
			if (isWindows) {
				const sp = path.join(libDir, "site-packages");
				if (fs.existsSync(sp)) sitePackages = sp;
			} else {
				try {
					const entries = fs.readdirSync(libDir);
					for (const e of entries) {
						if (e.startsWith("python")) {
							const sp = path.join(libDir, e, "site-packages");
							if (fs.existsSync(sp)) {
								sitePackages = sp;
								break;
							}
						}
					}
				} catch {}
			}
		}
	}

	const canStart = hasVenv;

	if (isInstalled) {
		return {
			id: "d810-ng",
			kind: "python-package",
			path: hasVenv ? venvPy : installDir,
			binDir: hasVenv ? path.dirname(venvPy) : installDir,
			version: D810_NG_VERSION,
			managed: true,
			installed: true,
			compatible: true,
			canStart,
			metadata: {
				pythonPath: hasVenv ? venvPy : undefined,
				packageDir: installDir,
				sitePackages,
				version: D810_NG_VERSION,
				license: D810_NG_LICENSE,
			},
		};
	}

	if (options.allowMissing) {
		return {
			id: "d810-ng",
			kind: "python-package",
			path: installDir,
			binDir: installDir,
			managed: false,
			installed: false,
			compatible: true,
			canStart: false,
			metadata: { license: D810_NG_LICENSE },
		};
	}

	return null;
}

export function resolveBlackDex(options: ProtectionToolResolveOptions = {}): ProtectionToolResolved | null {
	const agentDir = options.agentDir ?? getAgentDir();
	const blackdexDir = path.join(agentDir, "tools", "blackdex");

	const apk32 = path.join(blackdexDir, "app-BlackDex32.apk");
	const apk64 = path.join(blackdexDir, "app-BlackDex64.apk");
	const fallback32 = path.join(blackdexDir, "BlackDex32.apk");
	const fallback64 = path.join(blackdexDir, "BlackDex64.apk");
	const apkUniv = path.join(blackdexDir, "BlackDex.apk");

	const checkApk = (p: string): string | null => {
		if (!isValidZipHeader(p)) return null;
		try {
			if (fs.statSync(p).size >= 1_000_000) return p;
		} catch {}
		return null;
	};

	const has32 = checkApk(apk32) ?? checkApk(fallback32);
	const has64 = checkApk(apk64) ?? checkApk(fallback64);
	const hasUniv = checkApk(apkUniv);
	const isInstalled = has32 !== null || has64 !== null || hasUniv !== null;

	const primaryPath = hasUniv ?? has64 ?? has32 ?? apkUniv;

	if (isInstalled) {
		return {
			id: "blackdex",
			kind: "device-apk",
			path: primaryPath,
			binDir: blackdexDir,
			version: BLACKDEX_VERSION,
			managed: true,
			installed: true,
			compatible: true,
			canStart: true,
			metadata: {
				apkPath: primaryPath,
				apk32: has32 ?? undefined,
				apk64: has64 ?? undefined,
				version: BLACKDEX_VERSION,
				license: BLACKDEX_LICENSE,
			},
		};
	}

	if (options.allowMissing) {
		return {
			id: "blackdex",
			kind: "device-apk",
			path: apkUniv,
			binDir: blackdexDir,
			managed: false,
			installed: false,
			compatible: true,
			canStart: false,
			metadata: { license: BLACKDEX_LICENSE },
		};
	}

	return null;
}

export function resolveSimplify(options: ProtectionToolResolveOptions = {}): ProtectionToolResolved | null {
	const agentDir = options.agentDir ?? getAgentDir();
	const isWindows = (options.platform ?? process.platform) === "win32";
	const simplifyDir = path.join(agentDir, "tools", "simplify");
	const jarVersioned = path.join(simplifyDir, `simplify-${SIMPLIFY_VERSION}.jar`);
	const jarStandard = path.join(simplifyDir, "simplify.jar");
	const binWrapper = path.join(simplifyDir, "bin", isWindows ? "simplify.cmd" : "simplify");

	const checkJar = (p: string): string | null => {
		if (!isValidZipHeader(p)) return null;
		try {
			if (fs.statSync(p).size >= 10_000_000) return p;
		} catch {}
		return null;
	};

	const effectiveJar = checkJar(jarVersioned) ?? checkJar(jarStandard);
	const hasWrapper = isExecutableRegularFile(binWrapper);
	const isInstalled = effectiveJar !== null || hasWrapper;
	const canStart = isInstalled && isJavaAvailable(options);

	if (isInstalled) {
		return {
			id: "simplify",
			kind: "java-jar",
			path: hasWrapper ? binWrapper : (effectiveJar ?? jarStandard),
			binDir: hasWrapper ? path.dirname(binWrapper) : simplifyDir,
			version: SIMPLIFY_VERSION,
			managed: true,
			installed: true,
			compatible: true,
			canStart,
			metadata: {
				jarPath: effectiveJar ?? undefined,
				executablePath: hasWrapper ? binWrapper : undefined,
				version: SIMPLIFY_VERSION,
				license: SIMPLIFY_LICENSE,
			},
		};
	}

	if (options.allowMissing) {
		return {
			id: "simplify",
			kind: "java-jar",
			path: jarStandard,
			binDir: simplifyDir,
			managed: false,
			installed: false,
			compatible: true,
			canStart: false,
			metadata: { license: SIMPLIFY_LICENSE },
		};
	}

	return null;
}

export function resolveMsynth(options: ProtectionToolResolveOptions = {}): ProtectionToolResolved | null {
	const agentDir = options.agentDir ?? getAgentDir();
	const isWindows = (options.platform ?? process.platform) === "win32";
	const msynthDir = path.join(agentDir, "tools", "msynth");
	const venvDir = path.join(msynthDir, ".venv");
	const venvPy = path.join(venvDir, isWindows ? "Scripts/python.exe" : "bin/python");

	const hasVenv = isExecutableRegularFile(venvPy);

	if (hasVenv) {
		return {
			id: "msynth",
			kind: "python-package",
			path: venvPy,
			binDir: path.dirname(venvPy),
			version: MSYNTH_VERSION,
			managed: true,
			installed: true,
			compatible: true,
			canStart: true,
			metadata: {
				pythonPath: venvPy,
				venvDir,
				packageDir: msynthDir,
				version: MSYNTH_VERSION,
				license: MSYNTH_LICENSE,
			},
		};
	}

	if (options.allowMissing) {
		return {
			id: "msynth",
			kind: "python-package",
			path: venvPy,
			binDir: msynthDir,
			managed: false,
			installed: false,
			compatible: true,
			canStart: false,
			metadata: { license: MSYNTH_LICENSE },
		};
	}

	return null;
}

export function resolveTritondse(options: ProtectionToolResolveOptions = {}): ProtectionToolResolved | null {
	const agentDir = options.agentDir ?? getAgentDir();
	const isWindows = (options.platform ?? process.platform) === "win32";
	const tritondseDir = path.join(agentDir, "tools", "tritondse");
	const venvDir = path.join(tritondseDir, ".venv");
	const venvPy = path.join(venvDir, isWindows ? "Scripts/python.exe" : "bin/python");

	const wrapper = path.join(tritondseDir, "bin", isWindows ? "tritondse-python.cmd" : "tritondse-python");
	const effectivePy = isExecutableRegularFile(wrapper) ? wrapper : venvPy;

	const libDir = path.join(tritondseDir, "lib");
	const magicFile = path.join(tritondseDir, "share", "misc", "magic.mgc");
	const runEnv: NodeJS.ProcessEnv = {
		...process.env,
		...(options.env as NodeJS.ProcessEnv | undefined),
		DYLD_LIBRARY_PATH: fs.existsSync(libDir)
			? `${libDir}${process.env.DYLD_LIBRARY_PATH ? `:${process.env.DYLD_LIBRARY_PATH}` : ""}`
			: process.env.DYLD_LIBRARY_PATH,
		MAGIC: fs.existsSync(magicFile) ? magicFile : process.env.MAGIC,
	};

	// Strict check: probe if tritondse is actually present in venv (not merely python binary)
	const hasModule = (pyPath: string): boolean => {
		try {
			const res = child_process.spawnSync(pyPath, ["-I", "-c", "import tritondse; print('TRITONDSE_OK')"], {
				timeout: 2500,
				windowsHide: true,
				env: runEnv,
			});
			return res.status === 0 && res.stdout.toString().includes("TRITONDSE_OK");
		} catch {
			return false;
		}
	};

	if ((isExecutableRegularFile(effectivePy) || isExecutableRegularFile(venvPy)) && hasModule(effectivePy)) {
		return {
			id: "tritondse",
			kind: "python-package",
			path: effectivePy,
			binDir: path.dirname(effectivePy),
			version: TRITONDSE_VERSION,
			managed: true,
			installed: true,
			compatible: true,
			canStart: true,
			metadata: {
				executablePath: isExecutableRegularFile(wrapper) ? wrapper : effectivePy,
				pythonPath: effectivePy,
				version: TRITONDSE_VERSION,
				license: TRITONDSE_LICENSE,
			},
		};
	}

	const tritonVenvPy = path.join(
		agentDir,
		"tools",
		"vmp",
		"triton-venv",
		isWindows ? "Scripts/python.exe" : "bin/python",
	);
	if (isExecutableRegularFile(tritonVenvPy) && hasModule(tritonVenvPy)) {
		return {
			id: "tritondse",
			kind: "python-package",
			path: tritonVenvPy,
			binDir: path.dirname(tritonVenvPy),
			version: TRITONDSE_VERSION,
			managed: true,
			installed: true,
			compatible: true,
			canStart: true,
			metadata: {
				pythonPath: tritonVenvPy,
				version: TRITONDSE_VERSION,
				license: TRITONDSE_LICENSE,
			},
		};
	}

	if (options.allowMissing) {
		return {
			id: "tritondse",
			kind: "python-package",
			path: venvPy,
			binDir: tritondseDir,
			managed: false,
			installed: false,
			compatible: true,
			canStart: false,
			metadata: { license: TRITONDSE_LICENSE },
		};
	}

	return null;
}

// ============================================================================
// Public Authoritative Resolver & Inspector
// ============================================================================

export function resolveProtectionTool(
	id: ProtectionToolId,
	options: ProtectionToolResolveOptions = {},
): ProtectionToolResolved | null {
	switch (id) {
		case "frida-dexdump":
			return resolveFridaDexdump(options);
		case "fart":
			return resolveFart(options);
		case "qbdi":
			return resolveQbdi(options);
		case "jadx-string-decrypt":
			return resolveJadxStringDecrypt(options);
		case "dexkit":
			return resolveDexKit(options);
		case "d810-ng":
			return resolveD810Ng(options);
		case "blackdex":
			return resolveBlackDex(options);
		case "simplify":
			return resolveSimplify(options);
		case "msynth":
			return resolveMsynth(options);
		case "tritondse":
			return resolveTritondse(options);
	}
}

export function inspectProtectionTool(
	id: ProtectionToolId,
	options: ProtectionToolResolveOptions = {},
): ProtectionToolResolved {
	const resolved = resolveProtectionTool(id, { ...options, allowMissing: true });
	if (resolved) return resolved;
	return {
		id,
		kind: "cli",
		path: "",
		binDir: path.join(options.agentDir ?? getAgentDir(), "tools", id),
		managed: false,
		installed: false,
		compatible: true,
		canStart: false,
		metadata: {},
	};
}

// ============================================================================
// Real Upstream Installers
// ============================================================================

export async function installProtectionTool(
	id: ProtectionToolId,
	options: ProtectionToolInstallOptions = {},
): Promise<ProtectionToolInstallResult> {
	const agentDir = options.agentDir ?? getAgentDir();
	const isWindows = (options.platform ?? process.platform) === "win32";
	const log = options.onLog ?? options.onChunk ?? (() => {});

	try {
		switch (id) {
			case "frida-dexdump":
			case "msynth":
			case "d810-ng":
			case "tritondse": {
				const res = await installProtectionPythonTool(id, {
					agentDir: options.agentDir,
					onChunk: options.onChunk,
					onLog: options.onLog,
					signal: options.signal,
					timeoutMs: options.timeoutMs,
					env: options.env,
					which: options.which,
					platform: options.platform,
				});
				return {
					...res,
					id,
				};
			}

			case "dexkit": {
				const res = await installDexKit({
					agentDir: options.agentDir,
					onChunk: options.onChunk,
					onLog: options.onLog,
					signal: options.signal,
					timeoutMs: options.timeoutMs,
					which: options.which,
					platform: options.platform,
					env: options.env,
				});
				return {
					...res,
					id: "dexkit",
				};
			}

			case "qbdi": {
				const installDir = path.join(agentDir, "tools", "qbdi");
				await fsPromises.mkdir(installDir, { recursive: true });
				const platform = options.platform ?? process.platform;
				const arch = process.arch;
				const libName = platform === "darwin" ? "libQBDI.dylib" : platform === "win32" ? "QBDI.dll" : "libQBDI.so";
				const libPath = path.join(installDir, libName);
				const bindingPath = path.join(installDir, "frida-qbdi.js");

				// 1. Download official Frida binding
				log(`[reverse] Downloading QBDI v${QBDI_VERSION} Frida runtime binding...\n`);
				await downloadFileWithSha256(QBDI_FRIDA_BINDING_URL, bindingPath, undefined, {
					signal: options.signal,
					fetch: options.fetch,
					onLog: log,
					timeoutMs: options.timeoutMs,
				});

				// 2. Download and extract host native library
				if (platform === "darwin") {
					const asset = arch === "arm64" ? QBDI_RELEASE_ASSETS.darwin_arm64 : QBDI_RELEASE_ASSETS.darwin_x64;
					const pkgPath = path.join(installDir, path.basename(asset.url));
					log(`[reverse] Downloading QBDI macOS package (${path.basename(asset.url)})...\n`);
					await downloadFileWithSha256(asset.url, pkgPath, asset.sha256, {
						signal: options.signal,
						fetch: options.fetch,
						onLog: log,
						timeoutMs: options.timeoutMs,
					});

					const expandedDir = path.join(installDir, ".expanded-pkg");
					try {
						await runCheckedSubprocess(["/usr/sbin/pkgutil", "--expand-full", pkgPath, expandedDir], {
							onLog: log,
							signal: options.signal,
						});

						const findFileInDir = (dir: string, target: string): string | null => {
							for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
								const full = path.join(dir, entry.name);
								if (entry.isDirectory()) {
									const found = findFileInDir(full, target);
									if (found) return found;
								} else if (entry.name === target) {
									return full;
								}
							}
							return null;
						};

						const extractedLib = findFileInDir(expandedDir, "libQBDI.dylib");
						if (extractedLib && fs.existsSync(extractedLib)) {
							await fsPromises.copyFile(extractedLib, libPath);
						}
					} finally {
						await fsPromises.rm(expandedDir, { recursive: true, force: true }).catch(() => {});
						await fsPromises.rm(pkgPath, { force: true }).catch(() => {});
					}
				}

				// 3. For Linux: compile libQBDI.so from pinned upstream source using CMake
				if (platform === "linux") {
					const whichFn = options.which ?? ((bin, opts) => $which(bin, opts));
					const hasCmake = whichFn("cmake", { cache: WhichCachePolicy.Bypass }) !== null;
					const hasGit = whichFn("git", { cache: WhichCachePolicy.Bypass }) !== null;

					if (!hasCmake || !hasGit) {
						throw new Error(
							"QBDI host installation on Linux requires cmake, git, and a C++ compiler to build libQBDI.so from pinned upstream source (tag v0.12.1).",
						);
					}

					const repoDir = path.join(installDir, "QBDI-src");
					if (!fs.existsSync(repoDir)) {
						log(`[reverse] Cloning QBDI repository (tag ${QBDI_TAG})...\n`);
						await runCheckedSubprocess(
							["git", "clone", "--depth", "1", "--branch", QBDI_TAG, QBDI_UPSTREAM_URL, repoDir],
							{ onLog: log, signal: options.signal },
						);
					}

					const buildDir = path.join(repoDir, "build");
					log(`[reverse] Building QBDI shared library on Linux via CMake...\n`);
					await runCheckedSubprocess(
						[
							"cmake",
							"-B",
							buildDir,
							"-S",
							repoDir,
							"-DCMAKE_BUILD_TYPE=Release",
							"-DQBDI_SHARED_LIBRARY=ON",
							"-DQBDI_TOOLS_FRIDAQBDI=ON",
						],
						{ onLog: log, signal: options.signal },
					);
					await runCheckedSubprocess(["cmake", "--build", buildDir, "--config", "Release", "--target", "QBDI"], {
						onLog: log,
						signal: options.signal,
					});

					const builtLibCandidates = [
						path.join(buildDir, "libQBDI.so"),
						path.join(buildDir, "lib", "libQBDI.so"),
						path.join(buildDir, "src", "libQBDI.so"),
					];
					for (const cand of builtLibCandidates) {
						if (fs.existsSync(cand)) {
							await fsPromises.copyFile(cand, libPath);
							break;
						}
					}
				}
				if (platform === "win32") {
					const whichFn = options.which ?? ((bin, opts) => $which(bin, opts));
					const sevenZipBin =
						whichFn("7z", { cache: WhichCachePolicy.Bypass }) ??
						whichFn("7za", { cache: WhichCachePolicy.Bypass });
					const hasCmake = whichFn("cmake", { cache: WhichCachePolicy.Bypass }) !== null;
					const hasGit = whichFn("git", { cache: WhichCachePolicy.Bypass }) !== null;

					if (sevenZipBin) {
						const winAsset = {
							url: `https://github.com/QBDI/QBDI/releases/download/${QBDI_TAG}/QBDI-${QBDI_VERSION}-windows-X86_64.exe`,
							sha256: "2cbb5d01d4b75042a2cfbf9372841f7b126c08c4d70bff359cd8c53b6b6fa390",
						};
						const exePath = path.join(installDir, "qbdi-installer.exe");
						log(`[reverse] Downloading QBDI Windows x86_64 installer with verified SHA256...\n`);
						await downloadFileWithSha256(winAsset.url, exePath, winAsset.sha256, {
							signal: options.signal,
							fetch: options.fetch,
							onLog: log,
							timeoutMs: options.timeoutMs,
						});

						const extractedDir = path.join(installDir, ".extracted-win");
						try {
							await fsPromises.mkdir(extractedDir, { recursive: true });
							log(
								`[reverse] Extracting QBDI package via ${path.basename(sevenZipBin)} (isolated user scope)...\n`,
							);
							await runCheckedSubprocess([sevenZipBin, "x", "-y", `-o${extractedDir}`, exePath], {
								signal: options.signal,
								onLog: log,
							});

							const findFileInDir = (dir: string, target: string): string | null => {
								for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
									const full = path.join(dir, entry.name);
									if (entry.isDirectory()) {
										const found = findFileInDir(full, target);
										if (found) return found;
									} else if (entry.name.toLowerCase() === target.toLowerCase()) {
										return full;
									}
								}
								return null;
							};

							const extractedDll = findFileInDir(extractedDir, "QBDI.dll");
							if (extractedDll && fs.existsSync(extractedDll)) {
								await fsPromises.copyFile(extractedDll, libPath);
							}
						} finally {
							await fsPromises.rm(extractedDir, { recursive: true, force: true }).catch(() => {});
							await fsPromises.rm(exePath, { force: true }).catch(() => {});
						}
					} else if (hasCmake && hasGit) {
						const repoDir = path.join(installDir, "QBDI-src");
						if (!fs.existsSync(repoDir)) {
							log(`[reverse] Cloning QBDI repository (tag ${QBDI_TAG})...\n`);
							await runCheckedSubprocess(
								["git", "clone", "--depth", "1", "--branch", QBDI_TAG, QBDI_UPSTREAM_URL, repoDir],
								{ onLog: log, signal: options.signal },
							);
						}

						const buildDir = path.join(repoDir, "build");
						log(`[reverse] Building QBDI shared library on Windows via CMake...\n`);
						await runCheckedSubprocess(
							[
								"cmake",
								"-B",
								buildDir,
								"-S",
								repoDir,
								"-DCMAKE_BUILD_TYPE=Release",
								"-DQBDI_SHARED_LIBRARY=ON",
								"-DQBDI_TOOLS_FRIDAQBDI=ON",
							],
							{ onLog: log, signal: options.signal },
						);
						await runCheckedSubprocess(
							["cmake", "--build", buildDir, "--config", "Release", "--target", "QBDI"],
							{ onLog: log, signal: options.signal },
						);

						const candDlls = [
							path.join(buildDir, "Release", "QBDI.dll"),
							path.join(buildDir, "bin", "Release", "QBDI.dll"),
							path.join(buildDir, "QBDI.dll"),
						];
						for (const c of candDlls) {
							if (fs.existsSync(c)) {
								await fsPromises.copyFile(c, libPath);
								break;
							}
						}
					} else {
						throw new Error(
							"Isolated QBDI installation on Windows requires 7z/7za to unpack the verified installer or cmake/compiler to build from source without global installer execution.",
						);
					}
				}

				// 4. Download and extract Android ARM64 and ARM32 target libraries
				const arm64Dir = path.join(installDir, "android-arm64");
				const arm32Dir = path.join(installDir, "android-arm");
				await fsPromises.mkdir(arm64Dir, { recursive: true });
				await fsPromises.mkdir(arm32Dir, { recursive: true });

				const arm64Asset = QBDI_RELEASE_ASSETS.android_arm64;
				const arm64Tar = path.join(installDir, path.basename(arm64Asset.url));
				log(`[reverse] Downloading QBDI Android ARM64 target library...\n`);
				await downloadFileWithSha256(arm64Asset.url, arm64Tar, arm64Asset.sha256, {
					signal: options.signal,
					fetch: options.fetch,
					onLog: log,
					timeoutMs: options.timeoutMs,
				});

				try {
					await extractTarMemberByPattern(
						arm64Tar,
						path.join(arm64Dir, ".staging"),
						"libQBDI.so",
						path.join(arm64Dir, "libQBDI.so"),
						{ signal: options.signal, onLog: log },
					);
				} finally {
					await fsPromises.rm(arm64Tar, { force: true }).catch(() => {});
					await fsPromises.rm(path.join(arm64Dir, ".staging"), { recursive: true, force: true }).catch(() => {});
				}

				const arm32Asset = QBDI_RELEASE_ASSETS.android_arm32;
				const arm32Tar = path.join(installDir, path.basename(arm32Asset.url));
				log(`[reverse] Downloading QBDI Android ARM32 target library...\n`);
				await downloadFileWithSha256(arm32Asset.url, arm32Tar, arm32Asset.sha256, {
					signal: options.signal,
					fetch: options.fetch,
					onLog: log,
					timeoutMs: options.timeoutMs,
				});
				try {
					await extractTarMemberByPattern(
						arm32Tar,
						path.join(arm32Dir, ".staging"),
						"libQBDI.so",
						path.join(arm32Dir, "libQBDI.so"),
						{ signal: options.signal, onLog: log },
					);
				} finally {
					await fsPromises.rm(arm32Tar, { force: true }).catch(() => {});
					await fsPromises.rm(path.join(arm32Dir, ".staging"), { recursive: true, force: true }).catch(() => {});
				}
				if (!fs.existsSync(libPath) && platform !== "android") {
					throw new Error(
						`QBDI native host library ${libName} was not found at ${libPath}. Ensure platform compilation or package extraction succeeded on ${platform}.`,
					);
				}

				return {
					success: true,
					id: "qbdi",
					installDir,
					executablePath: fs.existsSync(libPath) ? libPath : bindingPath,
					message: `QBDI v${QBDI_VERSION} native libraries (host + Android arm64/arm) and Frida binding provisioned at ${installDir}`,
				};
			}

			case "jadx-string-decrypt": {
				const installDir = path.join(agentDir, "tools", "jadx-plugins");
				await fsPromises.mkdir(installDir, { recursive: true });
				const jarPath = path.join(installDir, `jadx-string-decrypt-${JADX_STRING_DECRYPT_VERSION}.jar`);
				const linkPath = path.join(installDir, "jadx-string-decrypt.jar");

				log(
					`[reverse] Downloading JADX string decryption plugin jar (Arsylk/jadx-string-decrypt v${JADX_STRING_DECRYPT_VERSION})...\n`,
				);
				await downloadFileWithSha256(JADX_STRING_DECRYPT_JAR_URL, jarPath, JADX_STRING_DECRYPT_SHA256, {
					signal: options.signal,
					fetch: options.fetch,
					onLog: log,
					timeoutMs: options.timeoutMs,
				});

				if (!isValidZipHeader(jarPath) || fs.statSync(jarPath).size < 50_000) {
					throw new Error("Downloaded jadx-string-decrypt jar is corrupted or invalid.");
				}

				await fsPromises.copyFile(jarPath, linkPath);

				const dropinDir = path.join(agentDir, "tools", "jadx-config", "plugins", "dropins");
				const dropinJar = path.join(dropinDir, "jadx-string-decrypt.jar");

				// Register with JADX if installed
				const whichFn = options.which ?? ((bin, opts) => $which(bin, opts));
				const jadxBin = whichFn("jadx", { cache: WhichCachePolicy.Bypass });
				if (jadxBin && isExecutableRegularFile(jadxBin)) {
					const jadxEnv = {
						...(options.env ?? process.env),
						JADX_CONFIG_DIR: path.join(agentDir, "tools", "jadx-config"),
					};
					// Remove dropin to avoid 'Duplicate plugin id: string-decrypt' collision
					await fsPromises.rm(dropinJar, { force: true }).catch(() => {});
					log(`[reverse] Registering plugin with JADX (jadx plugins --install-jar)...\n`);
					await runCheckedSubprocess([jadxBin, "plugins", "--install-jar", jarPath], {
						env: jadxEnv,
						onLog: log,
						signal: options.signal,
					});
					const listOut = await runCheckedSubprocess([jadxBin, "plugins", "--list-all"], {
						env: jadxEnv,
						onLog: log,
						signal: options.signal,
					});
					const activeLine = listOut
						.split("\n")
						.find(l => l.includes("string-decrypt") && !l.includes("disabled"));
					if (!activeLine) {
						throw new Error(
							`JADX plugin registration failed: 'jadx plugins --list-all' does not list an active string-decrypt plugin.`,
						);
					}
				} else {
					// Stage into isolated JADX dropin configuration directory for offline discovery
					await fsPromises.mkdir(dropinDir, { recursive: true });
					await fsPromises.copyFile(jarPath, dropinJar);
				}

				return {
					success: true,
					id: "jadx-string-decrypt",
					installDir,
					executablePath: jarPath,
					message: `JADX string decryption plugin staged at ${jarPath}`,
				};
			}

			case "blackdex": {
				const installDir = path.join(agentDir, "tools", "blackdex");
				await fsPromises.mkdir(installDir, { recursive: true });

				const apk32 = path.join(installDir, "app-BlackDex32.apk");
				const apk64 = path.join(installDir, "app-BlackDex64.apk");

				log(`[reverse] Downloading BlackDex 32-bit APK...\n`);
				await downloadFileWithSha256(BLACKDEX_URL_32, apk32, undefined, {
					signal: options.signal,
					fetch: options.fetch,
					onLog: log,
					timeoutMs: options.timeoutMs,
				});

				log(`[reverse] Downloading BlackDex 64-bit APK...\n`);
				await downloadFileWithSha256(BLACKDEX_URL_64, apk64, undefined, {
					signal: options.signal,
					fetch: options.fetch,
					onLog: log,
					timeoutMs: options.timeoutMs,
				});

				if (
					!isValidZipHeader(apk32) ||
					!isValidZipHeader(apk64) ||
					fs.statSync(apk32).size < 1_000_000 ||
					fs.statSync(apk64).size < 1_000_000
				) {
					throw new Error("Downloaded BlackDex APKs failed integrity check.");
				}

				return {
					success: true,
					id: "blackdex",
					installDir,
					executablePath: apk64,
					message: `BlackDex APKs provisioned at ${installDir}`,
				};
			}

			case "simplify": {
				const installDir = path.join(agentDir, "tools", "simplify");
				const binDir = path.join(installDir, "bin");
				await fsPromises.mkdir(binDir, { recursive: true });

				const jarVersioned = path.join(installDir, `simplify-${SIMPLIFY_VERSION}.jar`);
				const jarStandard = path.join(installDir, "simplify.jar");

				log(`[reverse] Downloading Simplify JAR v${SIMPLIFY_VERSION}...\n`);
				await downloadFileWithSha256(SIMPLIFY_JAR_URL, jarVersioned, undefined, {
					signal: options.signal,
					fetch: options.fetch,
					onLog: log,
					timeoutMs: options.timeoutMs,
				});

				if (!isValidZipHeader(jarVersioned) || fs.statSync(jarVersioned).size < 10_000_000) {
					throw new Error("Downloaded Simplify JAR is corrupted or invalid.");
				}

				await fsPromises.copyFile(jarVersioned, jarStandard);

				const wrapperPath = path.join(binDir, isWindows ? "simplify.cmd" : "simplify");
				if (isWindows) {
					const batContent =
						[
							`@echo off`,
							`set "JAVA_CMD=java"`,
							`if defined JAVA_HOME set "JAVA_CMD=%JAVA_HOME%\\bin\\java"`,
							`set "ADD_OPENS="`,
							`for /f "tokens=3" %%g in ('"%JAVA_CMD%" -version 2^>^&1 ^| findstr /i "version"') do set "JVER=%%~g"`,
							`if defined JVER (`,
							`    for /f "delims=." %%a in ("%JVER%") do (`,
							`        if "%%a"=="1" (`,
							`            for /f "tokens=2 delims=." %%b in ("%JVER%") do set "JMAJOR=%%b"`,
							`        ) else (`,
							`            set "JMAJOR=%%a"`,
							`        )`,
							`    )`,
							`)`,
							`if defined JMAJOR if %JMAJOR% geq 9 set "ADD_OPENS=--add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED"`,
							`"%JAVA_CMD%" %ADD_OPENS% -jar "%~dp0..\\simplify.jar" %*`,
						].join("\r\n") + "\r\n";
					await fsPromises.writeFile(wrapperPath, batContent);
				} else {
					const shContent =
						[
							`#!/usr/bin/env bash`,
							`JAVA_CMD="\${JAVA_HOME:+$JAVA_HOME/bin/}java"`,
							`JAVA_VER=$("$JAVA_CMD" -version 2>&1 | awk -F '"' '/version/ {print $2}' | awk -F '.' '{if ($1=="1") print $2; else print $1}')`,
							`ADD_OPENS=""`,
							`if [ -n "$JAVA_VER" ] && [ "$JAVA_VER" -ge 9 ] 2>/dev/null; then`,
							`    ADD_OPENS="--add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED"`,
							`fi`,
							`exec "$JAVA_CMD" $ADD_OPENS -jar "$(dirname "$0")/../simplify.jar" "$@"`,
						].join("\n") + "\n";
					await fsPromises.writeFile(wrapperPath, shContent, { mode: 0o755 });
				}
				return {
					success: true,
					id: "simplify",
					installDir,
					executablePath: wrapperPath,
					message: `Simplify JAR and wrapper provisioned at ${installDir}`,
				};
			}

			case "fart": {
				const installDir = path.join(agentDir, "tools", "fart");
				await fsPromises.mkdir(installDir, { recursive: true });

				log(`[reverse] Fetching FART repository archive (Apache-2.0, commit ${FART_COMMIT.slice(0, 8)})...\n`);
				const fetchFn = options.fetch ?? globalThis.fetch;
				const resp = await fetchFn(FART_ARCHIVE_URL, { signal: options.signal });
				if (!resp.ok) {
					throw new Error(`Failed to fetch FART archive: HTTP ${resp.status}`);
				}
				const archiveBytes = Buffer.from(await resp.arrayBuffer());
				await extractArchive({ bytes: archiveBytes, format: "tar.gz" }, installDir);

				return {
					success: true,
					id: "fart",
					installDir,
					executablePath: installDir,
					message: `FART offline repair reference assets provisioned at ${installDir}`,
				};
			}
		}
	} catch (err: unknown) {
		const message = err instanceof Error ? err.message : String(err);
		return {
			success: false,
			id,
			installDir: path.join(agentDir, "tools", id),
			executablePath: "",
			error: `Installation failed for ${id}: ${message}`,
		};
	}
}
