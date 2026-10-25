/**
 * DexKit Backend Resolver and Installer.
 *
 * Upstream: LuckyPray/DexKit (pinned v2.3.0, commit c9cd12a14b75409bebd2f73e4dfc5ff575df3eb8, Core LGPL-3.0, wrapper Apache-2.0).
 * Downloads, compiles, and stages host JNI shared library + Java/Kotlin wrapper runtime
 * dependencies + thin DexSearchBridge runner for structured DEX/APK code search:
 * - Compiles host JNI shared library (`libdexkit.dylib` / `.so` / `.dll`) via CMake targeting
 *   upstream `dexkit/src/main/cpp` (consuming Core + host JNI headers without vendoring Core)
 * - Fetches upstream DexKit API classes (`dexkit.jar`) extracted from Maven Central AAR,
 *   along with pinned Kotlin standard library and Google FlatBuffers runtime jars
 * - Compiles project thin bridge (`packages/coding-agent/src/tools/dex-search/DexSearchBridge.java`)
 *   into managed `dexkit-bridge.jar`
 * - Emits launcher wrapper scripts using unified `AppClassLoader` classpath (`-cp "<dir>/*"`)
 *   and native library path (`-Djava.library.path="<dir>"`)
 * - Postinstall executes real DexKit JNI initialization and query verification against a deterministic
 *   synthetic DEX fixture before promoting staged files into the managed agent directory
 * - Preserves upstream LICENSE receipts and notice documentation
 * - Rollback on failure: performs isolated staging in temporary directory before atomic publication
 */
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { $which, getAgentDir, WhichCachePolicy, type WhichOptions } from "@reverse/utils";
import { extractArchive } from "@reverse/utils/ar";
import { runSubprocess } from "./triton-source-install";
import type { SkillRequirementWhich } from "./skill-requirements";
import type { SkillToolPlatform } from "./skill-tool-catalog";
import dexSearchBridgeSource from "../tools/dex-search/DexSearchBridge.java" with { type: "text" };

// Pinned Upstream Constants
export const DEXKIT_VERSION = "2.3.0";
export const DEXKIT_TAG = "2.3.0";
export const DEXKIT_COMMIT = "c9cd12a14b75409bebd2f73e4dfc5ff575df3eb8";
export const DEXKIT_REPO_URL = "https://github.com/LuckyPray/DexKit.git";
export const DEXKIT_LICENSE_CORE = "LGPL-3.0";
export const DEXKIT_LICENSE_WRAPPER = "Apache-2.0";

// Upstream Maven AAR and Dependency Jars with Exact Checksums
export const DEXKIT_AAR_URLS = [
	"https://maven.aliyun.com/repository/public/org/luckypray/dexkit/2.3.0/dexkit-2.3.0.aar",
	"https://repo1.maven.org/maven2/org/luckypray/dexkit/2.3.0/dexkit-2.3.0.aar",
] as const;
export const DEXKIT_AAR_SHA256 = "8df532c4126b58490667f71127dc57aef62ccf3578d1d17330f2a1cb8836218e";
export const DEXKIT_CLASSES_JAR_SHA256 = "34a8c16d548aa7d8562128f4d2293cec4e0f9896bb1f46224dcd532e878900f5";

export const FLATBUFFERS_VERSION = "23.5.26";
export const FLATBUFFERS_JAR_URLS = [
	"https://maven.aliyun.com/repository/public/com/google/flatbuffers/flatbuffers-java/23.5.26/flatbuffers-java-23.5.26.jar",
	"https://repo1.maven.org/maven2/com/google/flatbuffers/flatbuffers-java/23.5.26/flatbuffers-java-23.5.26.jar",
] as const;
export const FLATBUFFERS_JAR_SHA256 = "8d10cac2ea9878896077ba437d76fdb1b9a07f55a863c560bb8a024b04103f8b";

export const KOTLIN_STDLIB_VERSION = "1.9.22";
export const KOTLIN_STDLIB_JAR_URLS = [
	"https://maven.aliyun.com/repository/public/org/jetbrains/kotlin/kotlin-stdlib/1.9.22/kotlin-stdlib-1.9.22.jar",
	"https://repo1.maven.org/maven2/org/jetbrains/kotlin/kotlin-stdlib/1.9.22/kotlin-stdlib-1.9.22.jar",
] as const;
export const KOTLIN_STDLIB_JAR_SHA256 = "6abe146c27864138b874ccccfe5f534e3eb923c99a1b7b5d45494ee5694f3e0a";

export interface DexKitInstallOptions {
	agentDir?: string;
	onChunk?: (chunk: string) => void;
	onLog?: (chunk: string) => void;
	signal?: AbortSignal;
	timeoutMs?: number;
	which?: SkillRequirementWhich;
	platform?: SkillToolPlatform;
	env?: Record<string, string | undefined>;
	fetch?: (
		input: Parameters<typeof globalThis.fetch>[0],
		init?: Parameters<typeof globalThis.fetch>[1],
	) => Promise<Response>;
	/** Optional pre-built JNI shared library path to reuse instead of recompiling */
	prebuiltLibPath?: string;
	/** Optional pre-cloned upstream source directory to reuse */
	upstreamSrcDir?: string;
	/** Optional explicit path to DexSearchBridge.java */
	bridgeSourcePath?: string;
}

export interface DexKitInstallResult {
	success: boolean;
	installDir: string;
	executablePath: string;
	error?: string;
	message?: string;
	jniVerified?: boolean;
	classesVerified?: boolean;
}

export interface DexKitResolutionInfo {
	installed: boolean;
	canStart: boolean;
	installDir: string;
	libPath?: string;
	bridgeJar?: string;
	dexkitJar?: string;
	flatbuffersJar?: string;
	kotlinStdlibJar?: string;
	wrapperBin?: string;
	missingComponents: string[];
}

/**
 * Returns expected native library filename for the given host platform.
 */
export function getDexKitNativeLibName(platform: NodeJS.Platform = process.platform): string {
	if (platform === "darwin") return "libdexkit.dylib";
	if (platform === "win32") return "dexkit.dll";
	return "libdexkit.so";
}

/**
 * Validates whether host platform and architecture are supported for DexKit host JNI.
 */
export function isSupportedHostPlatform(
	platform: NodeJS.Platform = process.platform,
	arch: string = process.arch,
): boolean {
	if (platform === "darwin") return arch === "arm64" || arch === "x64";
	if (platform === "linux") return arch === "x64" || arch === "arm64";
	if (platform === "win32") return arch === "x64";
	return false;
}

/**
 * Inspects a directory to check for all required DexKit runtime artifacts.
 */
export function resolveDexKitInstallation(options?: {
	agentDir?: string;
	platform?: SkillToolPlatform;
}): DexKitResolutionInfo {
	const agentDir = options?.agentDir ?? getAgentDir();
	const platform = options?.platform ?? (process.platform as SkillToolPlatform);
	const installDir = path.join(agentDir, "tools", "dexkit");
	const libName = getDexKitNativeLibName(platform as NodeJS.Platform);

	const libPath = path.join(installDir, libName);
	const bridgeJar = path.join(installDir, "dexkit-bridge.jar");
	const dexkitJar = path.join(installDir, "dexkit.jar");
	const flatbuffersJar = path.join(installDir, `flatbuffers-java-${FLATBUFFERS_VERSION}.jar`);
	const kotlinStdlibJar = path.join(installDir, `kotlin-stdlib-${KOTLIN_STDLIB_VERSION}.jar`);
	const isWindows = platform === "win32";
	const wrapperBin = path.join(installDir, "bin", isWindows ? "dexkit.cmd" : "dexkit");

	const missingComponents: string[] = [];

	let hasValidLib = false;
	try {
		if (fs.existsSync(libPath)) {
			const stat = fs.statSync(libPath);
			if (stat.size >= 100_000) hasValidLib = true;
		}
	} catch {}
	if (!hasValidLib) missingComponents.push(libName);

	const checkJar = (p: string, name: string) => {
		try {
			if (fs.existsSync(p) && fs.statSync(p).size > 1024) return true;
		} catch {}
		missingComponents.push(name);
		return false;
	};

	const hasBridge = checkJar(bridgeJar, "dexkit-bridge.jar");
	const hasDexkit = checkJar(dexkitJar, "dexkit.jar");
	const hasFlatbuffers = checkJar(flatbuffersJar, `flatbuffers-java-${FLATBUFFERS_VERSION}.jar`);
	const hasKotlin = checkJar(kotlinStdlibJar, `kotlin-stdlib-${KOTLIN_STDLIB_VERSION}.jar`);

	let hasWrapper = false;
	try {
		if (fs.existsSync(wrapperBin)) hasWrapper = true;
	} catch {}

	const installed = hasValidLib || hasBridge || hasDexkit || hasWrapper;
	const canStart = hasValidLib && hasBridge && hasDexkit && hasFlatbuffers && hasKotlin;

	return {
		installed,
		canStart,
		installDir,
		libPath: hasValidLib ? libPath : undefined,
		bridgeJar: hasBridge ? bridgeJar : undefined,
		dexkitJar: hasDexkit ? dexkitJar : undefined,
		flatbuffersJar: hasFlatbuffers ? flatbuffersJar : undefined,
		kotlinStdlibJar: hasKotlin ? kotlinStdlibJar : undefined,
		wrapperBin: hasWrapper ? wrapperBin : undefined,
		missingComponents,
	};
}

/** Maximum allowed size for any single dependency download (50 MB). */
const DEFAULT_MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024;
/** Default deadline for download requests (60 seconds per request). */
const DEFAULT_DOWNLOAD_TIMEOUT_MS = 60_000;

/**
 * Downloads a file from an ordered list of URLs with stream size bounding,
 * default deadline, and SHA-256 integrity verification.
 */
async function downloadWithMirrors(
	urls: readonly string[],
	destPath: string,
	expectedSha256?: string,
	options?: {
		signal?: AbortSignal;
		fetch?: DexKitInstallOptions["fetch"];
		onLog?: (msg: string) => void;
		maxBytes?: number;
		timeoutMs?: number;
	},
): Promise<Buffer> {
	const fetchFn = options?.fetch ?? globalThis.fetch;
	const log = options?.onLog ?? (() => {});
	const maxBytes = options?.maxBytes ?? DEFAULT_MAX_DOWNLOAD_BYTES;
	const reqTimeoutMs = options?.timeoutMs ?? DEFAULT_DOWNLOAD_TIMEOUT_MS;

	let lastError: Error | null = null;
	for (const url of urls) {
		if (options?.signal?.aborted) {
			throw new Error("Download aborted by signal");
		}

		const attemptController = new AbortController();
		const timeoutId = setTimeout(() => {
			attemptController.abort(new Error(`Download attempt timed out after ${reqTimeoutMs}ms for ${url}`));
		}, reqTimeoutMs);

		const abortListener = () => {
			attemptController.abort(options?.signal?.reason ?? new Error("Download aborted by caller signal"));
		};
		if (options?.signal) {
			options.signal.addEventListener("abort", abortListener, { once: true });
		}

		try {
			log(`[dexkit] Downloading ${path.basename(destPath)} from ${url}...\n`);
			const res = await fetchFn(url, { signal: attemptController.signal });
			if (!res.ok) {
				throw new Error(`HTTP ${res.status} ${res.statusText}`);
			}

			const clHeader = res.headers.get("content-length");
			if (clHeader) {
				const cl = Number.parseInt(clHeader, 10);
				if (!Number.isNaN(cl) && cl > maxBytes) {
					throw new Error(`Content-Length ${cl} exceeds maximum limit of ${maxBytes} bytes for ${url}`);
				}
			}

			if (!res.body) {
				throw new Error(`Response body is empty for ${url}`);
			}

			const reader = res.body.getReader();
			const chunks: Uint8Array[] = [];
			let receivedBytes = 0;
			try {
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					if (value) {
						receivedBytes += value.byteLength;
						if (receivedBytes > maxBytes) {
							await reader.cancel();
							throw new Error(`Download stream exceeded safety limit of ${maxBytes} bytes for ${url}`);
						}
						chunks.push(value);
					}
				}
			} finally {
				reader.releaseLock();
			}

			const buffer = Buffer.concat(chunks);

			if (expectedSha256) {
				const actualHash = crypto.createHash("sha256").update(buffer).digest("hex");
				if (actualHash.toLowerCase() !== expectedSha256.toLowerCase()) {
					throw new Error(`SHA-256 mismatch for ${url}: expected ${expectedSha256}, got ${actualHash}`);
				}
			}

			await fs.promises.mkdir(path.dirname(destPath), { recursive: true });
			await fs.promises.writeFile(destPath, buffer);
			return buffer;
		} catch (err) {
			lastError = err instanceof Error ? err : new Error(String(err));
			log(`[dexkit] Download failed from ${url}: ${lastError.message}\n`);
		} finally {
			clearTimeout(timeoutId);
			if (options?.signal) {
				options.signal.removeEventListener("abort", abortListener);
			}
		}
	}

	throw lastError ?? new Error(`All download mirrors failed for ${destPath}`);
}

/**
 * Locates Java SDK home directory for JNI headers during CMake configuration.
 */
function findJavaHome(env?: Record<string, string | undefined>): string | null {
	const candidates = [
		env?.JAVA_HOME,
		process.env.JAVA_HOME,
		"/opt/homebrew/opt/openjdk@25/libexec/openjdk.jdk/Contents/Home",
		"/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home",
		"/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home",
		"/Library/Java/JavaVirtualMachines/zulu-21.jdk/Contents/Home",
	];

	for (const cand of candidates) {
		if (cand && fs.existsSync(cand) && fs.existsSync(path.join(cand, "include"))) {
			return cand;
		}
	}

	if (process.platform === "darwin") {
		try {
			fs.accessSync("/usr/libexec/java_home", fs.constants.X_OK);
			const { execSync } = require("node:child_process");
			const out = execSync("/usr/libexec/java_home 2>/dev/null", { encoding: "utf8" }).trim();
			if (out && fs.existsSync(out)) return out;
		} catch {}
	}

	return null;
}

/**
 * Verifies exported JNI symbols in the compiled host shared library.
 */
function verifyJniSymbols(libPath: string, platform: NodeJS.Platform = process.platform): boolean {
	if (!fs.existsSync(libPath)) return false;
	try {
		const stat = fs.statSync(libPath);
		if (stat.size < 100_000) return false;
		const { execSync } = require("node:child_process");
		let cmd = "";
		if (platform === "darwin") {
			cmd = `nm -gU "${libPath}" | grep -E "Java_org_luckypray_dexkit_DexKitBridge"`;
		} else if (platform === "linux") {
			cmd = `nm -D "${libPath}" 2>/dev/null | grep -E "Java_org_luckypray_dexkit_DexKitBridge"`;
		} else if (platform === "win32") {
			cmd = `dumpbin /EXPORTS "${libPath}" 2>nul | findstr "Java_org_luckypray_dexkit_DexKitBridge"`;
		}
		if (!cmd) return false;
		const out = execSync(cmd, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
		return out.includes("nativeInitDexKit") || out.includes("DexKitBridge");
	} catch {
		return false;
	}
}

// ============================================================================
// Deterministic Dalvik Fixture Builder for Postinstall Verification
// ============================================================================

function adler32(buf: Buffer | Uint8Array): number {
	let a = 1;
	let b = 0;
	const MOD = 65521;
	for (let i = 0; i < buf.length; i++) {
		a = (a + buf[i]!) % MOD;
		b = (b + a) % MOD;
	}
	return ((b << 16) | a) >>> 0;
}

function uleb128(n: number): Buffer {
	const out: number[] = [];
	let val = n;
	while (true) {
		let byte = val & 0x7f;
		val >>>= 7;
		if (val !== 0) {
			byte |= 0x80;
			out.push(byte);
		} else {
			out.push(byte);
			break;
		}
	}
	return Buffer.from(out);
}

function p16(n: number): Buffer {
	const b = Buffer.alloc(2);
	b.writeUInt16LE(n, 0);
	return b;
}

function p32(n: number): Buffer {
	const b = Buffer.alloc(4);
	b.writeUInt32LE(n, 0);
	return b;
}

/**
 * Builds a deterministic synthetic DEX file containing:
 * - Class Lcom/example/TestGate;
 * - Method isLicensed()Z with conditional branch and const/4 returns.
 * - Method compute()I with const/4 return.
 */
export function buildDeterministicDexFixture(): Buffer {
	const CALLER = "Lcom/example/TestGate;";
	const OBJECT = "Ljava/lang/Object;";
	const strings = [CALLER, OBJECT, "I", "V", "Z", "compute", "isLicensed"].sort();
	const sidx: Record<string, number> = {};
	strings.forEach((s, i) => {
		sidx[s] = i;
	});

	const types = [CALLER, OBJECT, "I", "V", "Z"].sort((a, b) => sidx[a]! - sidx[b]!);
	const tidx: Record<string, number> = {};
	types.forEach((t, i) => {
		tidx[t] = i;
	});

	const protos = [
		{ shorty: "I", ret: "I" },
		{ shorty: "V", ret: "V" },
		{ shorty: "Z", ret: "Z" },
	].sort((a, b) => tidx[a.ret]! - tidx[b.ret]!);
	const pidx: Record<string, number> = {};
	protos.forEach((p, i) => {
		pidx[p.ret] = i;
	});

	const methods = [
		{ cls: CALLER, name: "compute", ret: "I" },
		{ cls: CALLER, name: "isLicensed", ret: "Z" },
	].sort((a, b) => {
		if (tidx[a.cls] !== tidx[b.cls]) return tidx[a.cls]! - tidx[b.cls]!;
		if (sidx[a.name] !== sidx[b.name]) return sidx[a.name]! - sidx[b.name]!;
		return pidx[a.ret]! - pidx[b.ret]!;
	});
	const midx: Record<string, number> = {};
	methods.forEach((m, i) => {
		midx[m.name] = i;
	});

	const insns_isLicensed = [0x0012, 0x0039, 0x0004, 0x1012, 0x000f, 0x0012, 0x000f];
	const insns_compute = [0x2012, 0x000f];

	function makeCodeItem(registers: number, insns: number[]): Buffer {
		const body = Buffer.concat(insns.map(p16));
		return Buffer.concat([p16(registers), p16(0), p16(0), p16(0), p32(0), p32(insns.length), body]);
	}

	let off = 0x70;
	const string_ids_off = off;
	off += 4 * strings.length;
	const type_ids_off = off;
	off += 4 * types.length;
	const proto_ids_off = off;
	off += 12 * protos.length;
	const method_ids_off = off;
	off += 8 * methods.length;
	const class_defs_off = off;
	off += 32 * 1;
	const data_off = off;

	const dataParts: Buffer[] = [];
	let dataLen = 0;
	function align4() {
		while (dataLen % 4 !== 0) {
			dataParts.push(Buffer.from([0]));
			dataLen += 1;
		}
	}

	const strOffs: number[] = [];
	for (const s of strings) {
		strOffs.push(data_off + dataLen);
		const raw = Buffer.from(s, "utf-8");
		const strData = Buffer.concat([uleb128(raw.length), raw, Buffer.from([0])]);
		dataParts.push(strData);
		dataLen += strData.length;
	}

	align4();
	const codeLicensedOff = data_off + dataLen;
	const codeLicensedBuf = makeCodeItem(1, insns_isLicensed);
	dataParts.push(codeLicensedBuf);
	dataLen += codeLicensedBuf.length;

	align4();
	const codeComputeOff = data_off + dataLen;
	const codeComputeBuf = makeCodeItem(1, insns_compute);
	dataParts.push(codeComputeBuf);
	dataLen += codeComputeBuf.length;

	align4();
	const classDataOff = data_off + dataLen;
	const classDataEntries = [
		{ midx: midx["compute"]!, acc: 0x0009, codeOff: codeComputeOff },
		{ midx: midx["isLicensed"]!, acc: 0x0009, codeOff: codeLicensedOff },
	].sort((a, b) => a.midx - b.midx);

	let cdBuf = Buffer.concat([uleb128(0), uleb128(0), uleb128(classDataEntries.length), uleb128(0)]);
	let lastMidx = 0;
	for (const entry of classDataEntries) {
		cdBuf = Buffer.concat([cdBuf, uleb128(entry.midx - lastMidx), uleb128(entry.acc), uleb128(entry.codeOff)]);
		lastMidx = entry.midx;
	}
	dataParts.push(cdBuf);
	dataLen += cdBuf.length;

	align4();
	const mapOff = data_off + dataLen;
	const mapItems = [
		{ type: 0x0000, size: 1, offset: 0 },
		{ type: 0x0001, size: strings.length, offset: string_ids_off },
		{ type: 0x0002, size: types.length, offset: type_ids_off },
		{ type: 0x0003, size: protos.length, offset: proto_ids_off },
		{ type: 0x0005, size: methods.length, offset: method_ids_off },
		{ type: 0x0006, size: 1, offset: class_defs_off },
		{ type: 0x2002, size: strings.length, offset: strOffs[0]! },
		{ type: 0x2001, size: 2, offset: codeLicensedOff },
		{ type: 0x2000, size: 1, offset: classDataOff },
		{ type: 0x1000, size: 1, offset: mapOff },
	].sort((a, b) => a.offset - b.offset);

	let mapListBuf = p32(mapItems.length);
	for (const item of mapItems) {
		mapListBuf = Buffer.concat([mapListBuf, p16(item.type), p16(0), p32(item.size), p32(item.offset)]);
	}
	dataParts.push(mapListBuf);
	dataLen += mapListBuf.length;

	const stringIdsBuf = Buffer.concat(strOffs.map(p32));
	const typeIdsBuf = Buffer.concat(types.map(t => p32(sidx[t]!)));
	const protoIdsBuf = Buffer.concat(protos.map(p => Buffer.concat([p32(sidx[p.shorty]!), p32(tidx[p.ret]!), p32(0)])));
	const methodIdsBuf = Buffer.concat(
		methods.map(m => Buffer.concat([p16(tidx[m.cls]!), p16(pidx[m.ret]!), p32(sidx[m.name]!)])),
	);

	const classDefBuf = Buffer.concat([
		p32(tidx[CALLER]!),
		p32(0x0001),
		p32(tidx[OBJECT]!),
		p32(0),
		p32(0xffffffff),
		p32(0),
		p32(classDataOff),
		p32(0),
	]);

	const dataSection = Buffer.concat(dataParts);
	const fileSize = data_off + dataSection.length;

	const headerBuf = Buffer.alloc(0x70);
	headerBuf.write("dex\n035\0", 0, 8, "ascii");
	headerBuf.writeUInt32LE(fileSize, 0x20);
	headerBuf.writeUInt32LE(0x70, 0x24);
	headerBuf.writeUInt32LE(0x12345678, 0x28);
	headerBuf.writeUInt32LE(mapOff, 0x34);
	headerBuf.writeUInt32LE(strings.length, 0x38);
	headerBuf.writeUInt32LE(string_ids_off, 0x3c);
	headerBuf.writeUInt32LE(types.length, 0x40);
	headerBuf.writeUInt32LE(type_ids_off, 0x44);
	headerBuf.writeUInt32LE(protos.length, 0x48);
	headerBuf.writeUInt32LE(proto_ids_off, 0x4c);
	headerBuf.writeUInt32LE(0, 0x50);
	headerBuf.writeUInt32LE(0, 0x54);
	headerBuf.writeUInt32LE(methods.length, 0x58);
	headerBuf.writeUInt32LE(method_ids_off, 0x5c);
	headerBuf.writeUInt32LE(1, 0x60);
	headerBuf.writeUInt32LE(class_defs_off, 0x64);
	headerBuf.writeUInt32LE(dataSection.length, 0x68);
	headerBuf.writeUInt32LE(data_off, 0x6c);

	const dexBlob = Buffer.concat([
		headerBuf,
		stringIdsBuf,
		typeIdsBuf,
		protoIdsBuf,
		methodIdsBuf,
		classDefBuf,
		dataSection,
	]);

	const sha1 = crypto.createHash("sha1").update(dexBlob.subarray(32)).digest();
	sha1.copy(dexBlob, 12);

	const adler = adler32(dexBlob.subarray(12));
	dexBlob.writeUInt32LE(adler, 8);

	return dexBlob;
}

/**
 * Creates a minimal valid APK (ZIP format) containing classes.dex in store mode.
 */
function createStoreZipWithClassesDex(dexBuffer: Buffer): Buffer {
	const filename = "classes.dex";
	const filenameBytes = Buffer.from(filename, "utf8");
	const crc = crc32(dexBuffer);
	const size = dexBuffer.length;

	// Local file header (30 bytes + name)
	const localHeader = Buffer.alloc(30 + filenameBytes.length);
	localHeader.writeUInt32LE(0x04034b50, 0); // Local header signature
	localHeader.writeUInt16LE(20, 4); // Min version 2.0
	localHeader.writeUInt16LE(0, 6); // General purpose bit flag
	localHeader.writeUInt16LE(0, 8); // Store compression (0)
	localHeader.writeUInt16LE(0, 10); // File modification time
	localHeader.writeUInt16LE(0, 12); // File modification date
	localHeader.writeUInt32LE(crc, 14); // CRC-32
	localHeader.writeUInt32LE(size, 18); // Compressed size
	localHeader.writeUInt32LE(size, 22); // Uncompressed size
	localHeader.writeUInt16LE(filenameBytes.length, 26); // Filename length
	localHeader.writeUInt16LE(0, 28); // Extra field length
	filenameBytes.copy(localHeader, 30);

	const localHeaderOffset = 0;

	// Central directory header (46 bytes + name)
	const cdHeader = Buffer.alloc(46 + filenameBytes.length);
	cdHeader.writeUInt32LE(0x02014b50, 0); // Central directory signature
	cdHeader.writeUInt16LE(20, 4); // Version made by
	cdHeader.writeUInt16LE(20, 6); // Min version to extract
	cdHeader.writeUInt16LE(0, 8); // General purpose bit flag
	cdHeader.writeUInt16LE(0, 10); // Store compression
	cdHeader.writeUInt16LE(0, 12); // Modification time
	cdHeader.writeUInt16LE(0, 14); // Modification date
	cdHeader.writeUInt32LE(crc, 16); // CRC-32
	cdHeader.writeUInt32LE(size, 20); // Compressed size
	cdHeader.writeUInt32LE(size, 24); // Uncompressed size
	cdHeader.writeUInt16LE(filenameBytes.length, 28); // Filename length
	cdHeader.writeUInt16LE(0, 30); // Extra field length
	cdHeader.writeUInt16LE(0, 32); // File comment length
	cdHeader.writeUInt16LE(0, 34); // Disk number start
	cdHeader.writeUInt16LE(0, 36); // Internal file attributes
	cdHeader.writeUInt32LE(0, 38); // External file attributes
	cdHeader.writeUInt32LE(localHeaderOffset, 42); // Relative offset of local header
	filenameBytes.copy(cdHeader, 46);

	const cdOffset = localHeader.length + dexBuffer.length;
	const cdSize = cdHeader.length;

	// End of central directory record (22 bytes)
	const eocd = Buffer.alloc(22);
	eocd.writeUInt32LE(0x06054b50, 0); // EOCD signature
	eocd.writeUInt16LE(0, 4); // Disk number
	eocd.writeUInt16LE(0, 6); // Start disk
	eocd.writeUInt16LE(1, 8); // Entries on disk
	eocd.writeUInt16LE(1, 10); // Total entries
	eocd.writeUInt32LE(cdSize, 12); // Central directory size
	eocd.writeUInt32LE(cdOffset, 16); // Central directory offset
	eocd.writeUInt16LE(0, 20); // Comment length

	return Buffer.concat([localHeader, dexBuffer, cdHeader, eocd]);
}

function crc32(buf: Buffer): number {
	let crc = ~0;
	for (let i = 0; i < buf.length; i++) {
		crc ^= buf[i]!;
		for (let j = 0; j < 8; j++) {
			crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
		}
	}
	return ~crc >>> 0;
}

// ============================================================================
// Main Installer Implementation
// ============================================================================

/**
 * Installs DexKit v2.3.0 into the managed agent directory with host JNI library,
 * Java/Kotlin runtime dependencies, thin DexSearchBridge, and postinstall query verification.
 */
export async function installDexKit(options: DexKitInstallOptions = {}): Promise<DexKitInstallResult> {
	const log = options.onLog ?? options.onChunk ?? (() => {});
	const agentDir = options.agentDir ?? getAgentDir();
	const platform = options.platform ?? (process.platform as SkillToolPlatform);
	const nodePlatform = platform as NodeJS.Platform;

	if (!isSupportedHostPlatform(nodePlatform, process.arch)) {
		const msg = `Host platform '${platform}' (${process.arch}) is not supported by DexKit native engine. Supported: macOS (arm64, x64), Linux (x64, arm64), Windows (x64).`;
		log(`[dexkit] ${msg}\n`);
		return {
			success: false,
			installDir: path.join(agentDir, "tools", "dexkit"),
			executablePath: "",
			error: msg,
		};
	}

	const installDir = path.join(agentDir, "tools", "dexkit");
	const stageDir = path.join(agentDir, "tools", `.dexkit-stage-${crypto.randomBytes(6).toString("hex")}`);
	const binDir = path.join(stageDir, "bin");
	const isWindows = nodePlatform === "win32";
	const libName = getDexKitNativeLibName(nodePlatform);
	const libPath = path.join(stageDir, libName);
	const bridgeJar = path.join(stageDir, "dexkit-bridge.jar");
	const dexkitJar = path.join(stageDir, "dexkit.jar");
	const flatbuffersJar = path.join(stageDir, `flatbuffers-java-${FLATBUFFERS_VERSION}.jar`);
	const kotlinStdlibJar = path.join(stageDir, `kotlin-stdlib-${KOTLIN_STDLIB_VERSION}.jar`);
	const wrapperPath = path.join(binDir, isWindows ? "dexkit.cmd" : "dexkit");
	const searchWrapper = path.join(stageDir, isWindows ? "dexkit-search.cmd" : "dexkit-search");

	const whichFn = options.which ?? ((bin, opts) => $which(bin, opts));
	const whichOpts: WhichOptions = { PATH: options.env?.PATH, cache: WhichCachePolicy.Bypass };

	const javaBin = whichFn("java", whichOpts);
	const javacBin = whichFn("javac", whichOpts);
	const jarBin = whichFn("jar", whichOpts);

	if (!javaBin || !javacBin || !jarBin) {
		const msg = `JDK 11+ is required for DexKit compilation and runtime (missing: ${[!javaBin && "java", !javacBin && "javac", !jarBin && "jar"].filter(Boolean).join(", ")}).`;
		log(`[dexkit] ${msg}\n`);
		return {
			success: false,
			installDir,
			executablePath: "",
			error: msg,
		};
	}

	log(`[dexkit] Initializing staging directory: ${stageDir}\n`);
	await fs.promises.mkdir(binDir, { recursive: true });

	let stageSuccess = false;
	try {
		// ------------------------------------------------------------------------
		// 1. Download FlatBuffers and Kotlin stdlib runtime dependencies
		// ------------------------------------------------------------------------
		log(`[dexkit] Provisioning Google FlatBuffers v${FLATBUFFERS_VERSION}...\n`);
		await downloadWithMirrors(FLATBUFFERS_JAR_URLS, flatbuffersJar, FLATBUFFERS_JAR_SHA256, {
			signal: options.signal,
			fetch: options.fetch,
			onLog: log,
			timeoutMs: options.timeoutMs,
		});

		log(`[dexkit] Provisioning JetBrains Kotlin stdlib v${KOTLIN_STDLIB_VERSION}...\n`);
		await downloadWithMirrors(KOTLIN_STDLIB_JAR_URLS, kotlinStdlibJar, KOTLIN_STDLIB_JAR_SHA256, {
			signal: options.signal,
			fetch: options.fetch,
			onLog: log,
			timeoutMs: options.timeoutMs,
		});
		// ------------------------------------------------------------------------
		// 2. Download and unpack upstream DexKit classes.jar from Maven Central AAR
		// ------------------------------------------------------------------------
		const tempAarPath = path.join(stageDir, ".dexkit-temp.aar");
		const tempExtractDir = path.join(stageDir, ".dexkit-aar-extract");
		try {
			log(`[dexkit] Provisioning upstream DexKit v${DEXKIT_VERSION} classes from Maven AAR...\n`);
			const aarBytes = await downloadWithMirrors(DEXKIT_AAR_URLS, tempAarPath, DEXKIT_AAR_SHA256, {
				signal: options.signal,
				fetch: options.fetch,
				onLog: log,
				timeoutMs: options.timeoutMs,
			});

			await fs.promises.mkdir(tempExtractDir, { recursive: true });
			await extractArchive({ bytes: aarBytes, format: "zip" }, tempExtractDir);

			const extractedClassesJar = path.join(tempExtractDir, "classes.jar");
			if (!fs.existsSync(extractedClassesJar)) {
				throw new Error("DexKit AAR did not contain classes.jar");
			}

			// Verify classes.jar checksum
			const classesJarBuf = await fs.promises.readFile(extractedClassesJar);
			const actualClassesHash = crypto.createHash("sha256").update(classesJarBuf).digest("hex");
			if (actualClassesHash.toLowerCase() !== DEXKIT_CLASSES_JAR_SHA256.toLowerCase()) {
				throw new Error(
					`classes.jar SHA-256 mismatch: expected ${DEXKIT_CLASSES_JAR_SHA256}, got ${actualClassesHash}`,
				);
			}

			await fs.promises.copyFile(extractedClassesJar, dexkitJar);
			log(`[dexkit] Installed DexKit classes.jar -> ${dexkitJar} (${classesJarBuf.length} bytes)\n`);
		} finally {
			await fs.promises.rm(tempAarPath, { force: true }).catch(() => {});
			await fs.promises.rm(tempExtractDir, { recursive: true, force: true }).catch(() => {});
		}

		// ------------------------------------------------------------------------
		// 3. Compile the embedded thin bridge in private staging
		// ------------------------------------------------------------------------
		// 文本资产随独立二进制分发，安装不依赖源码目录仍然存在。
		const bridgeSourceDir = path.join(stageDir, ".bridge-source");
		const bridgeSrc = options.bridgeSourcePath ?? path.join(bridgeSourceDir, "DexSearchBridge.java");
		if (!options.bridgeSourcePath) {
			await fs.promises.mkdir(bridgeSourceDir, { recursive: true });
			await fs.promises.writeFile(bridgeSrc, dexSearchBridgeSource);
		}

		log(`[dexkit] Compiling DexSearchBridge from ${bridgeSrc}...\n`);
		const bridgeClassesDir = path.join(stageDir, ".bridge-classes");
		await fs.promises.mkdir(bridgeClassesDir, { recursive: true });
		try {
			const javacRes = await runSubprocess([javacBin, "-d", bridgeClassesDir, bridgeSrc], {
				onChunk: log,
				signal: options.signal,
				env: options.env,
				timeoutMs: options.timeoutMs,
			});
			if (javacRes.exitCode !== 0) {
				throw new Error(`javac failed (exit ${javacRes.exitCode}): ${javacRes.stderr || javacRes.stdout}`);
			}

			const jarRes = await runSubprocess(
				[jarBin, "cfe", bridgeJar, "org.reverse.dexsearch.DexSearchBridge", "-C", bridgeClassesDir, "."],
				{ onChunk: log, signal: options.signal, env: options.env, timeoutMs: options.timeoutMs },
			);
			if (jarRes.exitCode !== 0) {
				throw new Error(`jar packaging failed (exit ${jarRes.exitCode}): ${jarRes.stderr || jarRes.stdout}`);
			}
			log(`[dexkit] Packaged dexkit-bridge.jar successfully\n`);
		} finally {
			await fs.promises.rm(bridgeClassesDir, { recursive: true, force: true }).catch(() => {});
			await fs.promises.rm(bridgeSourceDir, { recursive: true, force: true }).catch(() => {});
		}

		// ------------------------------------------------------------------------
		// 4. Provision host JNI shared library (libdexkit.dylib / .so / .dll)
		// ------------------------------------------------------------------------
		let jniAcquired = false;

		// 4a. Check explicitly supplied prebuilt library
		if (options.prebuiltLibPath && fs.existsSync(options.prebuiltLibPath)) {
			if (verifyJniSymbols(options.prebuiltLibPath, nodePlatform)) {
				log(`[dexkit] Using verified host JNI shared library from ${options.prebuiltLibPath}\n`);
				await fs.promises.copyFile(options.prebuiltLibPath, libPath);
				jniAcquired = true;
			} else {
				log(
					`[dexkit] Prebuilt library at ${options.prebuiltLibPath} failed JNI symbol verification; building from source...\n`,
				);
			}
		}

		// 4b. If not prebuilt, compile from upstream CMake
		if (!jniAcquired) {
			const cmakeBin = whichFn("cmake", whichOpts);
			const gitBin = whichFn("git", whichOpts);
			if (!cmakeBin) {
				throw new Error(
					"cmake is required to build DexKit host JNI shared library, but cmake was not found in PATH.",
				);
			}

			let upstreamSrc = options.upstreamSrcDir;
			const tempCloneDir = path.join(stageDir, ".dexkit-src");
			if (!upstreamSrc || !fs.existsSync(upstreamSrc)) {
				if (!gitBin) {
					throw new Error("git is required to fetch LuckyPray/DexKit source for host JNI compilation.");
				}
				log(`[dexkit] Cloning LuckyPray/DexKit (tag ${DEXKIT_TAG}, commit ${DEXKIT_COMMIT})...\n`);
				const gitRes = await runSubprocess(
					[gitBin, "clone", "--depth", "1", "--branch", DEXKIT_TAG, DEXKIT_REPO_URL, tempCloneDir],
					{ onChunk: log, signal: options.signal, env: options.env, timeoutMs: options.timeoutMs },
				);
				if (gitRes.exitCode !== 0) {
					throw new Error(`git clone failed (exit ${gitRes.exitCode}): ${gitRes.stderr || gitRes.stdout}`);
				}
				upstreamSrc = tempCloneDir;
			}

			const cppDir = path.join(upstreamSrc, "dexkit/src/main/cpp");
			if (!fs.existsSync(path.join(cppDir, "CMakeLists.txt"))) {
				throw new Error(`Upstream JNI CMakeLists.txt not found at ${cppDir}`);
			}

			const buildDir = path.join(stageDir, ".dexkit-build");
			log(`[dexkit] Configuring CMake for DexKit host JNI shared library...\n`);

			const javaHome = findJavaHome(options.env);
			const buildEnv: Record<string, string | undefined> = { ...options.env };
			if (javaHome && !buildEnv.JAVA_HOME) {
				buildEnv.JAVA_HOME = javaHome;
			}

			const ninjaBin = whichFn("ninja", whichOpts);
			const cmakeConfigureArgs = [
				cmakeBin,
				"-B",
				buildDir,
				"-S",
				cppDir,
				"-DCMAKE_BUILD_TYPE=Release",
				"-DCMAKE_CXX_STANDARD=20",
			];
			if (ninjaBin) {
				cmakeConfigureArgs.push("-GNinja");
			}

			const cfgRes = await runSubprocess(cmakeConfigureArgs, {
				onChunk: log,
				signal: options.signal,
				env: buildEnv,
				timeoutMs: options.timeoutMs,
			});
			if (cfgRes.exitCode !== 0) {
				throw new Error(`CMake configuration failed: ${cfgRes.stderr || cfgRes.stdout}`);
			}

			log(`[dexkit] Building DexKit host JNI shared library with CMake...\n`);
			const buildRes = await runSubprocess([cmakeBin, "--build", buildDir, "--config", "Release"], {
				onChunk: log,
				signal: options.signal,
				env: buildEnv,
				timeoutMs: options.timeoutMs,
			});
			if (buildRes.exitCode !== 0) {
				throw new Error(`CMake build failed: ${buildRes.stderr || buildRes.stdout}`);
			}

			const buildCandidates = [
				path.join(buildDir, libName),
				path.join(buildDir, "Release", libName),
				path.join(buildDir, "dexkit", libName),
			];
			const foundLib = buildCandidates.find(p => fs.existsSync(p));
			if (!foundLib) {
				throw new Error(`Compiled shared library ${libName} not found in ${buildDir}`);
			}

			await fs.promises.copyFile(foundLib, libPath);
			await fs.promises.rm(buildDir, { recursive: true, force: true }).catch(() => {});
			if (fs.existsSync(tempCloneDir)) {
				await fs.promises.rm(tempCloneDir, { recursive: true, force: true }).catch(() => {});
			}
			jniAcquired = true;
		}

		if (!verifyJniSymbols(libPath, nodePlatform)) {
			throw new Error(`Installed host library ${libPath} does not export required DexKit JNI symbols.`);
		}
		log(`[dexkit] Verified JNI shared library: ${libPath}\n`);

		// ------------------------------------------------------------------------
		// 5. Emit launcher wrapper scripts
		// ------------------------------------------------------------------------
		if (isWindows) {
			const batBin = `@echo off\r\nset "LIB_DIR=%~dp0.."\r\n"${javaBin}" -Djava.library.path="%LIB_DIR%" -cp "%LIB_DIR%\\*" org.reverse.dexsearch.DexSearchBridge %*\r\n`;
			const batSearch = `@echo off\r\nset "LIB_DIR=%~dp0"\r\n"${javaBin}" -Djava.library.path="%LIB_DIR%" -cp "%LIB_DIR%\\*" org.reverse.dexsearch.DexSearchBridge %*\r\n`;
			await fs.promises.writeFile(wrapperPath, batBin, "utf8");
			await fs.promises.writeFile(searchWrapper, batSearch, "utf8");
		} else {
			const shBin = `#!/usr/bin/env bash\nSCRIPT_DIR="$(cd "$(dirname "\${BASH_SOURCE[0]}")" && pwd)"\nLIB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"\nexec "${javaBin}" -Djava.library.path="$LIB_DIR" -cp "$LIB_DIR/*" org.reverse.dexsearch.DexSearchBridge "$@"\n`;
			const shSearch = `#!/usr/bin/env bash\nLIB_DIR="$(cd "$(dirname "\${BASH_SOURCE[0]}")" && pwd)"\nexec "${javaBin}" -Djava.library.path="$LIB_DIR" -cp "$LIB_DIR/*" org.reverse.dexsearch.DexSearchBridge "$@"\n`;
			await fs.promises.writeFile(wrapperPath, shBin, { mode: 0o755 });
			await fs.promises.writeFile(searchWrapper, shSearch, { mode: 0o755 });
		}

		// ------------------------------------------------------------------------
		// 6. Write License Receipts and Upstream Attribution Notices
		// ------------------------------------------------------------------------
		const receipt = {
			name: "dexkit",
			version: DEXKIT_VERSION,
			installedAt: new Date().toISOString(),
			hostPlatform: process.platform,
			hostArch: process.arch,
			components: [
				{
					name: "LuckyPray/DexKit Core",
					version: DEXKIT_VERSION,
					commit: DEXKIT_COMMIT,
					upstream: DEXKIT_REPO_URL,
					license: DEXKIT_LICENSE_CORE,
					distribution: "external host JNI shared library (zero Core source vendored)",
				},
				{
					name: "LuckyPray/DexKit Java API",
					version: DEXKIT_VERSION,
					upstream: DEXKIT_AAR_URLS[0],
					sha256: DEXKIT_CLASSES_JAR_SHA256,
					license: DEXKIT_LICENSE_WRAPPER,
				},
				{
					name: "Google FlatBuffers Java",
					version: FLATBUFFERS_VERSION,
					upstream: FLATBUFFERS_JAR_URLS[0],
					sha256: FLATBUFFERS_JAR_SHA256,
					license: "Apache-2.0",
				},
				{
					name: "JetBrains Kotlin Standard Library",
					version: KOTLIN_STDLIB_VERSION,
					upstream: KOTLIN_STDLIB_JAR_URLS[0],
					sha256: KOTLIN_STDLIB_JAR_SHA256,
					license: "Apache-2.0",
				},
				{
					name: "DexSearchBridge",
					version: DEXKIT_VERSION,
					source: "packages/coding-agent/src/tools/dex-search/DexSearchBridge.java",
					license: "Apache-2.0",
				},
			],
		};
		await fs.promises.writeFile(
			path.join(stageDir, "LICENSE-RECEIPT.json"),
			JSON.stringify(receipt, null, 2),
			"utf8",
		);

		const noticesText = `DexKit Third-Party Notices & Licenses
===================================================

1. LuckyPray/DexKit Core
   Upstream: https://github.com/LuckyPray/DexKit
   Version: 2.3.0 (commit ${DEXKIT_COMMIT})
   License: GNU Lesser General Public License v3.0 (LGPL-3.0)
   Notice: Reverse compiles and links the host JNI shared library dynamically as an external component.
   No LGPL-3.0 Core source code is vendored into Reverse.

2. LuckyPray/DexKit Java/Kotlin API (classes.jar)
   License: Apache License 2.0
   Copyright (c) LuckyPray

3. Google FlatBuffers (flatbuffers-java)
   Version: 23.5.26
   License: Apache License 2.0
   Copyright (c) Google LLC

4. JetBrains Kotlin Standard Library (kotlin-stdlib)
   Version: 1.9.22
   License: Apache License 2.0
   Copyright (c) JetBrains s.r.o.

5. Reverse DexSearchBridge
   Source: packages/coding-agent/src/tools/dex-search/DexSearchBridge.java
   License: Apache License 2.0
   Copyright (c) Reverse Contributors
`;
		await fs.promises.writeFile(path.join(stageDir, "NOTICES.txt"), noticesText, "utf8");

		// ------------------------------------------------------------------------
		// 7. Postinstall Verification: Execute Real Query Against Deterministic Fixture
		// ------------------------------------------------------------------------
		log(`[dexkit] Running postinstall verification on deterministic DEX fixture...\n`);
		const dexFixtureBytes = buildDeterministicDexFixture();
		const apkFixtureBytes = createStoreZipWithClassesDex(dexFixtureBytes);
		const testApkPath = path.join(stageDir, ".postinstall-test.apk");
		await fs.promises.writeFile(testApkPath, apkFixtureBytes);

		try {
			const queryPayload = JSON.stringify({
				action: "class",
				target: testApkPath,
				query: { className: "com.example.TestGate" },
			});

			const testArgs = [
				javaBin,
				`-Djava.library.path=${stageDir}`,
				"-cp",
				`${stageDir}/*`,
				"org.reverse.dexsearch.DexSearchBridge",
				"--input",
				queryPayload,
			];

			const testRes = await runSubprocess(testArgs, {
				signal: options.signal,
				env: options.env,
				timeoutMs: options.timeoutMs,
			});

			if (testRes.exitCode !== 0) {
				throw new Error(
					`DexSearchBridge verification process exited with code ${testRes.exitCode}: ${testRes.stderr || testRes.stdout}`,
				);
			}

			const out = testRes.stdout;
			const startIdx = out.indexOf("<<<DEX_SEARCH_OUTPUT_START>>>");
			const endIdx = out.indexOf("<<<DEX_SEARCH_OUTPUT_END>>>");
			if (startIdx === -1 || endIdx === -1 || endIdx <= startIdx) {
				throw new Error(`Verification output missing JSON delimiters: ${out}`);
			}

			const jsonStr = out.slice(startIdx + "<<<DEX_SEARCH_OUTPUT_START>>>".length, endIdx).trim();
			const parsed = JSON.parse(jsonStr);
			if (!parsed.success) {
				throw new Error(`DexKit verification query failed: ${parsed.error ?? jsonStr}`);
			}

			if (parsed.dexNum !== 1 || !Array.isArray(parsed.items) || parsed.items.length !== 1) {
				throw new Error(
					`Unexpected query verification results: dexNum=${parsed.dexNum}, items=${parsed.items?.length}`,
				);
			}

			const item = parsed.items[0];
			if (item.className !== "com.example.TestGate" || item.descriptor !== "Lcom/example/TestGate;") {
				throw new Error(`Verification item mismatch: ${JSON.stringify(item)}`);
			}

			log(`[dexkit] Postinstall verification succeeded: DexKit engine and JNI native bridge fully operational!\n`);
		} finally {
			await fs.promises.rm(testApkPath, { force: true }).catch(() => {});
		}

		stageSuccess = true;
	} catch (err) {
		const errorMsg = err instanceof Error ? err.message : String(err);
		log(`[dexkit] Installation failed during staging: ${errorMsg}\n`);
		return {
			success: false,
			installDir,
			executablePath: "",
			error: errorMsg,
		};
	} finally {
		if (!stageSuccess) {
			log(`[dexkit] Rolling back failed staging directory: ${stageDir}\n`);
			await fs.promises.rm(stageDir, { recursive: true, force: true }).catch(() => {});
		}
	}

	// ------------------------------------------------------------------------
	// 8. Atomic Promotion of Staged Files to Final Install Directory
	// ------------------------------------------------------------------------
	log(`[dexkit] Promoting staged files to ${installDir}...\n`);
	const backupDir = path.join(agentDir, "tools", `.dexkit-backup-${crypto.randomBytes(6).toString("hex")}`);
	let hasExistingInstall = false;

	try {
		await fs.promises.mkdir(path.dirname(installDir), { recursive: true });
		if (fs.existsSync(installDir)) {
			hasExistingInstall = true;
			await fs.promises.rename(installDir, backupDir);
		}
		await fs.promises.rename(stageDir, installDir);
		if (hasExistingInstall) {
			await fs.promises.rm(backupDir, { recursive: true, force: true }).catch(() => {});
		}
	} catch (err) {
		const msg = `Failed to promote staged DexKit files to ${installDir}: ${err instanceof Error ? err.message : String(err)}`;
		log(`[dexkit] ${msg}\n`);
		if (hasExistingInstall && fs.existsSync(backupDir)) {
			await fs.promises.rm(installDir, { recursive: true, force: true }).catch(() => {});
			await fs.promises.rename(backupDir, installDir).catch(() => {});
		}
		return {
			success: false,
			installDir,
			executablePath: "",
			error: msg,
		};
	} finally {
		if (fs.existsSync(stageDir)) {
			await fs.promises.rm(stageDir, { recursive: true, force: true }).catch(() => {});
		}
	}

	const finalExecutable = path.join(installDir, "bin", isWindows ? "dexkit.cmd" : "dexkit");
	return {
		success: true,
		installDir,
		executablePath: finalExecutable,
		message: `DexKit v${DEXKIT_VERSION} native library, Kotlin runtime dependencies, and DexSearchBridge successfully installed and verified at ${installDir}`,
		jniVerified: true,
		classesVerified: true,
	};
}
