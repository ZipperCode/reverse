/**
 * Focused regression and contract tests for RuntimeAnalyzeTool.
 *
 * Verifies:
 * - Offline static runtime inventory across APK archives and directories.
 * - Format boundary: correctly distinguishes plain React Native JS from binary Hermes Bytecode (HBC).
 * - Hermes version compatibility: hbctool (v59, 62, 74, 76) vs hermes-dec (v61-v96).
 * - Unity IL2CPP: global-metadata.dat sanity validation (0xFAB11BAF), version parsing,
 *   headless non-blocking execution, and Ghidra/IDA static engine handoff.
 * - Flutter Android AOT: arm64-v8a architecture constraint, distinguishing Flutter vs generic ELF,
 *   Dart snapshot hash extraction, and preventing silent unapproved background Dart VM builds.
 * - Target immutability and bounded artifact outputs.
 */

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import * as zlib from "node:zlib";
import { Settings } from "../src/config/settings";
import type { ToolSession } from "../src/tools";
import {
	RuntimeAnalyzeTool,
	HERMES_MAGIC_BYTES,
	UNITY_METADATA_MAGIC,
	ELF_MACHINE_AARCH64,
	ELF_MACHINE_ARM,
	computeHashes,
	isHermesBytecode,
	isPlainJavaScriptBundle,
	parseHermesHeader,
	parseUnityMetadataHeader,
	parseElfCharacteristics,
	type RuntimeAnalyzeRunner,
} from "../src/tools/runtime-analyze";

function createMockSession(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: false,
		settings: Settings.isolated({}),
	} as unknown as ToolSession;
}

// ============================================================================
// Fixture Helpers: Synthetic Bundles, Metadata, and ELFs
// ============================================================================

/** 生成合成 Hermes Bytecode 文件头及有效字节 */
function createHermesBytecodeBuffer(
	version: number,
	sourceHashHex = "0123456789abcdef0123456789abcdef01234567",
): Buffer {
	const buf = Buffer.alloc(64, 0);
	HERMES_MAGIC_BYTES.copy(buf, 0);
	buf.writeUInt32LE(version, 8);
	const hashBuf = Buffer.from(sourceHashHex, "hex");
	hashBuf.copy(buf, 12);
	buf.writeUInt32LE(64, 32); // file length
	return buf;
}

/** 生成合成 Plain React Native JS Bundle (Metro packager 风格) */
function createPlainJsBundleBuffer(): Buffer {
	return Buffer.from(
		'__d(function(g,r,i,a,m,e,d){"use strict";var x=r(d[0]);console.log("App startup", x);},0,[1]);\n' +
			'__d(function(g,r,i,a,m,e,d){"use strict";m.exports={name:"TestApp"};},1,[]);\n' +
			"require(0);\n",
		"utf8",
	);
}

/** 生成合成 Unity global-metadata.dat 文件 */
function createUnityMetadataBuffer(version: number, sanity = UNITY_METADATA_MAGIC): Buffer {
	const buf = Buffer.alloc(128, 0);
	buf.writeUInt32LE(sanity, 0);
	buf.writeInt32LE(version, 4);
	// 写入一些填充数据
	buf.writeInt32LE(16, 8); // stringLiteralOffset
	buf.writeInt32LE(64, 12); // stringLiteralSize
	return buf;
}

/** 生成合成 ELF 二进制 (支持指定机器架构、Dart AOT / Flutter / IL2CPP 符号) */
function createSyntheticElfBuffer(options: {
	machine: number;
	is64?: boolean;
	dartAot?: boolean;
	flutterEngine?: boolean;
	il2cpp?: boolean;
	snapshotHash?: string;
	dartVersion?: string;
}): Buffer {
	const buf = Buffer.alloc(512, 0);
	// ELF Magic \x7fELF
	buf[0] = 0x7f;
	buf[1] = 0x45;
	buf[2] = 0x4c;
	buf[3] = 0x46;
	buf[4] = options.is64 !== false ? 2 : 1; // 64-bit or 32-bit
	buf[5] = 1; // little-endian
	buf[6] = 1; // ELF version
	buf.writeUInt16LE(2, 16); // ET_EXEC / ET_DYN
	buf.writeUInt16LE(options.machine, 18); // e_machine

	// 在 ELF 数据区写入测试标记字符串
	let markerStr = "ELF_BODY_DATA:";
	if (options.dartAot) {
		markerStr += " _kDartVmSnapshotData _kDartVmSnapshotInstructions _kDartIsolateSnapshotInstructions";
		const hash = options.snapshotHash ?? "1234567890abcdef1234567890abcdef";
		markerStr += ` ${hash}product compressed-pointers arm64\0`;
	}
	if (options.flutterEngine) {
		markerStr += " FlutterEngine Dart_Initialize io.flutter";
	}
	if (options.il2cpp) {
		markerStr += " il2cpp_init il2cpp_runtime_invoke Il2CppCodeGen";
	}
	if (options.snapshotHash) {
		markerStr += ` Snapshot: ${options.snapshotHash} snapshot_hash\0${options.snapshotHash}`;
	}
	if (options.dartVersion) {
		markerStr += ` \0${options.dartVersion} (stable)\0`;
	}

	Buffer.from(markerStr, "latin1").copy(buf, 64);
	return buf;
}

/** CRC-32 计算 */
function crc32(buf: Buffer): number {
	let c = 0xffffffff;
	for (let i = 0; i < buf.length; i++) {
		c = (c >>> 8) ^ CRC_TABLE[(c ^ buf[i]!) & 0xff]!;
	}
	return (c ^ 0xffffffff) >>> 0;
}

const CRC_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
	let c = i;
	for (let k = 0; k < 8; k++) {
		c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
	}
	CRC_TABLE[i] = c >>> 0;
}

/** 生成合法的内存 ZIP/APK 文件 */
function createSyntheticZip(entries: Array<{ path: string; data: Buffer }>): Buffer {
	const localParts: Buffer[] = [];
	const centralParts: Buffer[] = [];
	let localOffset = 0;

	for (const entry of entries) {
		const nameBuf = Buffer.from(entry.path, "utf8");
		const raw = entry.data;
		const compressed = zlib.deflateRawSync(raw);
		const checksum = crc32(raw);

		const localHeader = Buffer.alloc(30, 0);
		localHeader.writeUInt32LE(0x04034b50, 0);
		localHeader.writeUInt16LE(20, 4);
		localHeader.writeUInt16LE(0, 6);
		localHeader.writeUInt16LE(8, 8); // deflate
		localHeader.writeUInt32LE(checksum, 14);
		localHeader.writeUInt32LE(compressed.length, 18);
		localHeader.writeUInt32LE(raw.length, 22);
		localHeader.writeUInt16LE(nameBuf.length, 26);

		localParts.push(localHeader, nameBuf, compressed);

		const centralHeader = Buffer.alloc(46, 0);
		centralHeader.writeUInt32LE(0x02014b50, 0);
		centralHeader.writeUInt16LE(20, 4);
		centralHeader.writeUInt16LE(20, 6);
		centralHeader.writeUInt16LE(0, 8);
		centralHeader.writeUInt16LE(8, 10);
		centralHeader.writeUInt32LE(checksum, 16);
		centralHeader.writeUInt32LE(compressed.length, 20);
		centralHeader.writeUInt32LE(raw.length, 24);
		centralHeader.writeUInt16LE(nameBuf.length, 28);
		centralHeader.writeUInt32LE(localOffset, 42);

		centralParts.push(centralHeader, nameBuf);
		localOffset += localHeader.length + nameBuf.length + compressed.length;
	}

	const centralDirectory = Buffer.concat(centralParts);
	const eocd = Buffer.alloc(22, 0);
	eocd.writeUInt32LE(0x06054b50, 0);
	eocd.writeUInt16LE(entries.length, 8);
	eocd.writeUInt16LE(entries.length, 10);
	eocd.writeUInt32LE(centralDirectory.length, 12);
	eocd.writeUInt32LE(localOffset, 16);

	return Buffer.concat([...localParts, centralDirectory, eocd]);
}

// ============================================================================
// Test Suites
// ============================================================================

describe("RuntimeAnalyzeTool", () => {
	let tmpDir: string;
	let session: ToolSession;

	beforeEach(async () => {
		tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "runtime-analyze-test-"));
		session = createMockSession(tmpDir);
	});

	afterEach(async () => {
		await fs.rm(tmpDir, { recursive: true, force: true });
	});

	// ========================================================================
	// 1. Format & Boundary Tests
	// ========================================================================

	describe("Format & Boundary Detection", () => {
		it("correctly identifies Hermes bytecode vs plain JavaScript bundle", () => {
			const hbcBuf = createHermesBytecodeBuffer(76);
			const plainJsBuf = createPlainJsBundleBuffer();

			expect(isHermesBytecode(hbcBuf)).toBe(true);
			expect(isPlainJavaScriptBundle(hbcBuf)).toBe(false);

			expect(isHermesBytecode(plainJsBuf)).toBe(false);
			expect(isPlainJavaScriptBundle(plainJsBuf)).toBe(true);

			const header = parseHermesHeader(hbcBuf);
			expect(header.isHbc).toBe(true);
			expect(header.version).toBe(76);
		});

		it("correctly validates Unity global-metadata.dat sanity magic", () => {
			const validMeta = createUnityMetadataBuffer(24);
			const invalidMeta = createUnityMetadataBuffer(24, 0x12345678);

			const validRes = parseUnityMetadataHeader(validMeta);
			expect(validRes.isValid).toBe(true);
			expect(validRes.sanity).toBe(UNITY_METADATA_MAGIC);
			expect(validRes.version).toBe(24);

			const invalidRes = parseUnityMetadataHeader(invalidMeta);
			expect(invalidRes.isValid).toBe(false);
			expect(invalidRes.sanity).toBe(0x12345678);
		});

		it("distinguishes Flutter Dart AOT snapshot vs generic ELF shared object", () => {
			const dartAotElf = createSyntheticElfBuffer({
				machine: ELF_MACHINE_AARCH64,
				dartAot: true,
				snapshotHash: "8c4749f10a8d795b59740523abcd1234",
				dartVersion: "3.2.0",
			});
			const genericElf = createSyntheticElfBuffer({
				machine: ELF_MACHINE_AARCH64,
				dartAot: false,
			});

			const dartParsed = parseElfCharacteristics(dartAotElf);
			expect(dartParsed.isElf).toBe(true);
			expect(dartParsed.architecture).toBe("arm64-v8a");
			expect(dartParsed.isDartAot).toBe(true);
			expect(dartParsed.dartSnapshotHash).toBe("8c4749f10a8d795b59740523abcd1234");
			expect(dartParsed.dartVersion).toBe("3.2.0");

			const genericParsed = parseElfCharacteristics(genericElf);
			expect(genericParsed.isElf).toBe(true);
			expect(genericParsed.isDartAot).toBe(false);
			expect(genericParsed.isFlutterEngine).toBe(false);
		});
	});

	// ========================================================================
	// 2. Action: Inventory
	// ========================================================================

	describe("Action: inventory", () => {
		it("detects mixed runtimes inside a synthetic APK archive without in-place mutation", async () => {
			const hbcBuf = createHermesBytecodeBuffer(74);
			const appSoBuf = createSyntheticElfBuffer({
				machine: ELF_MACHINE_AARCH64,
				dartAot: true,
				snapshotHash: "aabbccddeeff00112233445566778899",
			});
			const unityMetaBuf = createUnityMetadataBuffer(29);
			const apkBuf = createSyntheticZip([
				{ path: "assets/index.android.bundle", data: hbcBuf },
				{ path: "lib/arm64-v8a/libapp.so", data: appSoBuf },
				{
					path: "lib/arm64-v8a/libflutter.so",
					data: createSyntheticElfBuffer({
						machine: ELF_MACHINE_AARCH64,
						flutterEngine: true,
						dartVersion: "3.2.0",
					}),
				},
				{
					path: "lib/arm64-v8a/libil2cpp.so",
					data: createSyntheticElfBuffer({ machine: ELF_MACHINE_AARCH64, il2cpp: true }),
				},
				{ path: "assets/bin/Data/Managed/Metadata/global-metadata.dat", data: unityMetaBuf },
			]);

			const apkPath = path.join(tmpDir, "test-app.apk");
			await fs.writeFile(apkPath, apkBuf);
			const originalHashes = computeHashes(apkBuf);

			const tool = new RuntimeAnalyzeTool(session);
			const result = await tool.execute("call-inv-1", {
				action: "inventory",
				path: apkPath,
			});

			expect(result.details.status).toBe("ok");
			expect(result.details.inventory).toBeDefined();
			expect(result.details.inventory?.runtimes.length).toBeGreaterThanOrEqual(3);

			// 检查 React Native 检测结果
			const rn = result.details.inventory?.runtimes.find(r => r.runtime === "react_native");
			expect(rn).toBeDefined();
			expect(rn?.frameworkName).toContain("Hermes HBC v74");
			expect(rn?.recommendedAction).toBe("hermes");

			// 检查 Flutter 检测结果
			const flutter = result.details.inventory?.runtimes.find(r => r.runtime === "flutter");
			expect(flutter).toBeDefined();
			expect(flutter?.architecture).toBe("arm64-v8a");
			expect(flutter?.snapshotHash).toBe("aabbccddeeff00112233445566778899");
			expect(flutter?.recommendedAction).toBe("flutter");

			// 检查 Unity 检测结果
			const unity = result.details.inventory?.runtimes.find(r => r.runtime === "unity_il2cpp");
			expect(unity).toBeDefined();
			expect(unity?.recommendedAction).toBe("il2cpp");

			// 验证原始文件未被修改 (Target Immutability)
			const postBuf = await fs.readFile(apkPath);
			const postHashes = computeHashes(postBuf);
			expect(postHashes.sha256).toBe(originalHashes.sha256);
		});
	});

	// ========================================================================
	// 3. Action: Hermes (React Native)
	// ========================================================================

	describe("Action: hermes", () => {
		it("safely rejects plain JS bundles without executing hbctool", async () => {
			const plainJsPath = path.join(tmpDir, "index.android.bundle");
			await fs.writeFile(plainJsPath, createPlainJsBundleBuffer());

			let runnerCalled = false;
			const mockRunner: RuntimeAnalyzeRunner = async () => {
				runnerCalled = true;
				return { stdout: "", stderr: "", exitCode: 0, outputBytes: 0, truncated: false, timedOut: false };
			};

			const tool = new RuntimeAnalyzeTool(session, {
				which: () => "/usr/bin/hbctool",
				runner: mockRunner,
			});

			const res = await tool.execute("call-hermes-plain", {
				action: "hermes",
				path: plainJsPath,
			});

			expect(res.details.status).toBe("unsupported");
			expect(res.details.unsupportedReason).toContain("plain React Native JavaScript bundle");
			expect(res.details.unsupportedReason).toContain("sourcemap_inspect");
			expect(runnerCalled).toBe(false);
		});

		it("reports structured missing_dependency when hbctool and hermes-dec are absent", async () => {
			const hbcPath = path.join(tmpDir, "app.hbc");
			await fs.writeFile(hbcPath, createHermesBytecodeBuffer(74));

			const tool = new RuntimeAnalyzeTool(session, {
				which: () => null, // 没有任何工具
			});

			const res = await tool.execute("call-hermes-missing", {
				action: "hermes",
				path: hbcPath,
			});

			expect(res.details.status).toBe("missing_dependency");
			expect(res.details.missingDependency?.tool).toBe("hbctool");
			expect(res.details.missingDependency?.manualUrl).toBe("https://github.com/bongtrop/hbctool");
			expect(res.details.missingDependency?.installHint).toContain("pipx install hbctool");
			expect(res.details.missingDependency?.targetDiagnostics.bytecodeVersion).toBe(74);
		});

		it("reports unsupported version when target is HBC v96 and only hbctool is present", async () => {
			const hbcPath = path.join(tmpDir, "app-v96.hbc");
			await fs.writeFile(hbcPath, createHermesBytecodeBuffer(96));

			const tool = new RuntimeAnalyzeTool(session, {
				which: cmd => (cmd === "hbctool" ? "/usr/local/bin/hbctool" : null),
			});

			const res = await tool.execute("call-hermes-unsupported-ver", {
				action: "hermes",
				path: hbcPath,
			});

			expect(res.details.status).toBe("unsupported");
			expect(res.details.unsupportedReason).toContain("hbctool strictly supports HBC 59, 62, 74, 76 only");
			expect(res.details.unsupportedReason).toContain("pip install hermes-dec");
		});
	});
	// ========================================================================
	// 4. Action: Il2Cpp (Unity)
	// ========================================================================

	describe("Action: il2cpp", () => {
		it("detects corrupted/encrypted global-metadata.dat magic and returns structured error", async () => {
			const soPath = path.join(tmpDir, "libil2cpp.so");
			const metaPath = path.join(tmpDir, "global-metadata.dat");
			await fs.writeFile(soPath, createSyntheticElfBuffer({ machine: ELF_MACHINE_AARCH64, il2cpp: true }));
			await fs.writeFile(metaPath, createUnityMetadataBuffer(24, 0xdeadbeef)); // 错误魔数

			const tool = new RuntimeAnalyzeTool(session);
			const res = await tool.execute("call-il2cpp-corrupt", {
				action: "il2cpp",
				path: soPath,
				metadata_path: metaPath,
			});

			expect(res.details.status).toBe("error");
			expect(res.details.error).toContain("magic mismatch: expected 0xFAB11BAF");
		});

		it("reports structured missing_dependency when Il2CppDumper is absent", async () => {
			const soPath = path.join(tmpDir, "libil2cpp.so");
			const metaPath = path.join(tmpDir, "global-metadata.dat");
			await fs.writeFile(soPath, createSyntheticElfBuffer({ machine: ELF_MACHINE_AARCH64, il2cpp: true }));
			await fs.writeFile(metaPath, createUnityMetadataBuffer(24));

			const tool = new RuntimeAnalyzeTool(session, {
				which: () => null,
			});

			const res = await tool.execute("call-il2cpp-missing", {
				action: "il2cpp",
				path: soPath,
				metadata_path: metaPath,
			});

			expect(res.details.status).toBe("missing_dependency");
			expect(res.details.missingDependency?.tool).toBe("Il2CppDumper");
			expect(res.details.missingDependency?.targetDiagnostics.metadataVersion).toBe(24);
			expect(res.details.missingDependency?.targetDiagnostics.unitySupportRange).toContain("16–29");
		});

		it("fails when Il2CppDumper exits 0 but failed to produce dump outputs", async () => {
			const soPath = path.join(tmpDir, "libil2cpp.so");
			const metaPath = path.join(tmpDir, "global-metadata.dat");
			await fs.writeFile(soPath, createSyntheticElfBuffer({ machine: ELF_MACHINE_AARCH64, il2cpp: true }));
			await fs.writeFile(metaPath, createUnityMetadataBuffer(24));

			const fakeDumperDir = path.join(tmpDir, "fake_il2cppdumper");
			await fs.mkdir(fakeDumperDir, { recursive: true });
			await fs.writeFile(path.join(fakeDumperDir, "Il2CppDumper.dll"), "fake dll");

			const mockRunner: RuntimeAnalyzeRunner = async () => {
				return {
					stdout: "System.NotSupportedException: ERROR: Metadata file supplied is not a supported version",
					stderr: "",
					exitCode: 0,
					outputBytes: 80,
					truncated: false,
					timedOut: false,
				};
			};

			const tool = new RuntimeAnalyzeTool(session, {
				which: () => path.join(fakeDumperDir, "Il2CppDumper.dll"),
				runner: mockRunner,
			});

			const res = await tool.execute("call-il2cpp-zeroexit-fail", {
				action: "il2cpp",
				path: soPath,
				metadata_path: metaPath,
			});

			expect(res.details.status).toBe("error");
			expect(res.details.error).toContain("ERROR: Metadata file supplied is not a supported version");
		});
	});
	// 5. Action: Flutter (Dart AOT)
	// ========================================================================

	describe("Action: flutter", () => {
		it("strictly enforces arm64-v8a architecture and rejects 32-bit ARM", async () => {
			const arm32AppSo = createSyntheticElfBuffer({
				machine: ELF_MACHINE_ARM, // 32-bit ARM
				dartAot: true,
			});
			const appPath = path.join(tmpDir, "libapp.so");
			await fs.writeFile(appPath, arm32AppSo);

			const tool = new RuntimeAnalyzeTool(session);
			const res = await tool.execute("call-flutter-arch", {
				action: "flutter",
				path: appPath,
			});

			expect(res.details.status).toBe("unsupported");
			expect(res.details.unsupportedReason).toContain(
				"Blutter currently supports only Android libapp.so for arm64-v8a architecture",
			);
			expect(res.details.unsupportedReason).toContain("armeabi-v7a");
		});

		it("rejects generic non-Dart ELF shared object", async () => {
			const genericElf = createSyntheticElfBuffer({
				machine: ELF_MACHINE_AARCH64,
				dartAot: false,
			});
			const appPath = path.join(tmpDir, "libapp.so");
			await fs.writeFile(appPath, genericElf);

			const tool = new RuntimeAnalyzeTool(session);
			const res = await tool.execute("call-flutter-notdart", {
				action: "flutter",
				path: appPath,
			});

			expect(res.details.status).toBe("unsupported");
			expect(res.details.unsupportedReason).toContain("not a Flutter AOT application");
		});

		it("reports structured missing_dependency when Blutter is absent", async () => {
			const appSo = createSyntheticElfBuffer({
				machine: ELF_MACHINE_AARCH64,
				dartAot: true,
				snapshotHash: "1234567890abcdef1234567890abcdef",
				dartVersion: "3.2.0",
			});
			const appPath = path.join(tmpDir, "libapp.so");
			await fs.writeFile(appPath, appSo);

			const tool = new RuntimeAnalyzeTool(session, {
				which: () => null,
			});

			const res = await tool.execute("call-flutter-missing", {
				action: "flutter",
				path: appPath,
			});

			expect(res.details.status).toBe("missing_dependency");
			expect(res.details.missingDependency?.targetDiagnostics.architecture).toBe("arm64-v8a");
			expect(res.details.missingDependency?.targetDiagnostics.snapshotHash).toBe("1234567890abcdef1234567890abcdef");
		});

		it("requires explicit backend build when matching prebuilt Dart VM is absent (no silent clone/build)", async () => {
			const appSo = createSyntheticElfBuffer({
				machine: ELF_MACHINE_AARCH64,
				dartAot: true,
				snapshotHash: "1234567890abcdef1234567890abcdef",
			});
			const appPath = path.join(tmpDir, "libapp.so");
			await fs.writeFile(appPath, appSo);
			const flutterSo = createSyntheticElfBuffer({
				machine: ELF_MACHINE_AARCH64,
				flutterEngine: true,
				dartVersion: "3.2.0",
			});
			await fs.writeFile(path.join(tmpDir, "libflutter.so"), flutterSo);

			// 模拟 blutter 脚本存在，但其 bin 目录为空 (没有匹配的预编译 Dart VM)
			const fakeBlutterDir = path.join(tmpDir, "fake_blutter");
			await fs.mkdir(path.join(fakeBlutterDir, "bin"), { recursive: true });
			const fakeBlutterScript = path.join(fakeBlutterDir, "blutter.py");
			await fs.writeFile(fakeBlutterScript, "#!/usr/bin/env python3\n");

			const tool = new RuntimeAnalyzeTool(session, {
				which: () => fakeBlutterScript,
			});

			const res = await tool.execute("call-flutter-build-req", {
				action: "flutter",
				path: appPath,
			});

			expect(res.details.status).toBe("backend_build_required");
			expect(res.details.unsupportedReason).toContain(
				"Automated analysis does not silently checkout or compile external Dart SDK sources",
			);
		});

		it("rejects output_dir overlapping with target input path", async () => {
			const appSo = createSyntheticElfBuffer({
				machine: ELF_MACHINE_AARCH64,
				dartAot: true,
				snapshotHash: "1234567890abcdef1234567890abcdef",
				dartVersion: "3.2.0",
			});
			const appPath = path.join(tmpDir, "libapp.so");
			await fs.writeFile(appPath, appSo);

			const tool = new RuntimeAnalyzeTool(session);
			expect(
				tool.execute("call-overlap", {
					action: "flutter",
					path: appPath,
					output_dir: tmpDir,
				}),
			).rejects.toThrow("overlaps with target input path");
		});
	});
});
