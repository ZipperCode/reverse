/**
 * Unit & Behavioral Tests for DexKit Backend Installer.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import {
	FLATBUFFERS_VERSION,
	KOTLIN_STDLIB_VERSION,
	isSupportedHostPlatform,
	getDexKitNativeLibName,
	verifyJniSymbols,
	resolveDexKitInstallation,
	buildDeterministicDexFixture,
	installDexKit,
} from "../src/extensibility/dexkit-install";
import type { SkillToolPlatform } from "../src/extensibility/skill-tool-catalog";
describe("DexKit Installer - Pinned Constants & Platform Predicates", () => {
	it("resolves correct native library filenames by operating system", () => {
		expect(getDexKitNativeLibName("darwin")).toBe("libdexkit.dylib");
		expect(getDexKitNativeLibName("linux")).toBe("libdexkit.so");
		expect(getDexKitNativeLibName("win32")).toBe("dexkit.dll");
	});

	it("validates supported host architectures truthfully without false positives", () => {
		expect(isSupportedHostPlatform("darwin", "arm64")).toBe(true);
		expect(isSupportedHostPlatform("darwin", "x64")).toBe(true);
		expect(isSupportedHostPlatform("linux", "x64")).toBe(true);
		expect(isSupportedHostPlatform("linux", "arm64")).toBe(true);
		expect(isSupportedHostPlatform("win32", "x64")).toBe(true);
		expect(isSupportedHostPlatform("aix" as NodeJS.Platform, "ppc")).toBe(false);
		expect(isSupportedHostPlatform("darwin", "s390x")).toBe(false);
	});
});

describe("DexKit Installer - Synthetic Dalvik Fixture Generator", () => {
	it("generates a valid DEX binary with magic header, class defs, and Dalvik structure", () => {
		const buf = buildDeterministicDexFixture();
		expect(buf).toBeInstanceOf(Buffer);
		expect(buf.length).toBeGreaterThan(0x70);

		// Check Dalvik DEX magic: "dex\n035\0"
		const magic = buf.subarray(0, 8).toString("ascii");
		expect(magic).toBe("dex\n035\0");

		// Header checks
		const endianTag = buf.readUInt32LE(0x28);
		expect(endianTag).toBe(0x12345678);

		const classDefsSize = buf.readUInt32LE(0x60);
		expect(classDefsSize).toBe(1);

		const methodIdsSize = buf.readUInt32LE(0x58);
		expect(methodIdsSize).toBe(2);

		// Check string constants contain test gate
		const raw = buf.toString("utf8");
		expect(raw).toContain("Lcom/example/TestGate;");
		expect(raw).toContain("isLicensed");
		expect(raw).toContain("compute");
	});
});

describe("DexKit Installer - Resolution & Missing Dependencies Inspection", () => {
	let tempAgentDir: string;

	beforeEach(async () => {
		tempAgentDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "dexkit-test-agent-"));
	});

	afterEach(async () => {
		await fs.promises.rm(tempAgentDir, { recursive: true, force: true });
	});

	it("reports uninstalled status and complete missing components for an empty agent directory", () => {
		const res = resolveDexKitInstallation({ agentDir: tempAgentDir, platform: "darwin" });
		expect(res.installed).toBe(false);
		expect(res.canStart).toBe(false);
		expect(res.missingComponents).toContain("libdexkit.dylib");
		expect(res.missingComponents).toContain("dexkit-bridge.jar");
		expect(res.missingComponents).toContain("dexkit.jar");
		expect(res.missingComponents).toContain(`flatbuffers-java-${FLATBUFFERS_VERSION}.jar`);
		expect(res.missingComponents).toContain(`kotlin-stdlib-${KOTLIN_STDLIB_VERSION}.jar`);
	});

	it("correctly identifies fully provisioned installation", async () => {
		const installDir = path.join(tempAgentDir, "tools", "dexkit");
		const binDir = path.join(installDir, "bin");
		await fs.promises.mkdir(binDir, { recursive: true });

		// Stage valid-sized dummy files
		const largeBuf = Buffer.alloc(120_000, 0x90);
		await fs.promises.writeFile(path.join(installDir, "libdexkit.dylib"), largeBuf);
		await fs.promises.writeFile(path.join(installDir, "dexkit-bridge.jar"), Buffer.alloc(2048));
		await fs.promises.writeFile(path.join(installDir, "dexkit.jar"), Buffer.alloc(2048));
		await fs.promises.writeFile(
			path.join(installDir, `flatbuffers-java-${FLATBUFFERS_VERSION}.jar`),
			Buffer.alloc(2048),
		);
		await fs.promises.writeFile(
			path.join(installDir, `kotlin-stdlib-${KOTLIN_STDLIB_VERSION}.jar`),
			Buffer.alloc(2048),
		);
		await fs.promises.writeFile(path.join(binDir, "dexkit"), "#!/bin/sh\n", { mode: 0o755 });

		const res = resolveDexKitInstallation({ agentDir: tempAgentDir, platform: "darwin" });
		expect(res.installed).toBe(true);
		expect(res.canStart).toBe(true);
		expect(res.missingComponents).toEqual([]);
		expect(res.libPath).toBe(path.join(installDir, "libdexkit.dylib"));
		expect(res.bridgeJar).toBe(path.join(installDir, "dexkit-bridge.jar"));
		expect(res.dexkitJar).toBe(path.join(installDir, "dexkit.jar"));
	});
});

describe("DexKit Installer - Rollback & Isolated Staging", () => {
	it("rolls back cleanly on unsupported platform without leaving partial files", async () => {
		const tempAgentDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "dexkit-fail-test-"));
		try {
			const res = await installDexKit({
				agentDir: tempAgentDir,
				platform: "aix" as unknown as SkillToolPlatform,
			});
			expect(res.success).toBe(false);
			expect(res.error).toContain("is not supported");

			// Ensure tools/dexkit was NOT created
			const targetDir = path.join(tempAgentDir, "tools", "dexkit");
			expect(fs.existsSync(targetDir)).toBe(false);
		} finally {
			await fs.promises.rm(tempAgentDir, { recursive: true, force: true });
		}
	});

	it("rolls back cleanly if Java/JDK is missing from whichFn", async () => {
		const tempAgentDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "dexkit-nojava-test-"));
		try {
			const res = await installDexKit({
				agentDir: tempAgentDir,
				which: () => null, // Simulate no java / javac / jar in PATH
			});
			expect(res.success).toBe(false);
			expect(res.error).toContain("JDK 11+ is required");

			const targetDir = path.join(tempAgentDir, "tools", "dexkit");
			expect(fs.existsSync(targetDir)).toBe(false);
		} finally {
			await fs.promises.rm(tempAgentDir, { recursive: true, force: true });
		}
	});

	it("rolls back cleanly if aborted by signal before completion", async () => {
		const tempAgentDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "dexkit-abort-test-"));
		const controller = new AbortController();
		controller.abort(new Error("Pre-aborted test signal"));
		try {
			const res = await installDexKit({
				agentDir: tempAgentDir,
				signal: controller.signal,
			});
			expect(res.success).toBe(false);
			const targetDir = path.join(tempAgentDir, "tools", "dexkit");
			expect(fs.existsSync(targetDir)).toBe(false);
		} finally {
			await fs.promises.rm(tempAgentDir, { recursive: true, force: true });
		}
	});
});

/**
 * 本地测试辅助：生成用于 JNI 导出校验回归测试的确定性合成 PE 二进制。
 */
function buildDeterministicPeFixture(options?: {
	is64?: boolean;
	exportedSymbols?: string[];
	arbitraryText?: string;
	minSize?: number;
}): Buffer {
	const is64 = options?.is64 ?? true;
	const exportedSymbols = options?.exportedSymbols ?? [];
	const arbitraryText = options?.arbitraryText ?? "";
	const minSize = options?.minSize ?? 100_000;

	const totalSize = Math.max(1024, minSize);
	const buf = Buffer.alloc(totalSize);

	// DOS Header: "MZ" + e_lfanew
	buf.write("MZ", 0, "ascii");
	const peOffset = 0x80;
	buf.writeUInt32LE(peOffset, 0x3c);

	// PE Signature: "PE\0\0"
	buf.write("PE\0\0", peOffset, "ascii");

	// COFF File Header
	const machine = is64 ? 0x8664 : 0x014c;
	buf.writeUInt16LE(machine, peOffset + 4);
	const numSections = 1;
	buf.writeUInt16LE(numSections, peOffset + 6);
	const optHeaderSize = is64 ? 240 : 224;
	buf.writeUInt16LE(optHeaderSize, peOffset + 20);
	buf.writeUInt16LE(0x2022, peOffset + 22);

	// Optional Header
	const optOffset = peOffset + 24;
	const optMagic = is64 ? 0x20b : 0x10b;
	buf.writeUInt16LE(optMagic, optOffset);

	const exportDirEntryOffset = optOffset + (is64 ? 112 : 96);

	// Section 1 (.rdata)
	const sectionOffset = optOffset + optHeaderSize;
	buf.write(".rdata\0\0", sectionOffset, "ascii");
	buf.writeUInt32LE(0x2000, sectionOffset + 8);
	buf.writeUInt32LE(0x1000, sectionOffset + 12);
	buf.writeUInt32LE(totalSize - 0x200, sectionOffset + 16);
	buf.writeUInt32LE(0x200, sectionOffset + 20);
	buf.writeUInt32LE(0x40000040, sectionOffset + 36);

	if (arbitraryText) {
		buf.write(arbitraryText, 0x200, "utf8");
	}

	if (exportedSymbols.length > 0) {
		const exportRva = 0x1040;
		const exportFileOffset = 0x240;
		const exportSize = 0x200;
		buf.writeUInt32LE(exportRva, exportDirEntryOffset);
		buf.writeUInt32LE(exportSize, exportDirEntryOffset + 4);

		buf.writeUInt32LE(exportedSymbols.length, exportFileOffset + 24);
		const namesRva = 0x1070;
		const namesFileOffset = 0x270;
		buf.writeUInt32LE(namesRva, exportFileOffset + 32);

		let strFileOffset = 0x2e0;
		let strRva = 0x10e0;

		for (let i = 0; i < exportedSymbols.length; i++) {
			const sym = exportedSymbols[i]!;
			buf.writeUInt32LE(strRva, namesFileOffset + i * 4);
			buf.write(sym + "\0", strFileOffset, "utf8");
			const len = Buffer.byteLength(sym, "utf8") + 1;
			strFileOffset += len;
			strRva += len;
		}
	}

	return buf;
}

describe("DexKit Installer - Structured PE Export & JNI Symbol Verification", () => {
	it("结构化校验有效 PE32+ (x64) 真实 JNI 导出符号", async () => {
		const fixture = buildDeterministicPeFixture({
			is64: true,
			exportedSymbols: ["Java_org_luckypray_dexkit_DexKitBridge_nativeInitDexKit"],
			minSize: 120_000,
		});
		const tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "pe-verify-"));
		const dllPath = path.join(tempDir, "dexkit.dll");
		try {
			await fs.promises.writeFile(dllPath, fixture);
			expect(verifyJniSymbols(dllPath, "win32")).toBe(true);
		} finally {
			await fs.promises.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("结构化校验有效 PE32 (x86) 真实 JNI 导出符号", async () => {
		const fixture = buildDeterministicPeFixture({
			is64: false,
			exportedSymbols: ["Java_org_luckypray_dexkit_DexKitBridge_createDexKit"],
			minSize: 120_000,
		});
		const tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "pe-verify32-"));
		const dllPath = path.join(tempDir, "dexkit.dll");
		try {
			await fs.promises.writeFile(dllPath, fixture);
			expect(verifyJniSymbols(dllPath, "win32")).toBe(true);
		} finally {
			await fs.promises.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("边界回归：仅在节数据中包含伪符号文本但无导出表的 PE 文件不通过校验", async () => {
		const fixture = buildDeterministicPeFixture({
			arbitraryText: "Java_org_luckypray_dexkit_DexKitBridge_nativeInitDexKit in raw text",
			exportedSymbols: [],
			minSize: 120_000,
		});
		const tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "pe-fake-"));
		const dllPath = path.join(tempDir, "dexkit.dll");
		try {
			await fs.promises.writeFile(dllPath, fixture);
			expect(verifyJniSymbols(dllPath, "win32")).toBe(false);
		} finally {
			await fs.promises.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("边界回归：损坏或非 PE 格式文件不通过校验", async () => {
		const tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "pe-invalid-"));
		const dllPath = path.join(tempDir, "dexkit.dll");
		try {
			await fs.promises.writeFile(dllPath, Buffer.alloc(120_000, 0x41));
			expect(verifyJniSymbols(dllPath, "win32")).toBe(false);
		} finally {
			await fs.promises.rm(tempDir, { recursive: true, force: true });
		}
	});
});
