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
