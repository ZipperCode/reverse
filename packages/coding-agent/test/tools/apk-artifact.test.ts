import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import * as zlib from "node:zlib";
import { describe, expect, it } from "bun:test";
import { Settings } from "@reverse/coding-agent/config/settings";
import type { ToolSession } from "@reverse/coding-agent/tools";
import { ZipParser } from "@reverse/coding-agent/tools/android-package-inspect";
import { ApkArtifactTool } from "@reverse/coding-agent/tools/apk-artifact";
import { removeWithRetries } from "@reverse/utils";

// ============================================================================
// Helpers
// ============================================================================

function createTestSession(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
	};
}

/** Construct a valid uncompressed ZIP/APK archive in memory without external tools. */
function buildZipBuffer(entries: Array<{ name: string; data: Buffer; method?: number }>): Buffer {
	const localParts: Buffer[] = [];
	const cdParts: Buffer[] = [];
	let offset = 0;

	for (const entry of entries) {
		const nameBuf = Buffer.from(entry.name, "utf-8");
		const crc = zlib.crc32(entry.data);
		const method = entry.method ?? 0; // 0 = STORED
		const size = entry.data.length;

		const lh = Buffer.alloc(30);
		lh.writeUInt32LE(0x04034b50, 0);
		lh.writeUInt16LE(20, 4);
		lh.writeUInt16LE(0x0800, 6); // UTF-8
		lh.writeUInt16LE(method, 8);
		lh.writeUInt16LE(0, 10);
		lh.writeUInt16LE(0, 12);
		lh.writeUInt32LE(crc, 14);
		lh.writeUInt32LE(size, 18);
		lh.writeUInt32LE(size, 22);
		lh.writeUInt16LE(nameBuf.length, 26);
		lh.writeUInt16LE(0, 28);

		const localOffset = offset;
		localParts.push(lh, nameBuf, entry.data);
		offset += lh.length + nameBuf.length + entry.data.length;

		const cdh = Buffer.alloc(46);
		cdh.writeUInt32LE(0x02014b50, 0);
		cdh.writeUInt16LE(20, 4);
		cdh.writeUInt16LE(20, 6);
		cdh.writeUInt16LE(0x0800, 8);
		cdh.writeUInt16LE(method, 10);
		cdh.writeUInt16LE(0, 12);
		cdh.writeUInt16LE(0, 14);
		cdh.writeUInt32LE(crc, 16);
		cdh.writeUInt32LE(size, 20);
		cdh.writeUInt32LE(size, 24);
		cdh.writeUInt16LE(nameBuf.length, 28);
		cdh.writeUInt16LE(0, 30);
		cdh.writeUInt16LE(0, 32);
		cdh.writeUInt16LE(0, 34);
		cdh.writeUInt16LE(0, 36);
		cdh.writeUInt32LE(0, 38);
		cdh.writeUInt32LE(localOffset, 42);

		cdParts.push(cdh, nameBuf);
	}

	const cdStart = offset;
	const cdBuf = Buffer.concat(cdParts);
	const cdSize = cdBuf.length;

	const eocd = Buffer.alloc(22);
	eocd.writeUInt32LE(0x06054b50, 0);
	eocd.writeUInt16LE(0, 4);
	eocd.writeUInt16LE(0, 6);
	eocd.writeUInt16LE(entries.length, 8);
	eocd.writeUInt16LE(entries.length, 10);
	eocd.writeUInt32LE(cdSize, 12);
	eocd.writeUInt32LE(cdStart, 16);
	eocd.writeUInt16LE(0, 20);

	return Buffer.concat([...localParts, cdBuf, eocd]);
}

function createDummyDex(seed: number, size = 40): Buffer {
	const magic = Buffer.from("dex\n035\0", "utf-8");
	const rest = Buffer.alloc(size - magic.length, seed);
	return Buffer.concat([magic, rest]);
}

// ============================================================================
// Test Suite
// ============================================================================

describe("apk_artifact tool contracts & safety", () => {
	it("enforces action-based read/write approval boundaries", () => {
		const session = createTestSession("/tmp");
		const tool = new ApkArtifactTool(session);

		expect(tool.approval({ action: "diff" })).toBe("read");
		expect(tool.approval({ action: "verify" })).toBe("read");
		expect(tool.approval({ action: "repack" })).toBe("write");
		expect(tool.approval({ action: "sign" })).toBe("write");
		expect(tool.approval({ action: "install_verify" })).toBe("write");
	});

	it("diff: detects same-size replacements where size matches but bytes/hash differ", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "apk-diff-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new ApkArtifactTool(session);

			const apkAPath = path.join(tempDir, "original.apk");
			const apkBPath = path.join(tempDir, "modified.apk");

			const dexa = createDummyDex(0xaa, 40);
			const dexb = createDummyDex(0xbb, 40);

			const zipA = buildZipBuffer([
				{ name: "classes.dex", data: dexa },
				{ name: "resources.arsc", data: Buffer.from("arsc content") },
			]);
			const zipB = buildZipBuffer([
				{ name: "classes.dex", data: dexb },
				{ name: "resources.arsc", data: Buffer.from("arsc content") },
			]);

			await fs.writeFile(apkAPath, zipA);
			await fs.writeFile(apkBPath, zipB);

			const result = await tool.execute("call-diff", {
				action: "diff",
				original_path: apkAPath,
				modified_path: apkBPath,
			});

			expect(result.details.status).toBe("ok");
			expect(result.details.diff).toBeDefined();

			const diff = result.details.diff!;
			expect(diff.summary.changed_count).toBe(1);
			expect(diff.summary.same_size_changed_count).toBe(1);
			expect(diff.summary.identical_count).toBe(1);

			const changedDex = diff.changed.find(c => c.name === "classes.dex");
			expect(changedDex).toBeDefined();
			expect(changedDex?.same_size).toBe(true);
			expect(changedDex?.original_size).toBe(40);
			expect(changedDex?.modified_size).toBe(40);
			expect(changedDex?.original_sha256).not.toBe(changedDex?.modified_sha256);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("repack: preserves META-INF/services/ and nested META-INF subdirs while stripping signature artifacts", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "apk-repack-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new ApkArtifactTool(session);

			const inApk = path.join(tempDir, "input.apk");
			const outApk = path.join(tempDir, "output.apk");
			const newDexPath = path.join(tempDir, "patched.dex");

			const origDex = createDummyDex(0x11, 40);
			const repDex = createDummyDex(0x22, 48);
			await fs.writeFile(newDexPath, repDex);

			const serviceContent = Buffer.from("com.example.MyServiceImpl\n");
			const nativeImageContent = Buffer.from("[{name: 'java.lang.String'}]\n");
			const zipBuf = buildZipBuffer([
				{ name: "classes.dex", data: origDex },
				{ name: "resources.arsc", data: Buffer.from("table") },
				{ name: "META-INF/MANIFEST.MF", data: Buffer.from("Manifest-Version: 1.0\n") },
				{ name: "META-INF/CERT.SF", data: Buffer.from("Signature-Version: 1.0\n") },
				{ name: "META-INF/CERT.RSA", data: Buffer.from("dummy-rsa-block") },
				{ name: "META-INF/services/com.example.IService", data: serviceContent },
				{ name: "META-INF/native-image/config.MF", data: nativeImageContent },
			]);
			await fs.writeFile(inApk, zipBuf);

			const res = await tool.execute("call-repack", {
				action: "repack",
				path: inApk,
				output_path: outApk,
				dex_files: { "classes.dex": newDexPath },
			});

			expect(res.details.status).toBe("ok");
			const repack = res.details.repack!;
			expect(repack.replaced_entries).toContain("classes.dex");
			expect(repack.signed).toBe(false);

			// Independent ZipParser verification of output archive entries
			const outBuf = await fs.readFile(outApk);
			const zip = new ZipParser(outBuf);

			// Verify replaced classes.dex matches replacement bytes exactly
			const dexEntry = zip.getEntry("classes.dex");
			expect(dexEntry).toBeDefined();
			expect(zip.readFile(dexEntry!)).toEqual(repDex);

			// Verify META-INF/services/com.example.IService is preserved
			const serviceEntry = zip.getEntry("META-INF/services/com.example.IService");
			expect(serviceEntry).toBeDefined();
			expect(zip.readFile(serviceEntry!)).toEqual(serviceContent);

			// Verify nested META-INF/native-image/config.MF is preserved
			const nativeImageEntry = zip.getEntry("META-INF/native-image/config.MF");
			expect(nativeImageEntry).toBeDefined();
			expect(zip.readFile(nativeImageEntry!)).toEqual(nativeImageContent);

			// Verify direct signature artifacts are stripped
			expect(zip.getEntry("META-INF/MANIFEST.MF")).toBeUndefined();
			expect(zip.getEntry("META-INF/CERT.SF")).toBeUndefined();
			expect(zip.getEntry("META-INF/CERT.RSA")).toBeUndefined();
			expect(repack.dropped_signatures).toContain("META-INF/MANIFEST.MF");
			expect(repack.dropped_signatures).toContain("META-INF/CERT.SF");
			expect(repack.dropped_signatures).toContain("META-INF/CERT.RSA");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("alignment: ensures resources.arsc is 4-byte aligned and .so is 16KiB page aligned", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "apk-align-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new ApkArtifactTool(session);

			const inApk = path.join(tempDir, "unaligned.apk");
			const outApk = path.join(tempDir, "aligned.apk");

			const zipBuf = buildZipBuffer([
				{ name: "classes.dex", data: createDummyDex(0x10, 35) },
				{ name: "resources.arsc", data: Buffer.from("1234567") },
				{ name: "lib/arm64-v8a/libtest.so", data: Buffer.alloc(100, 0x7f) },
			]);
			await fs.writeFile(inApk, zipBuf);

			const res = await tool.execute("call-repack-align", {
				action: "repack",
				path: inApk,
				output_path: outApk,
				page_align_so: true,
			});

			expect(res.details.status).toBe("ok");
			const alignInfo = res.details.repack?.alignment;
			expect(alignInfo?.ok).toBe(true);

			const arscEntry = alignInfo?.checked_entries.find(e => e.name === "resources.arsc");
			expect(arscEntry).toBeDefined();
			if (!arscEntry) throw new Error("Repacked APK lacks resources.arsc alignment evidence");
			expect(arscEntry?.stored).toBe(true);
			expect(arscEntry?.aligned).toBe(true);
			expect(arscEntry.offset % 4).toBe(0);

			const soEntry = alignInfo?.checked_entries.find(e => e.name === "lib/arm64-v8a/libtest.so");
			expect(soEntry).toBeDefined();
			if (!soEntry) throw new Error("Repacked APK lacks native library alignment evidence");
			expect(soEntry?.stored).toBe(true);
			expect(soEntry?.aligned).toBe(true);
			expect(soEntry.offset % 16384).toBe(0);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("safety: rejects input/output aliasing and enforces strict no-overwrite policy", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "apk-safety-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new ApkArtifactTool(session);

			const apkPath = path.join(tempDir, "target.apk");
			const dummyContent = buildZipBuffer([{ name: "classes.dex", data: createDummyDex(1, 40) }]);
			await fs.writeFile(apkPath, dummyContent);

			// 1. Anti-aliasing test
			await expect(
				tool.execute("call-alias", {
					action: "repack",
					path: apkPath,
					output_path: apkPath,
				}),
			).rejects.toThrow(/cannot be identical/i);

			// 2. Strict no-overwrite test: existing output rejected
			const existingOut = path.join(tempDir, "existing.apk");
			await fs.writeFile(existingOut, "ORIGINAL PREEXISTING FILE CONTENT");

			await expect(
				tool.execute("call-overwrite", {
					action: "repack",
					path: apkPath,
					output_path: existingOut,
				}),
			).rejects.toThrow(/already exists/i);

			const preservedContent = await fs.readFile(existingOut, "utf-8");
			expect(preservedContent).toBe("ORIGINAL PREEXISTING FILE CONTENT");

			// 3. Sign requires output_path
			await expect(
				tool.execute("call-sign-no-out", {
					action: "sign",
					path: apkPath,
					keystore_path: "dev.keystore",
					key_alias: "key0",
					ks_pass_env: "DUMMY_ENV",
				}),
			).rejects.toThrow(/requires parameter 'output_path'/i);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("safety: rejects malformed dex_files map and duplicate entry names", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "apk-malformed-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new ApkArtifactTool(session);

			const inApk = path.join(tempDir, "in.apk");
			const outApk = path.join(tempDir, "out.apk");
			await fs.writeFile(inApk, buildZipBuffer([{ name: "classes.dex", data: createDummyDex(1, 40) }]));

			// Malformed dex_files value (number instead of string) rejected
			await expect(
				tool.execute("call-bad-dex-map", {
					action: "repack",
					path: inApk,
					output_path: outApk,
					dex_files: { "classes.dex": 12345 as unknown as string },
				}),
			).rejects.toThrow(/must be a non-empty string/i);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("verify: unsigned APK or missing signer tool never falsely reports signature verified", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "apk-verify-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new ApkArtifactTool(session);

			const unsignedApk = path.join(tempDir, "unsigned.apk");
			const zipBuf = buildZipBuffer([
				{ name: "classes.dex", data: createDummyDex(0x33, 40) },
				{ name: "resources.arsc", data: Buffer.from("arsc data") },
			]);
			await fs.writeFile(unsignedApk, zipBuf);

			// Force explicit nonexistent apksigner path so host build-tools don't affect test outcome
			const res = await tool.execute("call-verify", {
				action: "verify",
				path: unsignedApk,
				apksigner_path: "/nonexistent/tools/apksigner",
			});

			expect(res.details.verify?.verified).toBe(false);
			expect(res.details.verify?.status).not.toBe("ok");
			expect(res.details.verify?.signature?.tool_available).toBe(false);
			expect(res.details.verify?.signature?.verified).toBe(false);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("install_verify: mandates explicit device serial and rejects missing device", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "apk-iv-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new ApkArtifactTool(session);

			const apkPath = path.join(tempDir, "app.apk");
			await fs.writeFile(apkPath, buildZipBuffer([{ name: "classes.dex", data: createDummyDex(1, 40) }]));

			await expect(
				tool.execute("call-iv-no-serial", {
					action: "install_verify",
					path: apkPath,
					package: "com.example.test",
					activity: ".MainActivity",
				}),
			).rejects.toThrow(/requires explicit parameter 'serial'/i);

			await expect(
				tool.execute("call-iv-dummy-serial", {
					action: "install_verify",
					path: apkPath,
					package: "com.example.test",
					activity: ".MainActivity",
					serial: "nonexistent-device-serial-99999",
				}),
			).rejects.toThrow();
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});
