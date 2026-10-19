import type { AgentToolResult } from "@reverse/agent";
import { describe, expect, it } from "bun:test";
import * as os from "node:os";
import * as path from "node:path";
import * as fs from "node:fs/promises";
import { Settings } from "@reverse/coding-agent/config/settings";
import { createTools, FirmwareInspectTool, type ToolSession } from "@reverse/coding-agent/tools";
import { BUILTIN_TOOL_NAMES, normalizeToolName } from "@reverse/coding-agent/tools/builtin-names";
import { removeWithRetries } from "@reverse/utils";

function createTestSession(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
	};
}

function textOf(result: AgentToolResult<unknown>): string {
	return result.content
		.flatMap(item => (item.type === "text" ? [item.text] : []))
		.join("\n")
		.trim();
}

// ============================================================================
// Fixture Generators
// ============================================================================

/** Build a synthetic U-Boot legacy uImage header (64 bytes) + payload */
function createSyntheticUImage(
	options: {
		imageName?: string;
		osId?: number;
		archId?: number;
		typeId?: number;
		compId?: number;
		loadAddr?: number;
		entryPoint?: number;
		payloadSize?: number;
	} = {},
): Buffer {
	const name = options.imageName ?? "Linux-5.10-arm";
	const osId = options.osId ?? 5; // Linux
	const archId = options.archId ?? 2; // ARM
	const typeId = options.typeId ?? 2; // Kernel
	const compId = options.compId ?? 1; // gzip
	const loadAddr = options.loadAddr ?? 0x80008000;
	const entryPoint = options.entryPoint ?? 0x80008000;
	const payloadSize = options.payloadSize ?? 128;

	const buf = Buffer.alloc(64 + payloadSize, 0xaa);
	// 0x00: Magic 0x27051956 (big endian)
	buf.writeUInt32BE(0x27051956, 0);
	// 0x04: Header CRC
	buf.writeUInt32BE(0x12345678, 4);
	// 0x08: Timestamp (2023-01-01 00:00:00 UTC = 1672531199)
	buf.writeUInt32BE(1672531199, 8);
	// 0x0c: Data size
	buf.writeUInt32BE(payloadSize, 12);
	// 0x10: Load address
	buf.writeUInt32BE(loadAddr, 16);
	// 0x14: Entry point
	buf.writeUInt32BE(entryPoint, 20);
	// 0x18: Data CRC
	buf.writeUInt32BE(0x87654321, 24);
	// 0x1c: OS
	buf[28] = osId;
	// 0x1d: Arch
	buf[29] = archId;
	// 0x1e: Type
	buf[30] = typeId;
	// 0x1f: Comp
	buf[31] = compId;
	// 0x20..0x3f: Name (32 bytes null-terminated ASCII)
	buf.write(name, 32, 32, "ascii");

	return buf;
}

/** Build a synthetic SquashFS v4.0 superblock (96 bytes) + padding */
function createSyntheticSquashfs(
	options: {
		inodes?: number;
		blockSize?: number;
		compId?: number;
		bytesUsed?: number;
		isBigEndian?: boolean;
	} = {},
): Buffer {
	const inodes = options.inodes ?? 150;
	const blockSize = options.blockSize ?? 131072; // 128 KiB
	const compId = options.compId ?? 1; // gzip
	const bytesUsed = options.bytesUsed ?? 65536;
	const isBE = options.isBigEndian ?? false;

	const buf = Buffer.alloc(1024, 0);

	if (isBE) {
		buf.writeUInt32BE(0x68737173, 0); // "hsqs"
		buf.writeUInt32BE(inodes, 4);
		buf.writeUInt32BE(1672531200, 8); // mkfs_time
		buf.writeUInt32BE(blockSize, 12);
		buf.writeUInt32BE(10, 16); // fragments
		buf.writeUInt16BE(compId, 20); // compression
		buf.writeUInt16BE(17, 22); // block_log (2^17 = 131072)
		buf.writeUInt16BE(0, 24); // flags
		buf.writeUInt16BE(1, 26); // no_ids
		buf.writeUInt16BE(4, 28); // s_major
		buf.writeUInt16BE(0, 30); // s_minor
		buf.writeUInt32BE(0, 40); // bytes_used hi
		buf.writeUInt32BE(bytesUsed, 44); // bytes_used lo
	} else {
		buf.writeUInt32LE(0x73717368, 0); // "sqsh"
		buf.writeUInt32LE(inodes, 4);
		buf.writeUInt32LE(1672531200, 8); // mkfs_time
		buf.writeUInt32LE(blockSize, 12);
		buf.writeUInt32LE(10, 16); // fragments
		buf.writeUInt16LE(compId, 20); // compression
		buf.writeUInt16LE(17, 22); // block_log
		buf.writeUInt16LE(0, 24); // flags
		buf.writeUInt16LE(1, 26); // no_ids
		buf.writeUInt16LE(4, 28); // s_major
		buf.writeUInt16LE(0, 30); // s_minor
		buf.writeUInt32LE(bytesUsed, 40); // bytes_used lo
		buf.writeUInt32LE(0, 44); // bytes_used hi
	}

	return buf;
}

/** Build a synthetic CPIO archive with files and trailer */
function createSyntheticCpio(files: Array<{ name: string; content: string; mode?: number }>): Buffer {
	const chunks: Buffer[] = [];

	for (const f of files) {
		const mode = f.mode ?? 0o100644; // regular file
		const contentBuf = Buffer.from(f.content, "utf8");
		const nameBuf = Buffer.from(f.name + "\0", "utf8");

		const header = Buffer.alloc(110);
		header.write("070701", 0, "ascii"); // Magic
		header.write("00000001", 6, "ascii"); // ino
		header.write(mode.toString(16).padStart(8, "0"), 14, "ascii"); // mode
		header.write("00000000", 22, "ascii"); // uid
		header.write("00000000", 30, "ascii"); // gid
		header.write("00000001", 38, "ascii"); // nlink
		header.write("63B10000", 46, "ascii"); // mtime
		header.write(contentBuf.length.toString(16).padStart(8, "0"), 54, "ascii"); // filesize
		header.write("00000000", 62, "ascii"); // maj
		header.write("00000000", 70, "ascii"); // min
		header.write("00000000", 78, "ascii"); // rmaj
		header.write("00000000", 86, "ascii"); // rmin
		header.write(nameBuf.length.toString(16).padStart(8, "0"), 94, "ascii"); // namesize
		header.write("00000000", 102, "ascii"); // check

		chunks.push(header);
		chunks.push(nameBuf);

		// Pad header + name to 4 bytes
		const hnLen = 110 + nameBuf.length;
		const hnPad = ((hnLen + 3) & ~3) - hnLen;
		if (hnPad > 0) chunks.push(Buffer.alloc(hnPad, 0));

		// File content
		chunks.push(contentBuf);
		// Pad file to 4 bytes
		const fPad = ((contentBuf.length + 3) & ~3) - contentBuf.length;
		if (fPad > 0) chunks.push(Buffer.alloc(fPad, 0));
	}

	// TRAILER!!!
	const trailerName = Buffer.from("TRAILER!!!\0", "utf8");
	const trailerHdr = Buffer.alloc(110);
	trailerHdr.write("070701", 0, "ascii");
	trailerHdr.write("00000000", 54, "ascii"); // filesize = 0
	trailerHdr.write(trailerName.length.toString(16).padStart(8, "0"), 94, "ascii"); // namesize
	chunks.push(trailerHdr);
	chunks.push(trailerName);
	const trLen = 110 + trailerName.length;
	const trPad = ((trLen + 3) & ~3) - trLen;
	if (trPad > 0) chunks.push(Buffer.alloc(trPad, 0));

	return Buffer.concat(chunks);
}

// ============================================================================
// Tests
// ============================================================================

describe("firmware_inspect registration and discovery", () => {
	it("registers in BUILTIN_TOOL_NAMES and normalizes aliases", () => {
		expect(BUILTIN_TOOL_NAMES).toContain("firmware_inspect");
		expect(normalizeToolName("firmware_inspect")).toBe("firmware_inspect");
		expect(normalizeToolName("firmware")).toBe("firmware_inspect");
		expect(normalizeToolName("firmware_analyze")).toBe("firmware_inspect");
		expect(normalizeToolName("binwalk")).toBe("firmware_inspect");
		expect(normalizeToolName("rom_inspect")).toBe("firmware_inspect");
	});

	it("creates tool instance with discoverable loadMode and read approval", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "fw-test-"));
		try {
			const session = createTestSession(tempDir);
			const tools = await createTools(session, ["firmware_inspect"]);
			const tool = tools.find(t => t.name === "firmware_inspect") as FirmwareInspectTool | undefined;
			expect(tool).toBeDefined();
			expect(tool?.name).toBe("firmware_inspect");
			expect(tool?.approval).toBe("read");
			expect(tool?.loadMode).toBe("discoverable");
			expect(tool?.label).toBe("Firmware Image / ROM Inspect");
			expect(tool?.description).toContain("Native offline read-only firmware image");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("firmware_inspect path validation and error handling", () => {
	it("rejects non-existent file with descriptive error", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "fw-err-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new FirmwareInspectTool(session);
			await expect(
				tool.execute("call-1", {
					action: "info",
					path: path.join(tempDir, "missing.bin"),
				}),
			).rejects.toThrow("Firmware file not found");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects directory target with descriptive error", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "fw-err-dir-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new FirmwareInspectTool(session);
			await expect(
				tool.execute("call-1", {
					action: "info",
					path: tempDir,
				}),
			).rejects.toThrow("Target path is a directory");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects 0-byte empty file with descriptive error", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "fw-empty-"));
		try {
			const emptyFile = path.join(tempDir, "empty.bin");
			await fs.writeFile(emptyFile, Buffer.alloc(0));
			const session = createTestSession(tempDir);
			const tool = new FirmwareInspectTool(session);
			await expect(
				tool.execute("call-1", {
					action: "info",
					path: emptyFile,
				}),
			).rejects.toThrow("empty (0 bytes)");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects file exceeding max_bytes limit", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "fw-limit-"));
		try {
			const sampleFile = path.join(tempDir, "sample.bin");
			await fs.writeFile(sampleFile, Buffer.alloc(2048, 0x55));
			const session = createTestSession(tempDir);
			const tool = new FirmwareInspectTool(session);
			await expect(
				tool.execute("call-1", {
					action: "info",
					path: sampleFile,
					max_bytes: 1024,
				}),
			).rejects.toThrow("exceeds maximum allowed limit");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("firmware_inspect uImage inspection", () => {
	it("parses uImage info and regions correctly", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "fw-uimage-"));
		try {
			const uimageFile = path.join(tempDir, "uImage");
			const uimgBuf = createSyntheticUImage({
				imageName: "OpenWrt-Linux-Kernel",
				osId: 5, // Linux
				archId: 2, // ARM
				typeId: 2, // Kernel
				compId: 1, // gzip
				loadAddr: 0x80008000,
				entryPoint: 0x80008000,
				payloadSize: 256,
			});
			await fs.writeFile(uimageFile, uimgBuf);

			const session = createTestSession(tempDir);
			const tool = new FirmwareInspectTool(session);

			// 1. Action: info
			const infoRes = await tool.execute("call-info", {
				action: "info",
				path: uimageFile,
			});
			expect(infoRes.details.primaryFormat).toBe("uImage");
			expect(infoRes.details.fileSize).toBe(uimgBuf.length);
			expect(infoRes.details.sha256).toBeDefined();
			expect(infoRes.details.md5).toBeDefined();
			expect(infoRes.details.regionsSummary?.totalDetected).toBeGreaterThanOrEqual(1);

			const infoText = textOf(infoRes);
			expect(infoText).toContain("Firmware Overview");
			expect(infoText).toContain("OpenWrt-Linux-Kernel");
			expect(infoText).toContain("ARM");
			expect(infoText).toContain("gzip");

			// 2. Action: regions
			const regionsRes = await tool.execute("call-regions", {
				action: "regions",
				path: uimageFile,
			});
			expect(regionsRes.details.regions?.length).toBeGreaterThanOrEqual(1);
			const firstRegion = regionsRes.details.regions![0];
			expect(firstRegion.format).toBe("uImage");
			expect(firstRegion.offset).toBe(0);
			expect(firstRegion.compression).toBe("gzip");
			expect(firstRegion.metadata?.os).toBe("Linux");
			expect(firstRegion.metadata?.arch).toBe("ARM");
			expect(firstRegion.metadata?.loadAddress).toBe("0x80008000");

			const regionsText = textOf(regionsRes);
			expect(regionsText).toContain("uImage");
			expect(regionsText).toContain("0x0");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("firmware_inspect SquashFS inspection", () => {
	it("parses SquashFS v4.0 superblock and reports filesystem parameters", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "fw-sqsh-"));
		try {
			const sqshFile = path.join(tempDir, "rootfs.squashfs");
			const sqshBuf = createSyntheticSquashfs({
				inodes: 345,
				blockSize: 131072,
				compId: 4, // xz
				bytesUsed: 1048576,
			});
			await fs.writeFile(sqshFile, sqshBuf);

			const session = createTestSession(tempDir);
			const tool = new FirmwareInspectTool(session);

			const res = await tool.execute("call-info", {
				action: "info",
				path: sqshFile,
			});
			expect(res.details.primaryFormat).toBe("SquashFS 4.x");
			expect(res.details.regionsSummary?.totalDetected).toBeGreaterThanOrEqual(1);

			const regionsRes = await tool.execute("call-reg", {
				action: "regions",
				path: sqshFile,
			});
			const reg = regionsRes.details.regions![0];
			expect(reg.format).toBe("SquashFS 4.x");
			expect(reg.compression).toBe("xz");
			expect(reg.metadata?.inodes).toBe(345);
			expect(reg.metadata?.blockSize).toBe(131072);

			const text = textOf(regionsRes);
			expect(text).toContain("SquashFS v4.0");
			expect(text).toContain("xz");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("firmware_inspect CPIO archive inventory", () => {
	it("inventories file members and supports path filtering and pagination", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "fw-cpio-"));
		try {
			const cpioFile = path.join(tempDir, "initramfs.cpio");
			const files = [
				{ name: "init", content: "#!/bin/sh\necho boot\n", mode: 0o100755 },
				{ name: "etc/passwd", content: "root:x:0:0:root:/root:/bin/sh\n" },
				{ name: "etc/shadow", content: "root:$6$salt$hash:19000:0:99999:7:::\n" },
				{ name: "bin/busybox", content: "ELF_STUB_BUSYBOX" },
			];
			const cpioBuf = createSyntheticCpio(files);
			await fs.writeFile(cpioFile, cpioBuf);

			const session = createTestSession(tempDir);
			const tool = new FirmwareInspectTool(session);

			// 1. Action: info
			const infoRes = await tool.execute("call-info", {
				action: "info",
				path: cpioFile,
			});
			expect(infoRes.details.primaryFormat).toBe("CPIO");
			expect(infoRes.details.containerSummary?.entryCount).toBe(4);

			// 2. Action: entries (all)
			const entriesRes = await tool.execute("call-entries", {
				action: "entries",
				path: cpioFile,
			});
			expect(entriesRes.details.entries?.length).toBe(4);
			const paths = entriesRes.details.entries!.map(e => e.path);
			expect(paths).toContain("init");
			expect(paths).toContain("etc/passwd");
			expect(paths).toContain("etc/shadow");
			expect(paths).toContain("bin/busybox");

			// 3. Action: entries with path_filter
			const filteredRes = await tool.execute("call-filter", {
				action: "entries",
				path: cpioFile,
				path_filter: "etc",
			});
			expect(filteredRes.details.entries?.length).toBe(2);
			const filteredPaths = filteredRes.details.entries!.map(e => e.path);
			expect(filteredPaths).toContain("etc/passwd");
			expect(filteredPaths).toContain("etc/shadow");
			expect(filteredPaths).not.toContain("init");

			// 4. Action: entries pagination (limit & offset)
			const pagedRes = await tool.execute("call-page", {
				action: "entries",
				path: cpioFile,
				limit: 2,
				offset: 1,
			});
			expect(pagedRes.details.entries?.length).toBe(2);
			expect(pagedRes.details.entries![0].path).toBe("etc/passwd");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("firmware_inspect multi-region image and entropy distribution", () => {
	it("detects concatenated partitions in multi-region image", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "fw-multi-"));
		try {
			const multiFile = path.join(tempDir, "full_flash.bin");
			const bootloaderPad = Buffer.alloc(4096, 0xff); // 4KB bootloader padding
			const uimgBuf = createSyntheticUImage({ imageName: "KernelPart", payloadSize: 512 });
			const sqshBuf = createSyntheticSquashfs({ inodes: 200, bytesUsed: 16384 });

			const combined = Buffer.concat([bootloaderPad, uimgBuf, sqshBuf]);
			await fs.writeFile(multiFile, combined);

			const session = createTestSession(tempDir);
			const tool = new FirmwareInspectTool(session);

			const res = await tool.execute("call-info", {
				action: "info",
				path: multiFile,
			});
			expect(res.details.primaryFormat).toContain("Multi-Region Firmware");
			expect(res.details.regionsSummary?.totalDetected).toBeGreaterThanOrEqual(2);

			const regionsRes = await tool.execute("call-reg", {
				action: "regions",
				path: multiFile,
			});
			const detectedOffsets = regionsRes.details.regions!.map(r => r.offset);
			expect(detectedOffsets).toContain(4096); // uImage at 4096
			expect(detectedOffsets).toContain(4096 + uimgBuf.length); // SquashFS offset
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("computes block-by-block entropy with classification", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "fw-ent-"));
		try {
			const entFile = path.join(tempDir, "entropy_sample.bin");
			// 1024 bytes of nulls (sparse) + 1024 bytes of high entropy pseudo-random bytes
			const sparseChunk = Buffer.alloc(1024, 0);
			const randomChunk = Buffer.alloc(1024);
			for (let i = 0; i < 1024; i++) randomChunk[i] = (i * 101 + 37) % 256;
			const sampleBuf = Buffer.concat([sparseChunk, randomChunk]);
			await fs.writeFile(entFile, sampleBuf);

			const session = createTestSession(tempDir);
			const tool = new FirmwareInspectTool(session);

			const entRes = await tool.execute("call-ent", {
				action: "entropy",
				path: entFile,
				block_size: 1024,
			});
			expect(entRes.details.totalBlocks).toBe(2);
			expect(entRes.details.entropyBlocks?.length).toBe(2);

			const b0 = entRes.details.entropyBlocks![0];
			const b1 = entRes.details.entropyBlocks![1];
			expect(b0.entropy).toBe(0);
			expect(b0.classification).toBe("sparse");
			expect(b1.entropy).toBeGreaterThan(7.0);

			const entText = textOf(entRes);
			expect(entText).toContain("Entropy Distribution");
			expect(entText).toContain("sparse");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});
