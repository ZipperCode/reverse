/**
 * Focused regression and contract tests for DexPatchTool and shared reverse-python runner.
 */

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { Settings } from "../src/config/settings";
import type { ToolSession } from "../src/tools";
import { DexPatchTool } from "../src/tools/dex-patch";
import { runReversePython } from "../src/tools/reverse-python";

function createMockSession(cwd: string): ToolSession {
	// Cast reason: Test stub satisfying ToolSession contract
	return {
		cwd,
		hasUI: false,
		settings: Settings.isolated({}),
	} as unknown as ToolSession;
}

// ============================================================================
// Synthetic DEX Fixture Builder
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
 * Deterministic synthetic DEX generator constructing a real Dalvik executable with:
 * - Class Lcom/example/TestGate;
 * - Method isLicensed()Z with conditional branch and const/4 returns.
 * - Method compute()I with const/4 return.
 * - Valid Dalvik map_list, offsets, SHA-1 signature, and Adler-32 checksum.
 */
export function buildSyntheticDexFixture(): Buffer {
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

	// isLicensed()Z:
	// 0: const/4 v0, #0        (raw: 0x0012)
	// 2: if-nez v0, +4 units   (raw: 0x0039, 0x0004 -> branches to offset 10)
	// 6: const/4 v0, #1        (raw: 0x1012 -> reg 0, literal 1)
	// 8: return v0             (raw: 0x000f)
	// 10: const/4 v0, #0       (raw: 0x0012)
	// 12: return v0            (raw: 0x000f)
	const insns_isLicensed = [0x0012, 0x0039, 0x0004, 0x1012, 0x000f, 0x0012, 0x000f];

	// compute()I:
	// 0: const/4 v0, #2        (raw: 0x2012 -> reg 0, literal 2)
	// 2: return v0             (raw: 0x000f)
	const insns_compute = [0x2012, 0x000f];

	function makeCodeItem(registers: number, insns: number[]): Buffer {
		const body = Buffer.concat(insns.map(p16));
		return Buffer.concat([
			p16(registers), // registers_size
			p16(0), // ins_size
			p16(0), // outs_size
			p16(0), // tries_size
			p32(0), // debug_info_off
			p32(insns.length), // insns_size
			body,
		]);
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

	let cdBuf = Buffer.concat([
		uleb128(0), // static fields
		uleb128(0), // instance fields
		uleb128(classDataEntries.length), // direct methods
		uleb128(0), // virtual methods
	]);
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
		p32(0x0001), // public
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
	headerBuf.writeUInt32LE(0x12345678, 0x28); // endian_tag
	headerBuf.writeUInt32LE(mapOff, 0x34);
	headerBuf.writeUInt32LE(strings.length, 0x38);
	headerBuf.writeUInt32LE(string_ids_off, 0x3c);
	headerBuf.writeUInt32LE(types.length, 0x40);
	headerBuf.writeUInt32LE(type_ids_off, 0x44);
	headerBuf.writeUInt32LE(protos.length, 0x48);
	headerBuf.writeUInt32LE(proto_ids_off, 0x4c);
	headerBuf.writeUInt32LE(0, 0x50); // field_ids_size = 0
	headerBuf.writeUInt32LE(0, 0x54); // field_ids_off = 0
	headerBuf.writeUInt32LE(methods.length, 0x58);
	headerBuf.writeUInt32LE(method_ids_off, 0x5c);
	headerBuf.writeUInt32LE(1, 0x60); // class_defs_size = 1
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

// ============================================================================
// Test Suite
// ============================================================================

describe("DexPatchTool and reverse-python integration", () => {
	let tempDir: string;
	let dexPath: string;

	beforeEach(async () => {
		tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "dex-patch-test-"));
		dexPath = path.join(tempDir, "sample.dex");
		const dexBytes = buildSyntheticDexFixture();
		await fs.promises.writeFile(dexPath, dexBytes);
	});

	afterEach(async () => {
		try {
			await fs.promises.rm(tempDir, { recursive: true, force: true });
		} catch {}
	});

	describe("reverse-python shared runner", () => {
		it("terminates subprocess tree on timeout preventing delayed child writes", async () => {
			const sentinelPath = path.join(tempDir, "sentinel.txt");
			const res = await runReversePython({
				cwd: tempDir,
				sources: {
					"tree_spawn.py": [
						"import sys, subprocess, time, json",
						"req = json.load(sys.stdin)",
						"sentinel = req['sentinel']",
						'child_code = \'import time, sys; time.sleep(0.4); open(sys.argv[1], "w").write("orphaned")\'',
						"subprocess.Popen([sys.executable, '-c', child_code, sentinel])",
						"time.sleep(10)",
					].join("\n"),
				},
				entry: "tree_spawn.py",
				request: { sentinel: sentinelPath },
				timeoutMs: 150,
			});

			expect(res.status).toBe("error");
			expect(res.error).toContain("timed out");

			// Integration delay: exercising real OS process tree kill behavior against platform clock
			await Bun.sleep(500);
			expect(fs.existsSync(sentinelPath)).toBe(false);
		});

		it("rejects path traversal in staged sources", async () => {
			const res = await runReversePython({
				cwd: tempDir,
				sources: {
					"../evil.py": "print('evil')",
				},
				entry: "test.py",
				request: {},
			});

			expect(res.status).toBe("error");
			expect(res.error).toContain("outside temp directory");
		});
	});

	describe("DexPatchTool inspect", () => {
		it("inspects method bytecode and returns disassembly with branch targets", async () => {
			const tool = new DexPatchTool(createMockSession(tempDir));
			const res = await tool.execute("call_1", {
				action: "inspect",
				path: dexPath,
				class: "Lcom/example/TestGate;",
				method: "isLicensed",
				desc: "()Z",
			});

			expect(res.details.action).toBe("inspect");
			expect(res.details.status).toBe("ok");
			const method = res.details.inspect?.method;
			expect(method).toBeDefined();
			expect(method?.name).toBe("isLicensed");
			expect(method?.clean_decode).toBe(true);
			expect(method?.instructions.length).toBe(6);
			// Verifies branch target resolution
			const branch = method?.instructions[1];
			expect(branch?.name).toBe("if-nez");
			expect(branch?.branch_target).toBeDefined();
		});

		it("rejects non-existent class or method cleanly", async () => {
			const tool = new DexPatchTool(createMockSession(tempDir));
			await expect(
				tool.execute("call_2", {
					action: "inspect",
					path: dexPath,
					class: "Lcom/example/NonExistent;",
					method: "missing",
				}),
			).rejects.toThrow(ToolError);
		});
	});

	describe("DexPatchTool validate", () => {
		it("validates header integrity and checks verifier rules", async () => {
			const tool = new DexPatchTool(createMockSession(tempDir));
			const res = await tool.execute("call_3", {
				action: "validate",
				path: dexPath,
			});

			expect(res.details.action).toBe("validate");
			expect(res.details.status).toBe("ok");
			const val = res.details.validate;
			expect(val).toBeDefined();
			expect(val?.verifier_scope).toContain("Limited structural verifier");
			expect(val?.header.valid).toBe(true);
			expect(val?.header.checksum_ok).toBe(true);
			expect(val?.header.signature_ok).toBe(true);
			expect(val?.summary.total_classes).toBe(1);
			expect(val?.summary.methods_with_code).toBe(2);
			expect(val?.summary.unclean_decodes).toBe(0);
			expect(val?.summary.verifier_violations).toBe(0);
		});

		it("flags corrupted header on invalid file", async () => {
			const brokenPath = path.join(tempDir, "broken.dex");
			const brokenBytes = Buffer.from("NOT_A_VALID_DEX_FILE_CONTENT");
			await fs.promises.writeFile(brokenPath, brokenBytes);

			const tool = new DexPatchTool(createMockSession(tempDir));
			const res = await tool.execute("call_4", {
				action: "validate",
				path: brokenPath,
			});

			expect(res.details.validate?.header.valid).toBe(false);
		});
	});

	describe("DexPatchTool patch", () => {
		it("dry_run simulates patch and leaves no output file on disk", async () => {
			const outPath = path.join(tempDir, "dryrun_out.dex");
			const tool = new DexPatchTool(createMockSession(tempDir));

			const res = await tool.execute("call_5", {
				action: "patch",
				path: dexPath,
				out: outPath,
				dry_run: true,
				specs: [
					{
						name: "bypass_license",
						class: "Lcom/example/TestGate;",
						method: "isLicensed",
						desc: "()Z",
						match: { kind: "if-nez", target_reg: 0 },
						expect_next: { kind: "const4", literal: 1 },
						replace: { kind: "nops" },
					},
				],
			});

			expect(res.details.patch?.dry_run).toBe(true);
			expect(res.details.patch?.patches_count).toBe(1);
			expect(res.details.patch?.byte_diffs.length).toBe(1);
			expect(fs.existsSync(outPath)).toBe(false);
		});

		it("rejects input/output path aliasing and pre-existing output files", async () => {
			const tool = new DexPatchTool(createMockSession(tempDir));

			// Same file as input
			await expect(
				tool.execute("call_6", {
					action: "patch",
					path: dexPath,
					out: dexPath,
					dry_run: false,
					specs: [
						{
							class: "Lcom/example/TestGate;",
							method: "compute",
							match: { kind: "const4" },
							replace: { kind: "nops" },
						},
					],
				}),
			).rejects.toThrow("In-place modification is disallowed");

			// Pre-existing file
			const existingOut = path.join(tempDir, "existing.dex");
			await fs.promises.writeFile(existingOut, "pre-existing");
			await expect(
				tool.execute("call_7", {
					action: "patch",
					path: dexPath,
					out: existingOut,
					dry_run: false,
					specs: [
						{
							class: "Lcom/example/TestGate;",
							method: "compute",
							match: { kind: "const4" },
							replace: { kind: "nops" },
						},
					],
				}),
			).rejects.toThrow("Output path already exists");
		});

		it("rejects non-equal length replacements and polarity mismatches", async () => {
			const outPath = path.join(tempDir, "out_unequal.dex");
			const tool = new DexPatchTool(createMockSession(tempDir));

			// Unequal length (replacing 4-byte if-nez with 2-byte hex)
			await expect(
				tool.execute("call_8", {
					action: "patch",
					path: dexPath,
					out: outPath,
					dry_run: false,
					specs: [
						{
							class: "Lcom/example/TestGate;",
							method: "isLicensed",
							desc: "()Z",
							match: { kind: "if-nez" },
							replace: { kind: "bytes", bytes: "0000" }, // 2 bytes instead of 4
						},
					],
				}),
			).rejects.toThrow("Equal length is required");

			// Polarity mismatch (expecting return instead of const4)
			await expect(
				tool.execute("call_9", {
					action: "patch",
					path: dexPath,
					out: outPath,
					dry_run: false,
					specs: [
						{
							class: "Lcom/example/TestGate;",
							method: "isLicensed",
							desc: "()Z",
							match: { kind: "if-nez" },
							expect_next: { kind: "return" },
							replace: { kind: "nops" },
						},
					],
				}),
			).rejects.toThrow("Polarity check failed");
		});

		it("executes multi-patch cumulatively, recomputes headers, and preserves source", async () => {
			const outPath = path.join(tempDir, "patched_final.dex");
			const originalSourceBytes = await fs.promises.readFile(dexPath);
			const tool = new DexPatchTool(createMockSession(tempDir));

			const res = await tool.execute("call_10", {
				action: "patch",
				path: dexPath,
				out: outPath,
				dry_run: false,
				specs: [
					// Patch 1: Nop out the if-nez branch (4 bytes: 39 00 04 00 -> 00 00 00 00)
					{
						name: "patch_license_gate",
						class: "Lcom/example/TestGate;",
						method: "isLicensed",
						desc: "()Z",
						match: { kind: "if-nez", target_reg: 0 },
						expect_next: { kind: "const4", literal: 1 },
						replace: { kind: "nops" },
					},
					// Patch 2: Mutate compute() const/4 v0, #2 -> const/4 v0, #5 (2 bytes: 20 12 -> 50 12)
					{
						name: "patch_compute_value",
						class: "Lcom/example/TestGate;",
						method: "compute",
						desc: "()I",
						match: { kind: "const4", literal: 2, target_reg: 0 },
						expect_next: { kind: "return" },
						replace: { kind: "bytes", bytes: "1250" },
					},
				],
			});

			expect(res.details.patch?.dry_run).toBe(false);
			expect(res.details.patch?.patches_count).toBe(2);
			expect(res.details.patch?.byte_diffs.length).toBe(2);
			expect(fs.existsSync(outPath)).toBe(true);

			// Source remains 100% untouched
			const currentSourceBytes = await fs.promises.readFile(dexPath);
			expect(currentSourceBytes.equals(originalSourceBytes)).toBe(true);

			// Patched output validates cleanly
			const validateRes = await tool.execute("call_11", {
				action: "validate",
				path: outPath,
			});
			expect(validateRes.details.validate?.header.valid).toBe(true);
			expect(validateRes.details.validate?.header.checksum_ok).toBe(true);
			expect(validateRes.details.validate?.header.signature_ok).toBe(true);
			expect(validateRes.details.validate?.summary.unclean_decodes).toBe(0);
		});

		it("rejects match criteria on inapplicable instructions", async () => {
			const tool = new DexPatchTool(createMockSession(tempDir));

			// Spec specifies target_method on a method with no invoke instructions
			await expect(
				tool.execute("call_12", {
					action: "patch",
					path: dexPath,
					dry_run: true,
					specs: [
						{
							class: "Lcom/example/TestGate;",
							method: "compute",
							match: { target_method: "someMethod" },
							replace: { kind: "nops" },
						},
					],
				}),
			).rejects.toThrow("No instruction matched");

			// Spec specifies literal on a branch instruction
			await expect(
				tool.execute("call_13", {
					action: "patch",
					path: dexPath,
					dry_run: true,
					specs: [
						{
							class: "Lcom/example/TestGate;",
							method: "isLicensed",
							match: { kind: "if-nez", literal: 0 },
							replace: { kind: "nops" },
						},
					],
				}),
			).rejects.toThrow("No instruction matched");
		});

		it("rejects ordinal out of bounds", async () => {
			const tool = new DexPatchTool(createMockSession(tempDir));

			await expect(
				tool.execute("call_14", {
					action: "patch",
					path: dexPath,
					dry_run: true,
					specs: [
						{
							class: "Lcom/example/TestGate;",
							method: "isLicensed",
							match: { kind: "const4", ordinal: 99 },
							replace: { kind: "nops" },
						},
					],
				}),
			).rejects.toThrow("match.ordinal 99 is out of bounds");
		});

		it("rejects dangling symlink as output destination", async () => {
			const tool = new DexPatchTool(createMockSession(tempDir));
			const danglingLink = path.join(tempDir, "dangling_link.dex");
			try {
				await fs.promises.symlink("/non/existent/target/path", danglingLink);
			} catch {
				return; // Symlink creation not supported on some platforms
			}

			await expect(
				tool.execute("call_15", {
					action: "patch",
					path: dexPath,
					out: danglingLink,
					dry_run: false,
					specs: [
						{
							class: "Lcom/example/TestGate;",
							method: "compute",
							match: { kind: "const4" },
							replace: { kind: "nops" },
						},
					],
				}),
			).rejects.toThrow("Output path already exists (or is a dangling symlink)");
		});
	});
});
