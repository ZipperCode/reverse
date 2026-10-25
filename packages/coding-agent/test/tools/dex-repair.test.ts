/**
 * Comprehensive regression and contract tests for DexRepairTool (FART offline CodeItem repair).
 */

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { Settings } from "../../src/config/settings";
import type { ToolSession } from "../../src/tools";
import { DexRepairTool } from "../../src/tools/dex-repair";
import {
	buildFartInsBinFile,
	buildFartRecord,
	buildSyntheticDexFixture,
	makeCodeItem,
	SYNTHETIC_INSNS_LICENSED,
} from "../helpers/dex-synthetic-fixture";

function createMockSession(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: false,
		settings: Settings.isolated({}),
	} as unknown as ToolSession;
}

// Exact upstream FART dump record from https://github.com/hanbinglengyue/FART (fart.py line 670)
// 40-byte real CodeItem with opcodes: new-instance, invoke-direct, invoke-virtual, move-result-object, check-cast, return-object
const UPSTREAM_FART_B64 = "AgABAAIAAABLnY4ADAAAACIAFwNwEPoOAABuIP4OEAAMAR8BFwMRAQ==";

describe("DexRepairTool", () => {
	let testDir: string;
	let session: ToolSession;
	let tool: DexRepairTool;

	beforeEach(() => {
		testDir = fs.mkdtempSync(path.join(os.tmpdir(), "rev_test_dex_repair_"));
		session = createMockSession(testDir);
		tool = new DexRepairTool(session);
	});

	afterEach(() => {
		try {
			fs.rmSync(testDir, { recursive: true, force: true });
		} catch {
			// Ignore cleanup errors
		}
	});

	it("gates persisted repairs while keeping census and dry-run read-only", () => {
		// Status is always read tier
		expect(tool.approval({ action: "status" })).toBe("read");

		// Repair dry-run (default or explicit) is read tier
		expect(tool.approval({ action: "repair", dry_run: true })).toBe("read");
		expect(tool.approval({ action: "repair" })).toBe("read");

		// Repair write (dry_run: false) is write tier
		expect(tool.approval({ action: "repair", dry_run: false })).toBe("write");

		// Unknown/malformed defaults to write tier (fail-closed)
		expect(tool.approval({})).toBe("write");
		expect(tool.approval(null)).toBe("write");
	});

	it("performs status census on stripped and intact DEX files", async () => {
		const strippedDex = buildSyntheticDexFixture({ stripLicensed: true });
		const strippedPath = path.join(testDir, "stripped.dex");
		fs.writeFileSync(strippedPath, strippedDex);

		const resStripped = await tool.execute("call_1", {
			action: "status",
			path: strippedPath,
		});

		expect(resStripped.details.status).toBe("ok");
		expect(resStripped.details.target_info?.needs_repair).toBe(true);
		expect(resStripped.details.target_info?.methods_empty_or_stripped).toBe(1);
		expect(resStripped.details.target_info?.methods_with_code).toBe(1);

		const intactDex = buildSyntheticDexFixture();
		const intactPath = path.join(testDir, "intact.dex");
		fs.writeFileSync(intactPath, intactDex);

		const resIntact = await tool.execute("call_2", {
			action: "status",
			path: intactPath,
		});

		expect(resIntact.details.status).toBe("ok");
		expect(resIntact.details.target_info?.needs_repair).toBe(false);
		expect(resIntact.details.target_info?.methods_empty_or_stripped).toBe(0);
		expect(resIntact.details.target_info?.methods_with_code).toBe(2);
	});

	it("simulates repair in dry_run mode without modifying filesystem", async () => {
		const strippedDex = buildSyntheticDexFixture({ stripLicensed: true });
		const strippedPath = path.join(testDir, "classes.dex");
		fs.writeFileSync(strippedPath, strippedDex);
		const initialStat = fs.statSync(strippedPath);

		const licensedCodeItem = makeCodeItem(1, SYNTHETIC_INSNS_LICENSED);
		const fartRecord = buildFartRecord({
			name: "Lcom/example/TestGate;->isLicensed()Z",
			method_idx: 1,
			code_item: licensedCodeItem,
		});
		const dumpPath = path.join(testDir, "dump_ins.bin");
		fs.writeFileSync(dumpPath, fartRecord);

		const res = await tool.execute("call_dry", {
			action: "repair",
			path: strippedPath,
			records: dumpPath,
			dry_run: true,
		});

		expect(res.details.status).toBe("ok");
		expect(res.details.dry_run).toBe(true);
		expect(res.details.repaired_count).toBe(1);
		expect(res.details.repairs?.[0]?.method_idx).toBe(1);
		expect(res.details.repairs?.[0]?.name).toBe("isLicensed");
		expect(res.details.repairs?.[0]?.old_code_off).toBe(0);
		expect(res.details.repairs?.[0]?.new_code_off).toBeGreaterThan(0);
		expect(res.details.repairs?.[0]?.relocated).toBe(true);
		expect(res.details.validation?.check_clean).toBe(true);

		// Source file remained untouched
		const postStat = fs.statSync(strippedPath);
		expect(postStat.mtimeMs).toBe(initialStat.mtimeMs);
		expect(postStat.size).toBe(initialStat.size);
	});

	it("repairs stripped DEX with real CodeItem relocation, contiguous sections, and writes fresh output", async () => {
		const strippedDex = buildSyntheticDexFixture({ stripLicensed: true });
		const strippedPath = path.join(testDir, "classes_stripped.dex");
		fs.writeFileSync(strippedPath, strippedDex);

		const licensedCodeItem = makeCodeItem(1, SYNTHETIC_INSNS_LICENSED);
		const fartContent = buildFartInsBinFile([
			{
				name: "Lcom/example/TestGate;->isLicensed()Z",
				method_idx: 1,
				code_item: licensedCodeItem,
			},
		]);
		const dumpPath = path.join(testDir, "fart_ins.bin");
		fs.writeFileSync(dumpPath, fartContent);

		const outPath = path.join(testDir, "classes_repaired.dex");

		const res = await tool.execute("call_write", {
			action: "repair",
			path: strippedPath,
			records: dumpPath,
			dry_run: false,
			out: outPath,
		});

		expect(res.details.status).toBe("ok");
		expect(res.details.dry_run).toBe(false);
		expect(res.details.repaired_count).toBe(1);
		expect(res.details.out_path).toBe(outPath);
		expect(res.details.out_sha256).toBeDefined();

		// Verify output file exists
		expect(fs.existsSync(outPath)).toBe(true);
		const repairedBuf = fs.readFileSync(outPath);
		expect(repairedBuf.length).toBeGreaterThan(strippedDex.length);

		// Status check on repaired file confirms clean state
		const statusRes = await tool.execute("call_check", {
			action: "status",
			path: outPath,
		});
		expect(statusRes.details.target_info?.needs_repair).toBe(false);
		expect(statusRes.details.target_info?.methods_with_code).toBe(2);
		expect(statusRes.details.target_info?.methods_empty_or_stripped).toBe(0);
		expect(statusRes.details.target_info?.checksum_valid).toBe(true);
		expect(statusRes.details.target_info?.signature_valid).toBe(true);
	});

	it("detects and rejects foreign FART capture with mismatched ins_size and foreign index operands", async () => {
		// Upstream FART 40-byte record has ins_size=1 and foreign type/method indices
		// Attempting to inject it into static compute()I (ins_size=0, 5-type DEX) must be rejected
		const strippedDex = buildSyntheticDexFixture({ stripCompute: true });
		const strippedPath = path.join(testDir, "classes_stripped_compute.dex");
		fs.writeFileSync(strippedPath, strippedDex);

		const foreignRecord = `{name:Lcom/example/TestGate;->compute()I,method_idx:0,offset:0,code_item_len:40,ins:${UPSTREAM_FART_B64}}`;
		const dumpPath = path.join(testDir, "foreign_ins.bin");
		fs.writeFileSync(dumpPath, foreignRecord);

		await expect(
			tool.execute("call_foreign_fail", {
				action: "repair",
				path: strippedPath,
				records: dumpPath,
				dry_run: true,
			}),
		).rejects.toThrow("None of the 1 provided records could be matched");
	});

	it("restores CodeItem using valid signature-compatible FART dumped record", async () => {
		const strippedDex = buildSyntheticDexFixture({ stripCompute: true });
		const strippedPath = path.join(testDir, "classes_valid_compute.dex");
		fs.writeFileSync(strippedPath, strippedDex);

		// Valid compute()I CodeItem: registers=1, ins_size=0 (static), outs=0, const/4 v0, #2, return v0
		const validComputeCodeItem = makeCodeItem(1, [0x2012, 0x000f]);
		const validRecord = buildFartRecord({
			name: "int com.example.TestGate.compute()",
			method_idx: 0,
			code_item: validComputeCodeItem,
		});
		const dumpPath = path.join(testDir, "valid_compute_ins.bin");
		fs.writeFileSync(dumpPath, validRecord);

		const outPath = path.join(testDir, "classes_compute_repaired.dex");
		const res = await tool.execute("call_valid_compute_repair", {
			action: "repair",
			path: strippedPath,
			records: dumpPath,
			dry_run: false,
			out: outPath,
		});

		expect(res.details.status).toBe("ok");
		expect(res.details.repaired_count).toBe(1);
		expect(res.details.repairs?.[0]?.method_idx).toBe(0);
		expect(res.details.repairs?.[0]?.new_insns_size).toBe(2);
		expect(res.details.validation?.check_clean).toBe(true);
	});

	it("restores CodeItem when FART record uses ART PrettyMethod name format", async () => {
		const strippedDex = buildSyntheticDexFixture({ stripLicensed: true });
		const strippedPath = path.join(testDir, "classes_stripped_pretty.dex");
		fs.writeFileSync(strippedPath, strippedDex);

		const licensedCodeItem = makeCodeItem(1, SYNTHETIC_INSNS_LICENSED);
		// Producer PrettyMethod format: boolean com.example.TestGate.isLicensed()
		const prettyRecord = buildFartRecord({
			name: "boolean com.example.TestGate.isLicensed()",
			method_idx: 1,
			code_item: licensedCodeItem,
		});
		const dumpPath = path.join(testDir, "pretty_ins.bin");
		fs.writeFileSync(dumpPath, prettyRecord);

		const outPath = path.join(testDir, "classes_pretty_repaired.dex");
		const res = await tool.execute("call_pretty_repair", {
			action: "repair",
			path: strippedPath,
			records: dumpPath,
			dry_run: false,
			out: outPath,
		});

		expect(res.details.status).toBe("ok");
		expect(res.details.repaired_count).toBe(1);
		expect(res.details.repairs?.[0]?.name).toBe("isLicensed");
		expect(res.details.validation?.check_clean).toBe(true);
	});

	it("detects and rejects conflicting duplicate captures for the same method", async () => {
		const strippedDex = buildSyntheticDexFixture({ stripLicensed: true });
		const strippedPath = path.join(testDir, "classes.dex");
		fs.writeFileSync(strippedPath, strippedDex);

		const itemA = makeCodeItem(1, [0x0012, 0x000f]);
		const itemB = makeCodeItem(2, [0x1012, 0x000f]);

		const recordA = buildFartRecord({
			name: "Lcom/example/TestGate;->isLicensed()Z",
			method_idx: 1,
			code_item: itemA,
		});
		const recordB = buildFartRecord({
			name: "Lcom/example/TestGate;->isLicensed()Z",
			method_idx: 1,
			code_item: itemB, // conflicting payload!
		});

		const dumpPath = path.join(testDir, "conflicting_fart.bin");
		fs.writeFileSync(dumpPath, [recordA, recordB].join("\n"));

		await expect(
			tool.execute("call_conflict", {
				action: "repair",
				path: strippedPath,
				records: dumpPath,
				dry_run: true,
			}),
		).rejects.toThrow("Ambiguous conflicting captures detected");
	});

	it("rejects mismatched method captures and reports diagnostics", async () => {
		const strippedDex = buildSyntheticDexFixture({ stripLicensed: true });
		const strippedPath = path.join(testDir, "classes.dex");
		fs.writeFileSync(strippedPath, strippedDex);

		const licensedCodeItem = makeCodeItem(1, SYNTHETIC_INSNS_LICENSED);

		// Mismatch 1: method_idx 1 in DEX is isLicensed, but capture claims to be 'completelyDifferentMethod'
		const mismatchedRecord = buildFartRecord({
			name: "Lcom/example/TestGate;->completelyDifferentMethod()V",
			method_idx: 1,
			code_item: licensedCodeItem,
		});

		// Mismatch 2: method_idx 9999 is outside method_ids_size
		const outOfBoundsRecord = buildFartRecord({
			name: "Lcom/example/TestGate;->ghost()V",
			method_idx: 9999,
			code_item: licensedCodeItem,
		});

		const dumpContent = [mismatchedRecord, outOfBoundsRecord].join("\n");
		const dumpPath = path.join(testDir, "bad_fart.bin");
		fs.writeFileSync(dumpPath, dumpContent);

		await expect(
			tool.execute("call_fail", {
				action: "repair",
				path: strippedPath,
				records: dumpPath,
				dry_run: true,
			}),
		).rejects.toThrow(ToolError);
	});

	it("enforces anti-aliasing and no-overwrite policy on write destination", async () => {
		const strippedDex = buildSyntheticDexFixture({ stripLicensed: true });
		const strippedPath = path.join(testDir, "same.dex");
		fs.writeFileSync(strippedPath, strippedDex);

		const licensedCodeItem = makeCodeItem(1, SYNTHETIC_INSNS_LICENSED);
		const dumpPath = path.join(testDir, "records.bin");
		fs.writeFileSync(
			dumpPath,
			buildFartRecord({
				name: "Lcom/example/TestGate;->isLicensed()Z",
				method_idx: 1,
				code_item: licensedCodeItem,
			}),
		);

		// 1. In-place aliasing rejection
		await expect(
			tool.execute("call_alias", {
				action: "repair",
				path: strippedPath,
				records: dumpPath,
				dry_run: false,
				out: strippedPath,
			}),
		).rejects.toThrow(ToolError);

		// 2. Pre-existing destination rejection (no-clobber)
		const existingOut = path.join(testDir, "already_exists.dex");
		fs.writeFileSync(existingOut, Buffer.from("existing data"));
		await expect(
			tool.execute("call_exists", {
				action: "repair",
				path: strippedPath,
				records: dumpPath,
				dry_run: false,
				out: existingOut,
			}),
		).rejects.toThrow(ToolError);
	});

	it("repairs fully-stripped DEX having zero initial code items and creates TYPE_CODE_ITEM in map_list", async () => {
		// Completely stripped DEX: both methods have code_off = 0
		const allStrippedDex = buildSyntheticDexFixture({ stripLicensed: true, stripCompute: true });
		const dexPath = path.join(testDir, "all_stripped.dex");
		fs.writeFileSync(dexPath, allStrippedDex);

		const fartContent = buildFartInsBinFile([
			{
				name: "Lcom/example/TestGate;->compute()I",
				method_idx: 0,
				code_item: makeCodeItem(1, [0x2012, 0x000f]),
			},
			{
				name: "Lcom/example/TestGate;->isLicensed()Z",
				method_idx: 1,
				code_item: makeCodeItem(1, SYNTHETIC_INSNS_LICENSED),
			},
		]);
		const dumpPath = path.join(testDir, "all_fart.bin");
		fs.writeFileSync(dumpPath, fartContent);

		const outPath = path.join(testDir, "all_repaired.dex");
		const res = await tool.execute("call_all_repair", {
			action: "repair",
			path: dexPath,
			records: dumpPath,
			dry_run: false,
			out: outPath,
		});

		expect(res.details.status).toBe("ok");
		expect(res.details.repaired_count).toBe(2);
		expect(res.details.validation?.check_clean).toBe(true);
		expect(res.details.validation?.checksum_verified).toBe(true);
		expect(res.details.validation?.signature_verified).toBe(true);
	});

	it("rejects capture when method name matches but class descriptor mismatches", async () => {
		const strippedDex = buildSyntheticDexFixture({ stripLicensed: true });
		const dexPath = path.join(testDir, "target.dex");
		fs.writeFileSync(dexPath, strippedDex);

		// Same method name 'isLicensed()Z', but wrong class descriptor
		const wrongClassRecord = buildFartRecord({
			name: "Lcom/wrong/OtherGate;->isLicensed()Z",
			method_idx: 1,
			code_item: makeCodeItem(1, SYNTHETIC_INSNS_LICENSED),
		});
		const dumpPath = path.join(testDir, "wrong_class.bin");
		fs.writeFileSync(dumpPath, wrongClassRecord);

		await expect(
			tool.execute("call_wrong_class", {
				action: "repair",
				path: dexPath,
				records: dumpPath,
				dry_run: true,
			}),
		).rejects.toThrow(ToolError);
	});

	it("repairs DEX where packer set code_off=0 while retaining physical code in data and map", async () => {
		const retainedDex = buildSyntheticDexFixture({ stripLicensed: true, retainPhysicalCodeItem: true });
		const dexPath = path.join(testDir, "retained_stripped.dex");
		fs.writeFileSync(dexPath, retainedDex);

		const licensedCodeItem = makeCodeItem(1, SYNTHETIC_INSNS_LICENSED);
		const fartRecord = buildFartRecord({
			name: "boolean com.example.TestGate.isLicensed()",
			method_idx: 1,
			code_item: licensedCodeItem,
		});
		const dumpPath = path.join(testDir, "retained_fart.bin");
		fs.writeFileSync(dumpPath, fartRecord);

		const outPath = path.join(testDir, "retained_repaired.dex");
		const res = await tool.execute("call_retained_repair", {
			action: "repair",
			path: dexPath,
			records: dumpPath,
			dry_run: false,
			out: outPath,
		});

		expect(res.details.status).toBe("ok");
		expect(res.details.repaired_count).toBe(1);
		expect(res.details.validation?.check_clean).toBe(true);
		expect(res.details.validation?.checksum_verified).toBe(true);
		expect(res.details.validation?.signature_verified).toBe(true);
	});
});
