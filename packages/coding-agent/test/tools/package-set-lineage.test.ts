import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { encodeArchive } from "@reverse/utils/ar";
import {
	ReverseWorkflowStore,
	accumulatePatches,
	hashFileSha256,
	resolveActiveWorkflowBaseline,
	verifySourceOriginalBytes,
	computePackageSetSha256,
	isPackageSetManifest,
	parseAndValidatePackageSetManifest,
	resolvePackageSetInput,
	type PackageSetManifest,
} from "@reverse/coding-agent/reverse-workflow";

async function createSyntheticMemberApk(options: {
	manifestXml?: string;
	dexBytes?: Buffer;
	nativeBytes?: Buffer;
}): Promise<Uint8Array> {
	const manifest = Buffer.from(options.manifestXml ?? '<manifest package="com.example.pkgset"/>', "utf8");
	const entries: Array<[string, Buffer]> = [["AndroidManifest.xml", manifest]];

	if (options.dexBytes !== undefined) {
		const dex = Buffer.alloc(512, 0);
		options.dexBytes.copy(dex, 0x50);
		entries.push(["classes.dex", dex]);
	}

	if (options.nativeBytes !== undefined) {
		const nativeSo = Buffer.alloc(1024, 0);
		options.nativeBytes.copy(nativeSo, 0x100);
		entries.push(["lib/arm64-v8a/libfoo.so", nativeSo]);
	}

	return await encodeArchive("zip", entries);
}

interface PackageSetFixture {
	dir: string;
	manifestPath: string;
	manifestSha256: string;
	setSha256: string;
	basePath: string;
	splitPath: string;
}

async function createSyntheticPackageSet(
	parentDir: string,
	subDirName: string,
	options?: {
		baseDexBytes?: Buffer;
		splitNativeBytes?: Buffer;
	},
): Promise<PackageSetFixture> {
	const dir = path.join(parentDir, subDirName);
	await fs.mkdir(dir, { recursive: true });

	const basePath = path.join(dir, "base.apk");
	const splitPath = path.join(dir, "split_config.arm64_v8a.apk");

	await fs.writeFile(
		basePath,
		await createSyntheticMemberApk({
			dexBytes: options?.baseDexBytes ?? Buffer.from([0x10, 0x20, 0x30, 0x40]),
		}),
	);
	await fs.writeFile(
		splitPath,
		await createSyntheticMemberApk({
			nativeBytes: options?.splitNativeBytes ?? Buffer.from([0xaa, 0xbb, 0xcc, 0xdd]),
		}),
	);

	const baseStat = await fs.stat(basePath);
	const splitStat = await fs.stat(splitPath);
	const baseSha = await hashFileSha256(basePath);
	const splitSha = await hashFileSha256(splitPath);

	const members = [
		{
			name: "base",
			filename: "base.apk",
			size: baseStat.size,
			sha256: baseSha,
			alignment_ok: true,
			signed: true,
		},
		{
			name: "split_config.arm64_v8a",
			filename: "split_config.arm64_v8a.apk",
			size: splitStat.size,
			sha256: splitSha,
			alignment_ok: true,
			signed: true,
		},
	];

	const setSha256 = computePackageSetSha256(members);
	const manifestData: PackageSetManifest = {
		format: "apk_package_set",
		package: "com.example.pkgset",
		versionCode: 100,
		set_sha256: setSha256,
		members,
		signed: true,
	};

	const manifestPath = path.join(dir, "package-set.json");
	await fs.writeFile(manifestPath, JSON.stringify(manifestData, null, 2), "utf8");
	const manifestSha256 = await hashFileSha256(manifestPath);

	return {
		dir,
		manifestPath,
		manifestSha256,
		setSha256,
		basePath,
		splitPath,
	};
}

describe("APK Package Set Provenance, Lineage, and Invalidation", () => {
	it("strictly parses manifest format, validates directory containment, and rejects tampering", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-pkg-val-"));
		const pkg = await createSyntheticPackageSet(tempDir, "initial_set");

		// 1. Valid manifest parses and validates correctly
		const validated = await parseAndValidatePackageSetManifest(pkg.manifestPath);
		expect(validated.manifest.format).toBe("apk_package_set");
		expect(validated.manifest.members.length).toBe(2);
		expect(validated.manifestSha256).toBe(pkg.manifestSha256);
		expect(await isPackageSetManifest(pkg.manifestPath)).toBe(true);

		// 2. Ordinary JSON files are NOT recognized as package sets
		const regularJson = path.join(tempDir, "ordinary.json");
		await fs.writeFile(regularJson, JSON.stringify({ key: "value", format: "custom" }), "utf8");
		expect(await isPackageSetManifest(regularJson)).toBe(false);

		// 3. Rejects directory traversal escape
		const escapeManifestPath = path.join(pkg.dir, "escape.json");
		const escapeData = {
			...validated.manifest,
			members: [
				{ ...validated.manifest.members[0] },
				{ ...validated.manifest.members[1], filename: "../escape.apk" },
			],
		};
		await fs.writeFile(escapeManifestPath, JSON.stringify(escapeData), "utf8");
		expect(parseAndValidatePackageSetManifest(escapeManifestPath)).rejects.toThrow(/escapes directory containment/);

		// 4. Rejects member size tampering
		const badSizeManifestPath = path.join(pkg.dir, "bad-size.json");
		const badSizeData = {
			...validated.manifest,
			members: [{ ...validated.manifest.members[0], size: 999999 }, { ...validated.manifest.members[1] }],
		};
		await fs.writeFile(badSizeManifestPath, JSON.stringify(badSizeData), "utf8");
		expect(parseAndValidatePackageSetManifest(badSizeManifestPath)).rejects.toThrow(/size mismatch/);

		// 5. Rejects member hash mismatch
		const badHashManifestPath = path.join(pkg.dir, "bad-hash.json");
		const badHashData = {
			...validated.manifest,
			members: [
				{
					...validated.manifest.members[0],
					sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				},
				{ ...validated.manifest.members[1] },
			],
		};
		await fs.writeFile(badHashManifestPath, JSON.stringify(badHashData), "utf8");
		expect(parseAndValidatePackageSetManifest(badHashManifestPath)).rejects.toThrow(/SHA-256 mismatch/);

		// 6. Rejects aggregate set_sha256 mismatch
		const badSetShaManifestPath = path.join(pkg.dir, "bad-set-sha.json");
		const badSetShaData = {
			...validated.manifest,
			set_sha256: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		};
		await fs.writeFile(badSetShaManifestPath, JSON.stringify(badSetShaData), "utf8");
		expect(parseAndValidatePackageSetManifest(badSetShaManifestPath)).rejects.toThrow(/aggregate SHA-256 mismatch/);

		// 7. Malformed package-set.json is strictly parsed and never classified as an ordinary file
		const malformedManifest = path.join(tempDir, "package-set.json");
		await fs.writeFile(malformedManifest, "{ malformed json", "utf8");
		expect(await isPackageSetManifest(malformedManifest)).toBe(true);
		expect(parseAndValidatePackageSetManifest(malformedManifest)).rejects.toThrow(/not valid JSON/);

		// 8. Non-existent package-set.json returns false
		const nonExistentManifest = path.join(tempDir, "absent", "package-set.json");
		expect(await isPackageSetManifest(nonExistentManifest)).toBe(false);
	});

	it("accumulates patches preserving separate package_member and preventing cross-member collisions", () => {
		const parentPatches = [
			{
				patch_id: "patch_base",
				package_member: "base",
				member_path: "classes.dex",
				offset: 0x50,
				original_bytes: "1020",
				expected_bytes: "ffff",
				status: "active" as const,
				created_at: new Date().toISOString(),
			},
		];

		// Same entry name 'classes.dex' and same offset 0x50 on a different package_member 'split_feature'
		// MUST NOT collide or trigger overlapping span error
		const accumulated = accumulatePatches(
			parentPatches,
			[
				{
					patch_id: "patch_split",
					package_member: "split_config.arm64_v8a",
					member_path: "classes.dex",
					offset: 0x50,
					original_bytes: "3040",
					expected_bytes: "eeee",
				},
			],
			undefined,
			"bld_2",
		);

		expect(accumulated.length).toBe(2);
		expect(accumulated.find(p => p.patch_id === "patch_base")?.package_member).toBe("base");
		expect(accumulated.find(p => p.patch_id === "patch_split")?.package_member).toBe("split_config.arm64_v8a");

		// Overlapping spans on the SAME package_member MUST throw
		expect(() =>
			accumulatePatches(
				accumulated,
				[
					{
						patch_id: "patch_overlap",
						package_member: "base",
						member_path: "classes.dex",
						offset: 0x51,
						original_bytes: "20",
						expected_bytes: "aa",
					},
				],
				undefined,
				"bld_3",
			),
		).toThrow(/Overlapping active patches detected/);

		// Overlapping active patches on base where one omits package_member and other explicitly declares 'base'
		expect(() =>
			accumulatePatches(
				[
					{
						patch_id: "patch_omit",
						member_path: "classes.dex",
						offset: 0x50,
						original_bytes: "1020",
						expected_bytes: "ffff",
						status: "active",
						created_at: new Date().toISOString(),
					},
				],
				[
					{
						patch_id: "patch_explicit_base",
						package_member: "base",
						member_path: "classes.dex",
						offset: 0x51,
						original_bytes: "20",
						expected_bytes: "aa",
					},
				],
				undefined,
				"bld_overlap_norm",
			),
		).toThrow(/Overlapping active patches detected/);

		// Re-declaring the same patch definition with explicit 'base' is an idempotent re-declaration (not a collision)
		const redeclared = accumulatePatches(
			[
				{
					patch_id: "patch_same",
					member_path: "classes.dex",
					offset: 0x50,
					original_bytes: "1020",
					expected_bytes: "ffff",
					status: "active",
					created_at: new Date().toISOString(),
				},
			],
			[
				{
					patch_id: "patch_same",
					package_member: "base",
					member_path: "classes.dex",
					offset: 0x50,
					original_bytes: "1020",
					expected_bytes: "ffff",
				},
			],
			undefined,
			"bld_redec",
		);
		expect(redeclared.length).toBe(1);
		expect(redeclared[0]!.package_member).toBe("base");
	});

	it("registers derivative, verifies cumulative replay A+B across two package members, and detects hash drift", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-pkg-lineage-"));
		const store = new ReverseWorkflowStore({ repositoryRoot: tempDir });

		// 1. Initial base package set
		await createSyntheticPackageSet(tempDir, "base_set", {
			baseDexBytes: Buffer.from([0x10, 0x20, 0x30, 0x40]),
			splitNativeBytes: Buffer.from([0xaa, 0xbb, 0xcc, 0xdd]),
		});

		const wf = await store.create({
			target: "base_set/package-set.json",
			goal: "Test package set split lineage and cumulative replay",
		});
		expect(wf.id).toBeDefined();

		// 2. Build 1: Introduce Patch A on base (classes.dex at offset 0x50: 1020 -> 1122)
		const bld1Set = await createSyntheticPackageSet(tempDir, "bld1_set", {
			baseDexBytes: Buffer.from([0x11, 0x22, 0x30, 0x40]),
			splitNativeBytes: Buffer.from([0xaa, 0xbb, 0xcc, 0xdd]),
		});

		const d1 = await store.registerDerivative(wf.id, {
			build_id: "bld_1",
			target_path: "bld1_set/package-set.json",
			output_sha256: bld1Set.manifestSha256,
			patches: [
				{
					patch_id: "patch_A",
					package_member: "base",
					member_path: "classes.dex",
					offset: 0x50,
					original_bytes: "1020",
					expected_bytes: "1122",
				},
			],
		});

		expect(d1.build_id).toBe("bld_1");
		expect(d1.cumulative_patches.length).toBe(1);
		expect(d1.verification_result.status).toBe("verified");
		expect(d1.package_set?.format).toBe("apk_package_set");
		expect(d1.package_set?.members.length).toBe(2);

		// 3. Build 2: Retain Patch A on base and introduce Patch B on split member (libfoo.so at offset 0x100: aabb -> eeaa)
		const bld2Set = await createSyntheticPackageSet(tempDir, "bld2_set", {
			baseDexBytes: Buffer.from([0x11, 0x22, 0x30, 0x40]),
			splitNativeBytes: Buffer.from([0xee, 0xaa, 0xcc, 0xdd]),
		});

		const d2 = await store.registerDerivative(wf.id, {
			build_id: "bld_2",
			target_path: "bld2_set/package-set.json",
			output_sha256: bld2Set.manifestSha256,
			parent_build_id: "bld_1",
			patches: [
				{
					patch_id: "patch_B",
					package_member: "split_config.arm64_v8a",
					member_path: "lib/arm64-v8a/libfoo.so",
					offset: 0x100,
					original_bytes: "aabb",
					expected_bytes: "eeaa",
				},
			],
		});

		expect(d2.build_id).toBe("bld_2");
		expect(d2.parent_sha256).toBe(bld1Set.manifestSha256);
		expect(d2.cumulative_patches.length).toBe(2);
		expect(d2.cumulative_patches.find(p => p.patch_id === "patch_A")?.status).toBe("active");
		expect(d2.cumulative_patches.find(p => p.patch_id === "patch_B")?.status).toBe("active");
		expect(d2.verification_result.status).toBe("verified");

		// 4. Verification succeeds on healthy derivative
		const verifyOk = await store.verifyDerivative(wf.id, "bld_2");
		expect(verifyOk.status).toBe("verified");

		// 5. Tampering detection: mutate split_config.arm64_v8a.apk on disk without modifying package-set.json
		// The unchanged manifest cannot conceal the changed member; verifyDerivative MUST fail!
		const tamperedSplitBytes = Buffer.from("TAMPERED_SPLIT_CONTENT_CORRUPTION");
		await fs.writeFile(bld2Set.splitPath, tamperedSplitBytes);

		const verifyTampered = await store.verifyDerivative(wf.id, "bld_2");
		expect(verifyTampered.status).toBe("failed");
		expect(verifyTampered.failure_reason).toMatch(/SHA-256 mismatch|size mismatch/);
	});

	it("fails registration when patch original_bytes mismatch against the parent split member", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-pkg-orig-mismatch-"));
		const store = new ReverseWorkflowStore({ repositoryRoot: tempDir });

		await createSyntheticPackageSet(tempDir, "base_set", {
			baseDexBytes: Buffer.from([0x10, 0x20, 0x30, 0x40]),
			splitNativeBytes: Buffer.from([0xaa, 0xbb, 0xcc, 0xdd]),
		});

		const wf = await store.create({
			target: "base_set/package-set.json",
			goal: "Test original byte mismatch on split",
		});

		const bld1Set = await createSyntheticPackageSet(tempDir, "bld1_set", {
			baseDexBytes: Buffer.from([0x10, 0x20, 0x30, 0x40]),
			splitNativeBytes: Buffer.from([0x99, 0x99, 0xcc, 0xdd]),
		});

		// Declaring original_bytes as "0000" when actual split has "aabb" MUST fail source verification
		await expect(
			store.registerDerivative(wf.id, {
				build_id: "bld_mismatch",
				target_path: "bld1_set/package-set.json",
				output_sha256: bld1Set.manifestSha256,
				patches: [
					{
						patch_id: "patch_wrong_orig",
						package_member: "split_config.arm64_v8a",
						member_path: "lib/arm64-v8a/libfoo.so",
						offset: 0x100,
						original_bytes: "0000",
						expected_bytes: "9999",
					},
				],
			}),
		).rejects.toThrow(/original_bytes mismatch against source/);
	});

	it("detects dropped split member on disk even with zero patches", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-pkg-dropped-"));
		const store = new ReverseWorkflowStore({ repositoryRoot: tempDir });

		await createSyntheticPackageSet(tempDir, "base_set");
		const wf = await store.create({
			target: "base_set/package-set.json",
			goal: "Test dropped member detection",
		});

		const bldSet = await createSyntheticPackageSet(tempDir, "bld_set");
		// Remove the split member APK from disk before registering
		await fs.unlink(bldSet.splitPath);

		await expect(
			store.registerDerivative(wf.id, {
				build_id: "bld_dropped",
				target_path: "bld_set/package-set.json",
				output_sha256: bldSet.manifestSha256,
			}),
		).rejects.toThrow(/does not exist on disk/);
	});

	it("resolves active workflow baseline using package set dictionary matching manifest", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-pkg-resolve-"));
		const store = new ReverseWorkflowStore({ repositoryRoot: tempDir });

		await createSyntheticPackageSet(tempDir, "base_set");
		const wf = await store.create({
			target: "base_set/package-set.json",
			goal: "Test resolve baseline with packageSet input",
		});

		// Register a build
		const bld1Set = await createSyntheticPackageSet(tempDir, "bld1_set");
		await store.registerDerivative(wf.id, {
			build_id: "bld_1",
			target_path: "bld1_set/package-set.json",
			output_sha256: bld1Set.manifestSha256,
		});

		// 1. Resolve with explicit packageSet map pointing to bld1 files
		const resolved = await resolveActiveWorkflowBaseline(tempDir, {
			targetPath: bld1Set.basePath,
			packageSet: {
				base: bld1Set.basePath,
				splits: {
					"split_config.arm64_v8a": bld1Set.splitPath,
				},
			},
		});

		expect(resolved.workflow?.id).toBe(wf.id);
		expect(resolved.baseline?.build_id).toBe("bld_1");
		expect(resolved.packageSet?.manifestSha256).toBe(bld1Set.manifestSha256);
		expect(resolved.packageSet?.setSha256).toBe(bld1Set.setSha256);

		// 2. resolvePackageSetInput enforces exact match against manifest (fails if split is missing)
		await expect(
			resolvePackageSetInput(tempDir, {
				base: bld1Set.basePath,
				splits: {}, // missing 'split_config.arm64_v8a'
			}),
		).rejects.toThrow(/missing from supplied splits map/);

		// 3. resolveActiveWorkflowBaseline throws immediately on invalid explicit packageSet
		await expect(
			resolveActiveWorkflowBaseline(tempDir, {
				packageSet: {
					base: bld1Set.basePath,
					splits: {
						non_existent: path.join(tempDir, "missing.apk"),
					},
				},
			}),
		).rejects.toThrow();
	});

	it("computes package set SHA-256 using strict ordinal sort identical to Python worker", () => {
		const members = [
			{ name: "config.arm64", sha256: "1111111111111111111111111111111111111111111111111111111111111111" },
			{ name: "Config.x86", sha256: "2222222222222222222222222222222222222222222222222222222222222222" },
			{ name: "_extra", sha256: "3333333333333333333333333333333333333333333333333333333333333333" },
			{ name: "base", sha256: "4444444444444444444444444444444444444444444444444444444444444444" },
		];
		// In ASCII ordinal: 'Config.x86' (0x43) < '_extra' (0x5F) < 'base' (0x62) < 'config.arm64' (0x63)
		const hash = computePackageSetSha256(members);
		const expectedPayload = [
			"Config.x86:2222222222222222222222222222222222222222222222222222222222222222",
			"_extra:3333333333333333333333333333333333333333333333333333333333333333",
			"base:4444444444444444444444444444444444444444444444444444444444444444",
			"config.arm64:1111111111111111111111111111111111111111111111111111111111111111",
		].join("\n");
		const expectedHash = require("node:crypto").createHash("sha256").update(expectedPayload, "utf8").digest("hex");
		expect(hash).toBe(expectedHash);
	});

	it("rejects non-base package_member when verifying against single non-manifest target", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-single-target-"));
		const singleApkPath = path.join(tempDir, "single.apk");
		await fs.writeFile(singleApkPath, await createSyntheticMemberApk({ dexBytes: Buffer.from([0x10, 0x20]) }));

		await expect(
			verifySourceOriginalBytes(singleApkPath, [
				{
					patch_id: "p1",
					package_member: "split_config.arm64_v8a",
					member_path: "classes.dex",
					offset: 0x50,
					original_bytes: "1020",
				},
			]),
		).rejects.toThrow(/Cannot access package member 'split_config.arm64_v8a' on non-package-set target/);
	});

	it("preserves single APK source isolation when unrelated package-set.json exists nearby", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-single-nearby-set-"));
		const store = new ReverseWorkflowStore({ repositoryRoot: tempDir });

		// 1. Create an unrelated package set in the directory
		await createSyntheticPackageSet(tempDir, "unrelated_set", {
			baseDexBytes: Buffer.from([0x99, 0x99, 0x99, 0x99]),
		});
		// Put a package-set.json in tempDir directly
		const unrelatedManifest = path.join(tempDir, "package-set.json");
		await fs.copyFile(path.join(tempDir, "unrelated_set", "package-set.json"), unrelatedManifest);

		// 2. Create single APK workflow targeting standalone app.apk
		const appApk = path.join(tempDir, "app.apk");
		await fs.writeFile(appApk, await createSyntheticMemberApk({ dexBytes: Buffer.from([0x10, 0x20]) }));

		const wf = await store.create({
			target: "app.apk",
			goal: "Single APK modification",
		});

		// 3. Register derivative for single APK with patch on classes.dex (0x50: 1020 -> 3040)
		const modApk = path.join(tempDir, "app_mod.apk");
		await fs.writeFile(modApk, await createSyntheticMemberApk({ dexBytes: Buffer.from([0x30, 0x40]) }));
		const modSha = await hashFileSha256(modApk);

		const d = await store.registerDerivative(wf.id, {
			build_id: "bld_single",
			target_path: "app_mod.apk",
			output_sha256: modSha,
			patches: [
				{
					patch_id: "patch_single",
					member_path: "classes.dex",
					offset: 0x50,
					original_bytes: "1020",
					expected_bytes: "3040",
				},
			],
		});

		expect(d.build_id).toBe("bld_single");
		expect(d.verification_result.status).toBe("verified");
	});

	it("supports first-derivative split patch registration from raw package-set workflow binding", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-raw-pkg-set-"));
		const store = new ReverseWorkflowStore({ repositoryRoot: tempDir });

		// Create raw member APKs without any package-set.json manifest
		const rawDir = path.join(tempDir, "raw_split_app");
		await fs.mkdir(rawDir, { recursive: true });
		const rawBase = path.join(rawDir, "base.apk");
		const rawSplit = path.join(rawDir, "split_config.arm64_v8a.apk");

		await fs.writeFile(rawBase, await createSyntheticMemberApk({ dexBytes: Buffer.from([0x10, 0x20]) }));
		await fs.writeFile(rawSplit, await createSyntheticMemberApk({ nativeBytes: Buffer.from([0xaa, 0xbb]) }));

		// Create workflow with metadata.package_set pointing to raw files
		const wf = await store.create({
			target: "raw_split_app/base.apk",
			goal: "Raw package set workflow without initial manifest",
			metadata: {
				package_set: {
					base: "raw_split_app/base.apk",
					splits: {
						"split_config.arm64_v8a": "raw_split_app/split_config.arm64_v8a.apk",
					},
				},
			},
		});

		// Repack produces first derivative with package-set.json and patch on split member
		const repackedSet = await createSyntheticPackageSet(tempDir, "dist_set", {
			baseDexBytes: Buffer.from([0x10, 0x20]),
			splitNativeBytes: Buffer.from([0xcc, 0xdd]),
		});

		const d = await store.registerDerivative(wf.id, {
			build_id: "bld_first_raw",
			target_path: "dist_set/package-set.json",
			output_sha256: repackedSet.manifestSha256,
			patches: [
				{
					patch_id: "patch_split_first",
					package_member: "split_config.arm64_v8a",
					member_path: "lib/arm64-v8a/libfoo.so",
					offset: 0x100,
					original_bytes: "aabb",
					expected_bytes: "ccdd",
				},
			],
		});

		expect(d.build_id).toBe("bld_first_raw");
		expect(d.verification_result.status).toBe("verified");
		expect(d.cumulative_patches.length).toBe(1);

		// Regression: mutate unpatched split in the original raw set on disk
		await fs.writeFile(rawSplit, Buffer.from("MUTATED_ORIGINAL_SPLIT_CONTENT"));

		// A subsequent zero-patch derivative derived from original clean base MUST fail
		const cleanZeroSet = await createSyntheticPackageSet(tempDir, "dist_zero", {
			baseDexBytes: Buffer.from([0x10, 0x20]),
		});

		await expect(
			store.registerDerivative(wf.id, {
				build_id: "bld_zero_replay",
				target_path: "dist_zero/package-set.json",
				output_sha256: cleanZeroSet.manifestSha256,
				parent_sha256: d.original_sha256,
			}),
		).rejects.toThrow(/Stale original base package set: aggregate SHA-256 drifted/);
	});

	it("rejects declared source_package_set when its base APK does not match workflow candidate base", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-raw-mismatch-"));
		const store = new ReverseWorkflowStore({ repositoryRoot: tempDir });

		const appApk = path.join(tempDir, "real_app.apk");
		await fs.writeFile(appApk, await createSyntheticMemberApk({ dexBytes: Buffer.from([0x10, 0x20]) }));

		const unrelatedApk = path.join(tempDir, "unrelated.apk");
		await fs.writeFile(unrelatedApk, await createSyntheticMemberApk({ dexBytes: Buffer.from([0x99, 0x99]) }));

		const splitApk = path.join(tempDir, "split.apk");
		await fs.writeFile(splitApk, await createSyntheticMemberApk({ nativeBytes: Buffer.from([0xaa, 0xbb]) }));

		const wf = await store.create({
			target: "real_app.apk",
			goal: "Test mismatched raw source base rejection",
		});

		const repackedSet = await createSyntheticPackageSet(tempDir, "dist_set");

		await expect(
			store.registerDerivative(wf.id, {
				build_id: "bld_fake_base",
				target_path: "dist_set/package-set.json",
				output_sha256: repackedSet.manifestSha256,
				patches: [
					{
						patch_id: "patch_split",
						package_member: "split",
						member_path: "lib/arm64-v8a/libfoo.so",
						offset: 0x100,
						original_bytes: "aabb",
						expected_bytes: "ccdd",
					},
				],
				metadata: {
					source_package_set: {
						base: unrelatedApk,
						splits: {
							split: splitApk,
						},
					},
				},
			}),
		).rejects.toThrow();

		const reloadedWf = await store.get(wf.id);
		expect(reloadedWf?.build_lineage?.length ?? 0).toBe(0);
	});

	it("supports subsequent derivative with source_package_set matching parent build output", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-parent-source-set-"));
		const store = new ReverseWorkflowStore({ repositoryRoot: tempDir });

		// 1. Initial base package set
		await createSyntheticPackageSet(tempDir, "base_set");
		const wf = await store.create({
			target: "base_set/package-set.json",
			goal: "Test parent source_package_set matching",
		});

		// 2. Build 1
		const bld1Set = await createSyntheticPackageSet(tempDir, "bld1_set", {
			baseDexBytes: Buffer.from([0x11, 0x22]),
		});
		await store.registerDerivative(wf.id, {
			build_id: "bld_1",
			target_path: "bld1_set/package-set.json",
			output_sha256: bld1Set.manifestSha256,
		});

		// 3. Build 2 passes source_package_set pointing to bld1_set files (NOT base_set)
		const bld2Set = await createSyntheticPackageSet(tempDir, "bld2_set", {
			baseDexBytes: Buffer.from([0x33, 0x44]),
		});

		const d2 = await store.registerDerivative(wf.id, {
			build_id: "bld_2",
			target_path: "bld2_set/package-set.json",
			output_sha256: bld2Set.manifestSha256,
			parent_build_id: "bld_1",
			metadata: {
				source_package_set: {
					base: bld1Set.basePath,
					splits: {
						"split_config.arm64_v8a": bld1Set.splitPath,
					},
				},
			},
		});

		expect(d2.build_id).toBe("bld_2");
		expect(d2.parent_sha256).toBe(bld1Set.manifestSha256);
		expect(d2.verification_result.status).toBe("verified");
	});

	it("rejects incomplete publication directory with ownership token missing manifest", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-incomplete-pub-"));
		const pubDir = path.join(tempDir, "incomplete_dist");
		await fs.mkdir(pubDir, { recursive: true });

		const baseApk = path.join(pubDir, "base.apk");
		await fs.writeFile(baseApk, await createSyntheticMemberApk({ dexBytes: Buffer.from([0x10, 0x20]) }));

		// Ownership token present, but package-set.json absent
		await fs.writeFile(path.join(pubDir, ".apk_ownership_token"), "token_123");

		await expect(
			resolvePackageSetInput(tempDir, {
				base: baseApk,
				splits: {},
			}),
		).rejects.toThrow(/Incomplete package set publication/);
	});

	it("detects member mutation in zero-patch derivative even when manifest target is a symlink", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-symlink-manifest-"));
		const store = new ReverseWorkflowStore({ repositoryRoot: tempDir });

		await createSyntheticPackageSet(tempDir, "base_set");
		const wf = await store.create({
			target: "base_set/package-set.json",
			goal: "Test symlink manifest verification",
		});

		const bldSet = await createSyntheticPackageSet(tempDir, "bld_set");
		await store.registerDerivative(wf.id, {
			build_id: "bld_zero",
			target_path: "bld_set/package-set.json",
			output_sha256: bldSet.manifestSha256,
		});

		// Create a symlink pointing to package-set.json
		const symlinkPath = path.join(bldSet.dir, "symlink-package-set.json");
		await fs.symlink(bldSet.manifestPath, symlinkPath);

		// Mutate a member APK on disk
		await fs.writeFile(bldSet.splitPath, Buffer.from("MUTATED_SPLIT_VIA_SYMLINK"));

		// verifyDerivative via symlink target MUST fail, catching member hash drift
		const res = await store.verifyDerivative(wf.id, "bld_zero", symlinkPath);
		expect(res.status).toBe("failed");
		expect(res.failure_reason).toMatch(/SHA-256 mismatch|size mismatch/);
	});
});
