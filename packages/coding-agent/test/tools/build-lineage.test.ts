import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { encodeArchive } from "@reverse/utils/ar";
import { Settings } from "@reverse/coding-agent/config/settings";
import { EvidenceStore } from "@reverse/coding-agent/evidence/store";
import {
	ReverseWorkflowStore,
	formatBuildLineageContext,
	hashFileSha256,
} from "@reverse/coding-agent/reverse-workflow";
import { ReverseWorkflowTool, type ToolSession } from "@reverse/coding-agent/tools";

function createTestSession(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
	};
}

async function createSyntheticApk(options: {
	nativeBytes?: Buffer;
	dexBytes?: Buffer;
}): Promise<Uint8Array> {
	const manifest = Buffer.from("<manifest package=\"com.example.app\"/>", "utf8");

	const nativeSo = Buffer.alloc(512, 0);
	if (options.nativeBytes) {
		options.nativeBytes.copy(nativeSo, 0x100);
	}

	const classesDex = Buffer.alloc(1024, 0);
	if (options.dexBytes) {
		options.dexBytes.copy(classesDex, 0x200);
	}

	return await encodeArchive("zip", [
		["AndroidManifest.xml", manifest],
		["classes.dex", classesDex],
		["lib/arm64-v8a/libnative.so", nativeSo],
	]);
}

describe("Issue #10: Durable Build Artifact Lineage & Cumulative Patch Verification", () => {
	it("enforces complete lineage invariants across derivatives, replay, tampering, and recovery", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-lineage-test-"));
		const session = createTestSession(tempDir);
		const workflowTool = new ReverseWorkflowTool(session);
		const evidenceStore = new EvidenceStore({ repositoryRoot: tempDir });

		// 1. Setup clean synthetic base APK
		const baseApkPath = path.join(tempDir, "base.apk");
		await fs.writeFile(baseApkPath, await createSyntheticApk({}));
		const baseSha256 = await hashFileSha256(baseApkPath);

		// Initialize workflow
		const createRes = await workflowTool.execute("call_1", {
			action: "create",
			target: "base.apk",
			goal: "Analyze and patch native condition check",
		});
		const workflowId = createRes.details.workflow!.id;
		expect(workflowId).toBeDefined();

		// -------------------------------------------------------------------------
		// Invariant 1: A verified
		// -------------------------------------------------------------------------
		// Mod 1 applies Patch A (NOP: 1f2003d5) at offset 0x100 of libnative.so
		const mod1ApkPath = path.join(tempDir, "mod1.apk");
		const patchABytes = Buffer.from([0x1f, 0x20, 0x03, 0xd5]);
		await fs.writeFile(mod1ApkPath, await createSyntheticApk({ nativeBytes: patchABytes }));
		const mod1Sha256 = await hashFileSha256(mod1ApkPath);

		const regMod1Res = await workflowTool.execute("call_2", {
			action: "register_derivative",
			workflow_id: workflowId,
			target: "mod1.apk",
			build_id: "mod1",
			patches: [
				{
					patch_id: "patch_A",
					member_path: "lib/arm64-v8a/libnative.so",
					offset: 0x100,
					original_bytes: "00000000",
					expected_bytes: "1f2003d5",
				},
			],
			signature_status: "unsigned",
		});

		expect(regMod1Res.details.derivative).toBeDefined();
		expect(regMod1Res.details.derivative!.build_id).toBe("mod1");
		expect(regMod1Res.details.derivative!.output_sha256).toBe(mod1Sha256);
		expect(regMod1Res.details.derivative!.verification_result.static_status).toBe("verified");
		expect(regMod1Res.details.derivative!.verification_result.runtime_status).toBe("pending");

		// Verify lineage re-check action
		const verifyMod1 = await workflowTool.execute("call_3", {
			action: "verify_lineage",
			workflow_id: workflowId,
			build_id: "mod1",
		});
		expect(verifyMod1.details.verification_result?.static_status).toBe("verified");

		// -------------------------------------------------------------------------
		// Invariant 2: B on A retains A
		// -------------------------------------------------------------------------
		// Mod 2 is built on Mod 1: retains Patch A in libnative.so and adds Patch B in classes.dex
		const mod2ApkPath = path.join(tempDir, "mod2.apk");
		const patchBBytes = Buffer.from([0x10, 0x01]);
		await fs.writeFile(
			mod2ApkPath,
			await createSyntheticApk({ nativeBytes: patchABytes, dexBytes: patchBBytes }),
		);
		const mod2Sha256 = await hashFileSha256(mod2ApkPath);

		const regMod2Res = await workflowTool.execute("call_4", {
			action: "register_derivative",
			workflow_id: workflowId,
			target: "mod2.apk",
			build_id: "mod2",
			parent_build_id: "mod1",
			patches: [
				{
					patch_id: "patch_B",
					member_path: "classes.dex",
					offset: 0x200,
					original_bytes: "0000",
					expected_bytes: "1001",
				},
			],
			signature_status: "unsigned",
		});

		expect(regMod2Res.details.derivative!.verification_result.static_status).toBe("verified");
		const mod2Cumulative = regMod2Res.details.derivative!.cumulative_patches;
		expect(mod2Cumulative).toHaveLength(2);
		expect(mod2Cumulative.find(p => p.patch_id === "patch_A")?.status).toBe("active");
		expect(mod2Cumulative.find(p => p.patch_id === "patch_B")?.status).toBe("active");

		// Check status action surfaces current baseline
		const statusRes = await workflowTool.execute("call_5", {
			action: "status",
			workflow_id: workflowId,
		});
		expect(statusRes.details.baseline?.build_id).toBe("mod2");

		// -------------------------------------------------------------------------
		// Invariant 3: rejected broken B-from-original missing A
		// (Core Issue #10 bug: unpacking clean base and replacing only DEX drops native patch A)
		// -------------------------------------------------------------------------
		const brokenModPath = path.join(tempDir, "mod5_broken.apk");
		// Native bytes are clean 00000000 (missing Patch A!), DEX has patch B
		await fs.writeFile(
			brokenModPath,
			await createSyntheticApk({ dexBytes: patchBBytes }),
		);

		await expect(
			workflowTool.execute("call_6", {
				action: "register_derivative",
				workflow_id: workflowId,
				target: "mod5_broken.apk",
				build_id: "mod5_broken",
				parent_sha256: baseSha256, // Attempting to use original base as parent
				patches: [
					{
						patch_id: "patch_B",
						member_path: "classes.dex",
						offset: 0x200,
						original_bytes: "0000",
						expected_bytes: "1001",
					},
				],
			}),
		).rejects.toThrow();
		const store = new ReverseWorkflowStore({ repositoryRoot: tempDir });
		expect(await store.getDerivative(workflowId, "mod5_broken")).toBeNull();
		expect((await store.getBaseline(workflowId))?.build_id).toBe("mod2");

		// -------------------------------------------------------------------------
		// Invariant 4: deterministic replay A+B accepted
		// (Allowed to replay full active patchset from clean original)
		// -------------------------------------------------------------------------
		const replayApkPath = path.join(tempDir, "mod_replayed.apk");
		await fs.writeFile(
			replayApkPath,
			await createSyntheticApk({ nativeBytes: patchABytes, dexBytes: patchBBytes }),
		);

		const regReplayRes = await workflowTool.execute("call_7", {
			action: "register_derivative",
			workflow_id: workflowId,
			target: "mod_replayed.apk",
			build_id: "mod_replayed",
			parent_sha256: baseSha256, // Declared replay from clean original base
		});

		expect(regReplayRes.details.derivative!.verification_result.static_status).toBe("verified");
		expect(regReplayRes.details.derivative!.parent_sha256).toBe(baseSha256);
		expect(regReplayRes.details.derivative!.cumulative_patches).toHaveLength(2);

		// -------------------------------------------------------------------------
		// Invariant 5: explicit retirement with reason
		// -------------------------------------------------------------------------
		// Explicitly retire patch_A with reason
		const retireRes = await workflowTool.execute("call_8", {
			action: "retire_patch",
			workflow_id: workflowId,
			patch_id: "patch_A",
			reason: "Native condition bypassed by dex logic in mod3",
		});
		expect(retireRes.details.retirement_audit?.patch_id).toBe("patch_A");

		// Build mod3 without patch_A (native reverted to clean 00000000, DEX has patch_B)
		const mod3ApkPath = path.join(tempDir, "mod3.apk");
		await fs.writeFile(
			mod3ApkPath,
			await createSyntheticApk({ dexBytes: patchBBytes }),
		);

		const regMod3Res = await workflowTool.execute("call_9", {
			action: "register_derivative",
			workflow_id: workflowId,
			target: "mod3.apk",
			build_id: "mod3",
		});

		expect(regMod3Res.details.derivative!.verification_result.static_status).toBe("verified");
		const mod3Patches = regMod3Res.details.derivative!.cumulative_patches;
		const patchARecord = mod3Patches.find(p => p.patch_id === "patch_A");
		expect(patchARecord?.status).toBe("retired");
		expect(patchARecord?.retirement_reason).toBe("Native condition bypassed by dex logic in mod3");

		// Verify historical immutability: mod1 in workflow still retains patch_A as active!
		// store is already defined above
		const historicalMod1 = await store.getDerivative(workflowId, "mod1");
		expect(historicalMod1?.cumulative_patches.find(p => p.patch_id === "patch_A")?.status).toBe("active");

		// -------------------------------------------------------------------------
		// Invariant 6: source/output tamper rejects
		// -------------------------------------------------------------------------
		// Declaring an incorrect output_sha256 rejects registration
		await expect(
			workflowTool.execute("call_10", {
				action: "register_derivative",
				workflow_id: workflowId,
				target: "mod3.apk",
				build_id: "tampered_output",
				output_sha256: "0000000000000000000000000000000000000000000000000000000000000000",
			}),
		).rejects.toThrow();
		expect(await store.getDerivative(workflowId, "tampered_output")).toBeNull();

		// Tampering with the source parent file on disk causes drift rejection
		const tamperedMod1 = Buffer.from(await fs.readFile(mod1ApkPath));
		tamperedMod1[0] = 0xff; // Corrupt first byte
		await fs.writeFile(mod1ApkPath, tamperedMod1);

		await expect(
			workflowTool.execute("call_11", {
				action: "register_derivative",
				workflow_id: workflowId,
				target: "mod2.apk",
				build_id: "new_on_tampered_parent",
				parent_build_id: "mod1",
			}),
		).rejects.toThrow();
		expect(await store.getDerivative(workflowId, "new_on_tampered_parent")).toBeNull();

		// Restore mod1
		await fs.writeFile(mod1ApkPath, await createSyntheticApk({ nativeBytes: patchABytes }));
		// Attempting replay from original when base file is missing rejects
		const baseBackup = Buffer.from(await fs.readFile(baseApkPath));
		await fs.unlink(baseApkPath);
		await expect(
			workflowTool.execute("call_11b", {
				action: "register_derivative",
				workflow_id: workflowId,
				target: "mod_replayed.apk",
				build_id: "replay_missing_base",
				parent_sha256: baseSha256,
			}),
		).rejects.toThrow();
		expect(await store.getDerivative(workflowId, "replay_missing_base")).toBeNull();
		await fs.writeFile(baseApkPath, baseBackup);

		// -------------------------------------------------------------------------
		// Invariant 7: older hash runtime evidence not inherited
		// -------------------------------------------------------------------------
		// Record hypothesis & conclusion for mod1
		const hyp = await evidenceStore.addHypothesis({
			kind: "hypothesis",
			claim: "Cold boot succeeds with native condition NOPed",
			verificationPlan: "Observe logcat ColdBoot Complete",
			target: "mod1.apk",
		});

		const concMod1 = await evidenceStore.verifyHypothesis({
			hypothesisId: hyp.id,
			method: "cold_boot_trace",
			command: "am start -W com.example.app",
			result: "Success",
			conclusion: "Cold boot observed successfully on mod1",
			status: "verified",
			target: "mod1.apk",
			targetSha256: mod1Sha256, // Bound to mod1
		});

		// Attempting to bind mod1 runtime evidence to mod2 (which has mod2Sha256) rejects
		await expect(
			workflowTool.execute("call_12", {
				action: "register_derivative",
				workflow_id: workflowId,
				target: "mod2.apk",
				build_id: "mod2_with_old_evidence",
				runtime_evidence_ids: [concMod1.id],
			}),
		).rejects.toThrow();
		expect(await store.getDerivative(workflowId, "mod2_with_old_evidence")).toBeNull();

		// Valid evidence bound to mod2's exact output hash promotes runtime_status to verified
		const concMod2 = await evidenceStore.verifyHypothesis({
			hypothesisId: hyp.id,
			method: "cold_boot_trace",
			command: "am start -W com.example.app",
			result: "Success on mod2",
			conclusion: "Cold boot observed on mod2",
			status: "verified",
			target: "mod2.apk",
			targetSha256: mod2Sha256, // Exact hash match
		});

		const regMod2WithEv = await workflowTool.execute("call_13", {
			action: "register_derivative",
			workflow_id: workflowId,
			target: "mod2.apk",
			build_id: "mod2_verified_runtime",
			runtime_evidence_ids: [concMod2.id],
		});
		expect(regMod2WithEv.details.derivative!.verification_result.runtime_status).toBe("verified");

		// -------------------------------------------------------------------------
		// Invariant 8: reopen store / session compaction restores baseline
		// -------------------------------------------------------------------------
		// Fresh store instance simulating new session or post-compaction reload
		const reopenedStore = new ReverseWorkflowStore({ repositoryRoot: tempDir });
		const baselineAfterReopen = await reopenedStore.getBaseline(workflowId);
		expect(baselineAfterReopen).not.toBeNull();
		expect(baselineAfterReopen!.build_id).toBe("mod2_verified_runtime");
		expect(baselineAfterReopen!.output_sha256).toBe(mod2Sha256);

		// Verify compaction recovery context helper produces pure manifest metadata
		const contextText = await formatBuildLineageContext(tempDir);
		expect(contextText).toBeDefined();
		expect(contextText).toContain("Reverse Workflow Verified Lineage & Baseline Manifest");
		expect(contextText).toContain(workflowId);
		expect(contextText).toContain("mod2_verified_runtime");
		expect(contextText).toContain(mod2Sha256);

		// Clean up
		await fs.rm(tempDir, { recursive: true, force: true });
	});
});
