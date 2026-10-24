import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { EvidenceStore } from "../src/evidence/store";
import { ReverseKnowledgeStore } from "../src/reverse-knowledge/store";
import { createKnowledgeId } from "../src/reverse-knowledge/contracts";
import { validateVerifiedOnly, learnFromEvidenceAndWorkflows, applyKnowledge } from "../src/reverse-knowledge/service";
import { ReverseWorkflowStore } from "../src/reverse-workflow/store";
import { generateFindingsData, generateFindingsMarkdown } from "../src/reverse-workspace/findings";

describe("EvidenceAssurance - Closed #6 evidentiary rigor & refutation cascade", () => {
	it("rejects verified conclusion claiming independent_reproduction backed only by startmarker dynamic_call_observation", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ev-assurance-startmarker-"));
		try {
			const store = new EvidenceStore({ repositoryRoot: tempDir, stateRoot: tempDir });

			// 0. Attempting high assurance with zero supporting facts must fail
			const hypEmpty = await store.addHypothesis({
				kind: "hypothesis",
				claim: "Independent crypto implementation verified",
				verificationPlan: "None",
			});
			await expect(
				store.verifyHypothesis({
					hypothesisId: hypEmpty.id,
					method: "pure assertion",
					command: "echo verified",
					result: "looks good",
					conclusion: "Crypto independent reproduction without facts",
					status: "verified",
					assurance: "independent_reproduction",
				}),
			).rejects.toThrow("without supporting evidence facts");

			// 1. Fact: Logcat WirelessSDKSign start observed
			const fact = await store.addFact({
				kind: "fact",
				sourceTool: "logcat",
				locator: "WirelessSDK:main",
				content: "Observed WirelessSDKSign start marker in log stream",
				subject: "wireless_sdk_sign",
				assurance: "dynamic_call_observation",
			});

			// 2. Hypothesis: WirelessSDK.sign succeeds
			const hyp = await store.addHypothesis({
				kind: "hypothesis",
				claim: "WirelessSDK.sign succeeds and is accepted by remote server",
				verificationPlan: "Hook native function and observe execution",
				subject: "wireless_sdk_sign",
				facts: [fact.id],
			});

			// 3. Attempting to claim independent_reproduction backed only by dynamic_call_observation must fail
			await expect(
				store.verifyHypothesis({
					hypothesisId: hyp.id,
					method: "logcat scan",
					command: "logcat -d",
					result: "WirelessSDKSign start seen",
					conclusion: "WirelessSDK signing algorithm verified independent reproduction",
					status: "verified",
					assurance: "independent_reproduction",
				}),
			).rejects.toThrow("Evidence records do not meet minimum assurance tier 'independent_reproduction'");

			// 4. Verifying at dynamic_call_observation level succeeds
			const conc = await store.verifyHypothesis({
				hypothesisId: hyp.id,
				method: "logcat scan",
				command: "logcat -d",
				result: "WirelessSDKSign start seen",
				conclusion: "WirelessSDK signing invocation confirmed started",
				status: "verified",
				assurance: "dynamic_call_observation",
			});

			expect(conc.status).toBe("verified");
			expect(conc.context?.assurance).toBe("dynamic_call_observation");
			expect(conc.reproducibility).toBe("not specified");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("rejects verified conclusion when compound command stages failed with nonzero exit code", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ev-assurance-failed-stage-"));
		try {
			const store = new EvidenceStore({ repositoryRoot: tempDir, stateRoot: tempDir });

			const hyp = await store.addHypothesis({
				kind: "hypothesis",
				claim: "App boots into instrumented hook environment",
				verificationPlan: "adb install && am start && pidof",
			});

			// Outer envelope might say succeeded or return rc, but internal stage failed (am start rc 1)
			await expect(
				store.verifyHypothesis({
					hypothesisId: hyp.id,
					method: "adb compound launch",
					command: "adb install app.apk && adb shell am start && adb shell pidof",
					result: "Command ran with partial failure",
					conclusion: "App started successfully",
					status: "verified",
					compoundStages: [
						{ stage: "install", exitCode: 0, status: "success" },
						{ stage: "am_start", exitCode: 1, status: "failed", stderr: "FATAL EXCEPTION in PID 32936" },
					],
				}),
			).rejects.toThrow("compound command stage 'am_start' failed with exit code 1");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("rejects verified conclusion when target artifact SHA-256 mismatches or is missing", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ev-assurance-hash-mismatch-"));
		try {
			const store = new EvidenceStore({ repositoryRoot: tempDir, stateRoot: tempDir });

			const factOld = await store.addFact({
				kind: "fact",
				sourceTool: "apk_build",
				locator: "build/mod1.apk",
				content: "Built modified apk mod1",
				executionBinding: {
					artifactSha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				},
			});

			const hypNew = await store.addHypothesis({
				kind: "hypothesis",
				claim: "Runtime signature validation passes for mod2",
				verificationPlan: "cold boot and log inspection",
				facts: [factOld.id],
				executionBinding: {
					artifactSha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				},
			});

			// Hypothesis claims mod2 (bbbb...), but supporting fact is mod1 (aaaa...)
			await expect(
				store.verifyHypothesis({
					hypothesisId: hypNew.id,
					method: "cold boot trace",
					command: "am start",
					result: "booted",
					conclusion: "Verified on mod2",
					status: "verified",
				}),
			).rejects.toThrow("Evidence records do not match required target SHA-256");

			// Fact with missing hash when targetSha256 is required also fails
			const factNoHash = await store.addFact({
				kind: "fact",
				sourceTool: "generic",
				locator: "loc",
				content: "Untracked build",
			});
			const hypWithFactNoHash = await store.addHypothesis({
				kind: "hypothesis",
				claim: "Runtime signature validation",
				verificationPlan: "cold boot",
				facts: [factNoHash.id],
				executionBinding: {
					artifactSha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				},
			});
			await expect(
				store.verifyHypothesis({
					hypothesisId: hypWithFactNoHash.id,
					method: "cold boot trace",
					command: "am start",
					result: "booted",
					conclusion: "Verified on mod2",
					status: "verified",
				}),
			).rejects.toThrow("Evidence records do not match required target SHA-256");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("rejects verified conclusion when subject mismatches or is missing when required", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ev-assurance-subject-mismatch-"));
		try {
			const store = new EvidenceStore({ repositoryRoot: tempDir, stateRoot: tempDir });

			const factUi = await store.addFact({
				kind: "fact",
				sourceTool: "ui_interaction",
				locator: "desktop_client:window",
				content: "Message sent through official PC UI",
				subject: "official_client_ui",
			});

			const hypProtocol = await store.addHypothesis({
				kind: "hypothesis",
				claim: "Independent LWP protocol cross-account sending verified",
				verificationPlan: "send packet via standalone protocol client",
				subject: "independent_protocol",
				facts: [factUi.id],
			});

			await expect(
				store.verifyHypothesis({
					hypothesisId: hypProtocol.id,
					method: "packet capture",
					command: "tcpdump -i any",
					result: "packet seen",
					conclusion: "Cross account sending verified 100%",
					status: "verified",
					subject: "independent_protocol",
				}),
			).rejects.toThrow("Evidence records do not match required subject 'independent_protocol'");

			// Fact with missing subject when subject is required must fail
			const factNoSubject = await store.addFact({
				kind: "fact",
				sourceTool: "untyped",
				locator: "unknown",
				content: "Generic untyped observation",
			});
			const hypRequiresSubject = await store.addHypothesis({
				kind: "hypothesis",
				claim: "Protocol verified",
				verificationPlan: "packet test",
				subject: "independent_protocol",
				facts: [factNoSubject.id],
			});
			await expect(
				store.verifyHypothesis({
					hypothesisId: hypRequiresSubject.id,
					method: "packet capture",
					command: "tcpdump",
					result: "captured",
					conclusion: "Protocol verified",
					status: "verified",
					subject: "independent_protocol",
				}),
			).rejects.toThrow("Evidence records do not match required subject 'independent_protocol'");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("distinguishes universal absence requiring exhaustive search from bounded negative observation", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ev-assurance-negative-scope-"));
		try {
			const store = new EvidenceStore({ repositoryRoot: tempDir, stateRoot: tempDir });

			const hyp = await store.addHypothesis({
				kind: "hypothesis",
				claim: "sessionViewId parameter does not exist on PC client",
				verificationPlan: "grep logcat tail",
			});

			// 1. Claiming universal absence with non-exhaustive search is strictly rejected
			await expect(
				store.verifyHypothesis({
					hypothesisId: hyp.id,
					method: "logcat tail scan",
					command: "logcat | tail -n 50 | grep sessionViewId",
					result: "no matches found",
					conclusion: "sessionViewId is mobile-only and completely absent on PC",
					status: "verified",
					claimScope: "universal",
					negativeScope: {
						searchTarget: "logcat_window",
						query: "sessionViewId",
						scopeBoundary: "tail_50_lines",
						isExhaustive: false,
					},
				}),
			).rejects.toThrow("negative search scope on 'logcat_window' must be exhaustive");

			// 2. Bounded observation ('not observed in this logcat window') is completely valid and recordable
			const boundedConc = await store.verifyHypothesis({
				hypothesisId: hyp.id,
				method: "logcat tail scan",
				command: "logcat | tail -n 50 | grep sessionViewId",
				result: "no matches found in last 50 lines",
				conclusion: "sessionViewId not observed in the recent 50-line logcat tail window",
				status: "verified",
				claimScope: "bounded",
				negativeScope: {
					searchTarget: "logcat_window",
					query: "sessionViewId",
					scopeBoundary: "tail_50_lines",
					isExhaustive: false,
					claimScope: "bounded",
				},
			});
			expect(boundedConc.status).toBe("verified");
			expect(boundedConc.context?.negativeScope?.isExhaustive).toBe(false);
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("evaluateEvidenceSupport boundary checks: empty ids, unverified hypotheses, unknowns, permitted kinds", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ev-assurance-eval-boundaries-"));
		try {
			const store = new EvidenceStore({ repositoryRoot: tempDir, stateRoot: tempDir });

			// 1. Empty IDs must return valid: false
			const evalEmpty = await store.evaluateSupport([]);
			expect(evalEmpty.valid).toBe(false);
			expect(evalEmpty.reason).toContain("No evidence records provided");

			// 2. Unverified pending hypothesis cannot satisfy as verified proof
			const pendingHyp = await store.addHypothesis({
				kind: "hypothesis",
				claim: "Unverified theoretical assertion",
				verificationPlan: "None yet",
			});
			const evalPending = await store.evaluateSupport([pendingHyp.id]);
			expect(evalPending.valid).toBe(false);
			expect(evalPending.unverifiedIds).toContain(pendingHyp.id);

			// 3. Unknown cannot satisfy as verified proof
			const unknownRec = await store.addUnknown({
				kind: "unknown",
				question: "What is this encryption key?",
			});
			const evalUnknown = await store.evaluateSupport([unknownRec.id]);
			expect(evalUnknown.valid).toBe(false);
			expect(evalUnknown.unverifiedIds).toContain(unknownRec.id);

			// 4. Permitted kinds enforcement
			const factRec = await store.addFact({
				kind: "fact",
				sourceTool: "strings",
				locator: "offset:0x1000",
				content: "Found string /api/v1/auth",
			});
			// Requiring conclusion kind only rejects fact
			const evalKinds = await store.evaluateSupport([factRec.id], {
				requiredKinds: ["conclusion"],
			});
			expect(evalKinds.valid).toBe(false);
			expect(evalKinds.unmetKindIds).toContain(factRec.id);

			// 5. Requiring exhaustive negative scope fails if record lacks exhaustive negative scope
			const evalNegReq = await store.evaluateSupport([factRec.id], {
				requireExhaustiveNegative: true,
			});
			expect(evalNegReq.valid).toBe(false);
			expect(evalNegReq.nonExhaustiveNegativeIds).toContain(factRec.id);
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});
	it("validateVerifiedOnly flags evidence with failed compound stages as unverified and invalid", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ev-assurance-failed-stage-kn-"));
		try {
			const store = new EvidenceStore({ repositoryRoot: tempDir, stateRoot: tempDir });

			// Raw fact with failed stage
			const factFailedStage = await store.addFact({
				kind: "fact",
				sourceTool: "bash",
				locator: "script.sh",
				content: "Ran build script with failure",
				compoundStages: [{ stage: "build", exitCode: 1, status: "failed" }],
			});

			const validation = await validateVerifiedOnly(
				{
					title: "Faulty Pattern",
					kind: "verified_conclusion",
					target_format: "APK",
					source_evidence_ids: [factFailedStage.id],
					summary: "Pattern from failed command",
				},
				store,
			);
			expect(validation.unverified).toBe(true);
			expect(validation.invalidEvidenceIds).toContain(factFailedStage.id);
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("propagates refutation cascade across ledger: subsequent refutation marks earlier verified conclusion stale", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ev-assurance-cascade-"));
		try {
			const store = new EvidenceStore({ repositoryRoot: tempDir, stateRoot: tempDir });
			const knStore = new ReverseKnowledgeStore({ repositoryRoot: tempDir });

			// 1. Hypothesis: Java native signature binding works
			const hyp = await store.addHypothesis({
				kind: "hypothesis",
				claim: "Java native signature binding is functional",
				verificationPlan: "Load library and check return",
			});

			// 2. Conclusion 1: Verified (seen start marker or non-null return)
			const conc1 = await store.verifyHypothesis({
				hypothesisId: hyp.id,
				method: "frida hook",
				command: "frida -f com.app",
				result: "WirelessSDKSign returned end0",
				conclusion: "Native signing functional",
				status: "verified",
			});

			// Initial state: conc1 is verified, hyp is verified
			const evalBefore = await store.evaluateSupport([conc1.id, hyp.id]);
			expect(evalBefore.valid).toBe(true);

			// Retain knowledge based on conc1
			await validateVerifiedOnly(
				{
					title: "Native Signing Pattern",
					kind: "verified_conclusion",
					target_format: "APK",
					source_evidence_ids: [conc1.id],
					summary: "Functional native signature",
				},
				store,
			);

			const retainedKnId = createKnowledgeId();
			await knStore.save({
				id: retainedKnId,
				kind: "verified_conclusion",
				title: "Native Signing Pattern",
				target_format: "APK",
				confidence: "high",
				source_evidence_ids: [conc1.id],
				summary: "Functional native signature",
				created_at: new Date().toISOString(),
				updated_at: new Date().toISOString(),
			});

			// 3. New test reveals UnsatisfiedLinkError / Server rejection: Refuting the hypothesis!
			const conc2 = await store.verifyHypothesis({
				hypothesisId: hyp.id,
				method: "server replay",
				command: "python replay.py",
				result: "Server returned ERR_INVALID_SIGN -102",
				conclusion: "Signature is rejected by server; native binding invalid",
				status: "refuted",
			});

			// 4. Canonical validity resolver now sees:
			// - hyp is REFUTED
			// - conc2 is REFUTED
			// - conc1 is STALE / SUPERSEDED
			const validityMap = await store.resolveValidity();
			expect(validityMap.get(hyp.id)?.effectiveStatus).toBe("refuted");
			expect(validityMap.get(conc2.id)?.effectiveStatus).toBe("refuted");
			expect(validityMap.get(conc1.id)?.effectiveStatus).toBe("stale");
			expect(validityMap.get(conc1.id)?.isValid).toBe(false);

			// 5. evaluateEvidenceSupport strictly rejects conc1 and hyp
			const evalConc1 = await store.evaluateSupport([conc1.id]);
			expect(evalConc1.valid).toBe(false);
			expect(evalConc1.staleIds).toContain(conc1.id);

			const evalHyp = await store.evaluateSupport([hyp.id]);
			expect(evalHyp.valid).toBe(false);
			expect(evalHyp.refutedIds).toContain(hyp.id);

			// 6. Knowledge store audit flags the retained knowledge as stale_evidence!
			const audit = await knStore.audit({ mark_stale: true }, store);
			expect(audit.stale_records).toBeGreaterThan(0);
			const finding = audit.findings.find(f => f.record_id === retainedKnId);
			expect(finding).toBeDefined();
			expect(finding?.type).toBe("stale_evidence");

			// 7. validateVerifiedOnly refuses promoting unverified hypothesis
			await expect(
				validateVerifiedOnly(
					{
						title: "Another Knowledge",
						kind: "verified_conclusion",
						target_format: "APK",
						source_evidence_ids: [hyp.id],
						summary: "Stale claim",
					},
					store,
				),
			).rejects.toThrow("Cannot promote unverified hypothesis");

			// 8. learnFromEvidenceAndWorkflows skips conc1 and does not promote it
			const wfStore = new ReverseWorkflowStore({ repositoryRoot: tempDir });
			const learnRes = await learnFromEvidenceAndWorkflows(store, wfStore, knStore);
			expect(learnRes.learned_conclusions).toBe(0);

			// 9. reverse-workspace findings export excludes conc1 from Ironclad Proof
			const findings = generateFindingsData(
				{
					id: "wf_1",
					format: "APK",
					status: "active",
					goal: "Test goal",
					target: "test.apk",
					steps: [],
					created_at: "",
					updated_at: "",
				},
				[
					{ id: conc1.id, record: conc1 },
					{ id: conc2.id, record: conc2 },
					{ id: hyp.id, record: hyp },
				],
				{ name: "test.apk", format: "APK", path: "test.apk", is_reference: true, inspected_at: "" },
			);

			// Hypotheses should be in unverified_hypotheses, not verified_hypotheses
			expect(findings.verified_hypotheses.length).toBe(0);
			expect(findings.unverified_hypotheses.length).toBe(1);

			// Conclusions status in findings should mark conc1 as refuted/superseded
			const conc1Summary = findings.conclusions.find(c => c.id === conc1.id);
			expect(conc1Summary?.status).toBe("refuted");

			// Markdown should not list conc1 under Ironclad Proof
			const md = generateFindingsMarkdown(
				{
					id: "wf_1",
					format: "APK",
					status: "active",
					goal: "Test goal",
					target: "test.apk",
					steps: [],
					created_at: "",
					updated_at: "",
				},
				[
					{ id: conc1.id, record: conc1 },
					{ id: conc2.id, record: conc2 },
					{ id: hyp.id, record: hyp },
				],
				{ name: "test.apk", format: "APK", path: "test.apk", is_reference: true, inspected_at: "" },
			);
			expect(md).toContain("## 2b. Refuted / Superseded Hypotheses & Conclusions");
			expect(md).toContain(`[REFUTED / SUPERSEDED] ${conc1.id}`);
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("validates quantitative ratio denominator > 0 and rejects denominator 0 or negative units", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ev-assurance-ratio-"));
		try {
			const store = new EvidenceStore({ repositoryRoot: tempDir, stateRoot: tempDir });

			await expect(
				store.addFact({
					kind: "fact",
					sourceTool: "unit_test",
					locator: "suite:1",
					content: "Ratio check",
					completionRatio: {
						verifiedUnits: 5,
						totalRequiredUnits: 0, // Invalid denominator
					},
				}),
			).rejects.toThrow("totalRequiredUnits' must be a positive integer > 0");

			await expect(
				store.addFact({
					kind: "fact",
					sourceTool: "unit_test",
					locator: "suite:1",
					content: "Ratio check",
					completionRatio: {
						verifiedUnits: 10,
						totalRequiredUnits: 5, // Verified > Total
					},
				}),
			).rejects.toThrow("cannot exceed 'totalRequiredUnits'");

			// Valid ratio
			const fact = await store.addFact({
				kind: "fact",
				sourceTool: "unit_test",
				locator: "suite:1",
				content: "Ratio check",
				completionRatio: {
					verifiedUnits: 5,
					totalRequiredUnits: 5,
					unitDescription: "trials",
				},
			});
			expect(fact.context?.completionRatio?.verifiedUnits).toBe(5);
			expect(fact.context?.completionRatio?.totalRequiredUnits).toBe(5);
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});
	it("rejects conflicting target file hash and execution artifact hash on creation", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ev-assurance-conflict-hash-"));
		try {
			const targetFile = path.join(tempDir, "sample.bin");
			await fs.writeFile(targetFile, "target-file-content");
			const store = new EvidenceStore({ repositoryRoot: tempDir, stateRoot: tempDir });

			await expect(
				store.addFact({
					kind: "fact",
					sourceTool: "r2",
					locator: "entry0",
					content: "Entrypoint",
					target: "sample.bin",
					executionBinding: {
						artifactSha256: "1111111111111111111111111111111111111111111111111111111111111111",
					},
				}),
			).rejects.toThrow("Conflicting target file hash");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("rejects rebinding hypothesis subject or hash during verification", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ev-assurance-rebind-"));
		try {
			const store = new EvidenceStore({ repositoryRoot: tempDir, stateRoot: tempDir });

			const fact1 = await store.addFact({
				kind: "fact",
				sourceTool: "triage",
				locator: "loc",
				content: "auth observation",
				subject: "auth_v1",
			});

			const hyp = await store.addHypothesis({
				kind: "hypothesis",
				claim: "Auth v1 logic",
				verificationPlan: "test",
				subject: "auth_v1",
				facts: [fact1.id],
			});

			// Attempting to rebind hypothesis subject to auth_v2 must fail
			await expect(
				store.verifyHypothesis({
					hypothesisId: hyp.id,
					method: "verify",
					command: "cmd",
					result: "res",
					conclusion: "Auth verified",
					status: "verified",
					subject: "auth_v2",
				}),
			).rejects.toThrow("Cannot rebind hypothesis subject from 'auth_v1' to 'auth_v2'");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("validates existing hypothesis context compoundStages on verification without context override", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ev-assurance-hyp-stages-"));
		try {
			const store = new EvidenceStore({ repositoryRoot: tempDir, stateRoot: tempDir });

			// Hypothesis was recorded with a failed compound stage in its own context
			const hyp = await store.addHypothesis({
				kind: "hypothesis",
				claim: "Build and deploy succeeds",
				verificationPlan: "compile and test",
				context: { compoundStages: [{ stage: "compile", exitCode: 1, status: "failed" }] },
			});

			// Calling verifyHypothesis without overriding context must still fail on the hypothesis's failed stage
			await expect(
				store.verifyHypothesis({
					hypothesisId: hyp.id,
					method: "check",
					command: "ls",
					result: "ok",
					conclusion: "Build deploy succeeded",
					status: "verified",
				}),
			).rejects.toThrow("hypothesis context compound command stage 'compile' failed with exit code 1");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("caps hypothesis assurance to active verifying conclusion tier", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ev-assurance-cap-tier-"));
		try {
			const store = new EvidenceStore({ repositoryRoot: tempDir, stateRoot: tempDir });

			const fact = await store.addFact({
				kind: "fact",
				sourceTool: "strings",
				locator: "offset:0x10",
				content: "Found token string",
				assurance: "static_candidate",
			});

			// Hypothesis declares independent_reproduction tier in its raw context
			const hyp = await store.addHypothesis({
				kind: "hypothesis",
				claim: "Token parsing verified",
				verificationPlan: "inspect",
				assurance: "independent_reproduction",
				facts: [fact.id],
			});

			// Verified by static_candidate conclusion
			await store.verifyHypothesis({
				hypothesisId: hyp.id,
				method: "static check",
				command: "strings",
				result: "found",
				conclusion: "Token string exists in binary",
				status: "verified",
				assurance: "static_candidate",
			});

			// Evaluating hypothesis support for minAssurance independent_reproduction must fail!
			const evalHyp = await store.evaluateSupport([hyp.id], {
				minAssurance: "independent_reproduction",
			});
			expect(evalHyp.valid).toBe(false);
			expect(evalHyp.unmetAssuranceIds).toContain(hyp.id);

			// But evaluating for static_candidate succeeds
			const evalStatic = await store.evaluateSupport([hyp.id], {
				minAssurance: "static_candidate",
			});
			expect(evalStatic.valid).toBe(true);
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("propagates explicit conclusion invalidation back to hypothesis and resolves completely via worklist", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ev-assurance-worklist-chain-"));
		try {
			const store = new EvidenceStore({ repositoryRoot: tempDir, stateRoot: tempDir });

			// 1. Setup chain: H1 verified by C1
			const h1 = await store.addHypothesis({
				kind: "hypothesis",
				claim: "H1 claim",
				verificationPlan: "test",
			});
			const c1 = await store.verifyHypothesis({
				hypothesisId: h1.id,
				method: "m1",
				command: "c1",
				result: "r1",
				conclusion: "C1 verified",
				status: "verified",
			});

			// H2 depends on H1
			const h2 = await store.addHypothesis({
				kind: "hypothesis",
				claim: "H2 claim",
				verificationPlan: "test",
				facts: [h1.id],
			});
			const c2 = await store.verifyHypothesis({
				hypothesisId: h2.id,
				method: "m2",
				command: "c2",
				result: "r2",
				conclusion: "C2 verified",
				status: "verified",
			});

			// Both H1 and H2 initially verified
			const evalInitial = await store.evaluateSupport([h1.id, h2.id]);
			expect(evalInitial.valid).toBe(true);

			// Now a new conclusion C3 explicitly invalidates C1!
			const h3 = await store.addHypothesis({
				kind: "hypothesis",
				claim: "H3 claim",
				verificationPlan: "test",
			});
			await store.verifyHypothesis({
				hypothesisId: h3.id,
				method: "m3",
				command: "c3",
				result: "r3",
				conclusion: "C3 supersedes C1",
				status: "verified",
				invalidatesConclusions: [c1.id],
			});

			// Worklist propagation:
			// C1 is stale -> H1 becomes stale -> H2 becomes stale -> C2 becomes stale!
			const validityMap = await store.resolveValidity();
			expect(validityMap.get(c1.id)?.effectiveStatus).toBe("stale");
			expect(validityMap.get(h1.id)?.effectiveStatus).toBe("stale");
			expect(validityMap.get(h1.id)?.isValid).toBe(false);
			expect(validityMap.get(h2.id)?.effectiveStatus).toBe("stale");
			expect(validityMap.get(c2.id)?.effectiveStatus).toBe("stale");

			const evalAfter = await store.evaluateSupport([h2.id]);
			expect(evalAfter.valid).toBe(false);
			expect(evalAfter.staleIds).toContain(h2.id);
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("revalidates retained knowledge live during knowledge search and apply without manual audit", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ev-assurance-live-reval-"));
		try {
			const store = new EvidenceStore({ repositoryRoot: tempDir, stateRoot: tempDir });
			const knStore = new ReverseKnowledgeStore({ repositoryRoot: tempDir });

			const hyp = await store.addHypothesis({
				kind: "hypothesis",
				claim: "Protocol handshake",
				verificationPlan: "handshake test",
			});
			const conc = await store.verifyHypothesis({
				hypothesisId: hyp.id,
				method: "handshake",
				command: "curl",
				result: "200 ok",
				conclusion: "Handshake verified",
				status: "verified",
			});

			// Retain knowledge backed by conc
			const knId = createKnowledgeId();
			await knStore.save({
				id: knId,
				kind: "verified_conclusion",
				title: "CustomProtocolUniqueHandshake Pattern",
				target_format: "APK",
				confidence: "high",
				source_evidence_ids: [conc.id],
				summary: "Handshake verified",
				created_at: new Date().toISOString(),
				updated_at: new Date().toISOString(),
			});

			// 1. Search before refutation returns the active knowledge
			const searchBefore = await knStore.search(
				{ query: "CustomProtocolUniqueHandshake", include_bundled: false },
				store,
			);
			expect(searchBefore.length).toBe(1);

			const applyBefore = await applyKnowledge(knStore, { goal: "CustomProtocolUniqueHandshake" }, store);
			expect(applyBefore.recommendations.length).toBe(1);

			// 2. Refute the hypothesis in the evidence ledger
			await store.verifyHypothesis({
				hypothesisId: hyp.id,
				method: "replay",
				command: "replay",
				result: "failed",
				conclusion: "Handshake refuted",
				status: "refuted",
			});

			// 3. Search and apply automatically exclude the knowledge without running manual audit!
			const searchAfter = await knStore.search(
				{ query: "CustomProtocolUniqueHandshake", include_bundled: false },
				store,
			);
			expect(searchAfter.length).toBe(0);

			const applyAfter = await applyKnowledge(knStore, { goal: "CustomProtocolUniqueHandshake" }, store);
			expect(applyAfter.recommendations.length).toBe(0);
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});
});
