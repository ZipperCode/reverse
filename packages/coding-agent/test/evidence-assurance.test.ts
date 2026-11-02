import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { EvidenceStore } from "../src/evidence/store";
import { ReverseKnowledgeStore } from "../src/reverse-knowledge/store";
import { createKnowledgeId } from "../src/reverse-knowledge/contracts";
import { validateVerifiedOnly, learnFromEvidenceAndWorkflows, applyKnowledge } from "../src/reverse-knowledge/service";
import { ReverseWorkflowStore } from "../src/reverse-workflow/store";
import { advanceWorkflow } from "../src/reverse-workflow/progression";
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

			const factBounded = await store.addFact({
				kind: "fact",
				sourceTool: "logcat",
				locator: "logcat:tail_50",
				content: "Scanned 50 lines of logcat tail; 0 occurrences of sessionViewId",
			});
			const hyp = await store.addHypothesis({
				kind: "hypothesis",
				claim: "sessionViewId parameter does not exist on PC client",
				verificationPlan: "grep logcat tail",
				facts: [factBounded.id],
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
			const fact1 = await store.addFact({
				kind: "fact",
				sourceTool: "frida",
				locator: "session:s1:seq:1",
				content: "Observed WirelessSDKSign return end0",
			});
			const hyp = await store.addHypothesis({
				kind: "hypothesis",
				claim: "Java native signature binding is functional",
				verificationPlan: "Load library and check return",
				facts: [fact1.id],
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
			const f1 = await store.addFact({
				kind: "fact",
				sourceTool: "triage",
				locator: "offset:0x100",
				content: "Initial fact F1",
			});
			const h1 = await store.addHypothesis({
				kind: "hypothesis",
				claim: "H1 claim",
				verificationPlan: "test",
				facts: [f1.id],
			});
			const c1 = await store.verifyHypothesis({
				hypothesisId: h1.id,
				method: "m1",
				command: "c1",
				result: "r1",
				conclusion: "C1 verified",
				status: "verified",
			});

			// Legacy ledger entries: H2 referencing H1 and verified by C2 (preserved read-only from existing ledger)
			const h2 = {
				id: "ev_hyp_legacy_h2",
				kind: "hypothesis" as const,
				title: "[Hypothesis] H2 claim",
				createdAt: new Date().toISOString(),
				claim: "H2 claim",
				verificationPlan: "test",
				facts: [h1.id],
			};
			const c2 = {
				id: "ev_conc_legacy_c2",
				kind: "conclusion" as const,
				title: "[Conclusion] C2 verified",
				createdAt: new Date().toISOString(),
				hypothesisId: h2.id,
				method: "m2",
				command: "c2",
				result: "r2",
				conclusion: "C2 verified",
				reproducibility: "not specified",
				status: "verified" as const,
				verifiedAt: new Date().toISOString(),
			};
			await fs.appendFile(store.ledgerPath, `${JSON.stringify(h2)}\n${JSON.stringify(c2)}\n`, "utf-8");

			// Both H1 and H2 initially verified when reading ledger
			const evalInitial = await store.evaluateSupport([h1.id, h2.id]);
			expect(evalInitial.valid).toBe(true);

			// Now a new conclusion C3 explicitly invalidates C1!
			const h3 = await store.addHypothesis({
				kind: "hypothesis",
				claim: "H3 claim",
				verificationPlan: "test",
				facts: [f1.id],
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

			const factHandshake = await store.addFact({
				kind: "fact",
				sourceTool: "pcap_inspect",
				locator: "pcap:stream_0",
				content: "Observed 200 OK handshake frame",
			});
			const hyp = await store.addHypothesis({
				kind: "hypothesis",
				claim: "Protocol handshake",
				verificationPlan: "handshake test",
				facts: [factHandshake.id],
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

	it("rejects verified conclusions with empty facts at default/static assurance, wrong kind, missing, or stale facts while preserving refutations", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ev-assurance-strict-facts-"));
		try {
			const store = new EvidenceStore({ repositoryRoot: tempDir, stateRoot: tempDir });

			const hypEmpty = await store.addHypothesis({
				kind: "hypothesis",
				claim: "Token validation uses static key",
				verificationPlan: "Check disassembly",
			});

			// 1. Default assurance (unspecified) with empty facts must fail
			await expect(
				store.verifyHypothesis({
					hypothesisId: hypEmpty.id,
					method: "manual review",
					command: "r2 -qc pdf sample.bin",
					result: "looks valid",
					conclusion: "Verified without facts",
					status: "verified",
				}),
			).rejects.toThrow("without supporting evidence facts");

			// 2. Explicit static_candidate assurance with empty facts must also fail
			await expect(
				store.verifyHypothesis({
					hypothesisId: hypEmpty.id,
					method: "strings scan",
					command: "strings sample.bin",
					result: "found string",
					conclusion: "Static candidate verified without facts",
					status: "verified",
					assurance: "static_candidate",
				}),
			).rejects.toThrow("without supporting evidence facts");

			// 3. Refutation without supporting facts remains allowed
			const refConc = await store.verifyHypothesis({
				hypothesisId: hypEmpty.id,
				method: "runtime test",
				command: "./sample.bin",
				result: "key rejected",
				conclusion: "Claim refuted empirically",
				status: "refuted",
			});
			expect(refConc.status).toBe("refuted");

			// 4. Missing fact ID must fail
			const hypChecks = await store.addHypothesis({
				kind: "hypothesis",
				claim: "Header magic check",
				verificationPlan: "Inspect bytes",
			});
			await expect(
				store.verifyHypothesis({
					hypothesisId: hypChecks.id,
					method: "xxd",
					command: "xxd -l 16 sample.bin",
					result: "bytes read",
					conclusion: "Header verified",
					status: "verified",
					facts: ["ev_fact_missing_nonexistent"],
				}),
			).rejects.toThrow("Evidence records not found in ledger");

			// 5. Wrong kind (unknown, hypothesis, or conclusion instead of fact) must fail
			const unk = await store.addUnknown({
				kind: "unknown",
				question: "Where is IV generated?",
			});
			await expect(
				store.verifyHypothesis({
					hypothesisId: hypChecks.id,
					method: "review",
					command: "read",
					result: "checked",
					conclusion: "Verified from unknown",
					status: "verified",
					facts: [unk.id],
				}),
			).rejects.toThrow("permitted kinds [fact]");

			const validFact = await store.addFact({
				kind: "fact",
				sourceTool: "triage",
				locator: "0x0",
				content: "ELF magic 7f 45 4c 46",
				assurance: "static_candidate",
			});
			const otherHyp = await store.addHypothesis({
				kind: "hypothesis",
				claim: "Other verified hypothesis",
				verificationPlan: "check magic",
				facts: [validFact.id],
			});
			const otherConc = await store.verifyHypothesis({
				hypothesisId: otherHyp.id,
				method: "triage",
				command: "file sample.bin",
				result: "ELF",
				conclusion: "Confirmed ELF",
				status: "verified",
				assurance: "static_candidate",
			});

			// Passing a verified hypothesis or conclusion instead of a fact must fail requiredKinds: ["fact"]
			await expect(
				store.verifyHypothesis({
					hypothesisId: hypChecks.id,
					method: "chain",
					command: "echo",
					result: "ok",
					conclusion: "Tried using hypothesis as fact",
					status: "verified",
					facts: [otherHyp.id],
				}),
			).rejects.toThrow("permitted kinds [fact]");

			await expect(
				store.verifyHypothesis({
					hypothesisId: hypChecks.id,
					method: "chain",
					command: "echo",
					result: "ok",
					conclusion: "Tried using conclusion as fact",
					status: "verified",
					facts: [otherConc.id],
				}),
			).rejects.toThrow("permitted kinds [fact]");

			// 6. Stale/explicitly invalidated fact must fail
			const staleTargetFact = await store.addFact({
				kind: "fact",
				sourceTool: "grep",
				locator: "line:10",
				content: "Outdated observation",
			});
			const invalidatorHyp = await store.addHypothesis({
				kind: "hypothesis",
				claim: "Invalidate outdated fact",
				verificationPlan: "re-check",
				facts: [validFact.id],
			});
			await store.verifyHypothesis({
				hypothesisId: invalidatorHyp.id,
				method: "re-check",
				command: "grep",
				result: "superseded",
				conclusion: "Prior observation invalidated",
				status: "verified",
				invalidatesConclusions: [staleTargetFact.id],
			});

			await expect(
				store.verifyHypothesis({
					hypothesisId: hypChecks.id,
					method: "verify stale",
					command: "grep",
					result: "seen",
					conclusion: "Attempt with stale fact",
					status: "verified",
					facts: [staleTargetFact.id],
				}),
			).rejects.toThrow("stale or superseded");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("prevents static facts from inflating assurance while keeping unspecified conclusion assurance unspecified", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ev-assurance-no-static-inflation-"));
		try {
			const store = new EvidenceStore({ repositoryRoot: tempDir, stateRoot: tempDir });

			const staticFact = await store.addFact({
				kind: "fact",
				sourceTool: "r2_inspect",
				locator: "0x401000",
				content: "Static xref to AES_encrypt",
				assurance: "static_candidate",
			});

			// 1. Unspecified hypothesis + unspecified conclusion keeps conclusion assurance undefined (never inflated)
			const hypDefault = await store.addHypothesis({
				kind: "hypothesis",
				claim: "AES_encrypt symbol referenced in login module",
				verificationPlan: "Inspect xrefs",
				facts: [staticFact.id],
			});
			const defaultConc = await store.verifyHypothesis({
				hypothesisId: hypDefault.id,
				method: "xref review",
				command: "r2 -qc axt",
				result: "xref exists",
				conclusion: "Confirmed static cross-reference",
				status: "verified",
			});
			expect(defaultConc.context?.assurance).toBeUndefined();
			const evalDefaultForDynamic = await store.evaluateSupport([defaultConc.id, hypDefault.id], {
				minAssurance: "dynamic_call_observation",
			});
			expect(evalDefaultForDynamic.valid).toBe(false);

			// 2. Hypothesis requesting dynamic_call_observation rejects both explicit dynamic and omitted assurance when backed only by static fact
			const hypDynamicClaim = await store.addHypothesis({
				kind: "hypothesis",
				claim: "AES_encrypt is invoked during login",
				verificationPlan: "Hook AES_encrypt at runtime",
				assurance: "dynamic_call_observation",
				facts: [staticFact.id],
			});

			await expect(
				store.verifyHypothesis({
					hypothesisId: hypDynamicClaim.id,
					method: "xref review",
					command: "r2 -qc axt",
					result: "xref exists",
					conclusion: "Claiming dynamic call from static xref",
					status: "verified",
					assurance: "dynamic_call_observation",
				}),
			).rejects.toThrow("Evidence records do not meet minimum assurance tier 'dynamic_call_observation'");

			await expect(
				store.verifyHypothesis({
					hypothesisId: hypDynamicClaim.id,
					method: "xref review",
					command: "r2 -qc axt",
					result: "xref exists",
					conclusion: "Omitting conclusion assurance on dynamic hypothesis with static fact",
					status: "verified",
				}),
			).rejects.toThrow("Evidence records do not meet minimum assurance tier 'dynamic_call_observation'");

			// Explicitly recording static_candidate tier succeeds and caps hypothesis effective assurance
			const staticConc = await store.verifyHypothesis({
				hypothesisId: hypDynamicClaim.id,
				method: "xref review",
				command: "r2 -qc axt",
				result: "xref exists",
				conclusion: "Confirmed static cross-reference candidate only",
				status: "verified",
				assurance: "static_candidate",
			});
			expect(staticConc.context?.assurance).toBe("static_candidate");

			const evalDynamic = await store.evaluateSupport([hypDynamicClaim.id], {
				minAssurance: "dynamic_call_observation",
			});
			expect(evalDynamic.valid).toBe(false);
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("enforces dynamic progression gate: static conclusions and unqualified session facts cannot bypass dynamic gate, qualified dynamic evidence can", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ev-assurance-dyn-gate-"));
		let wfStore: ReverseWorkflowStore | undefined;
		try {
			const targetPath = path.join(tempDir, "sample.apk");
			await fs.writeFile(targetPath, "PK\x03\x04dynamic-gate-apk");
			const otherPath = path.join(tempDir, "other.apk");
			await fs.writeFile(otherPath, "PK\x03\x04different-apk-bytes");

			const store = new EvidenceStore({ repositoryRoot: tempDir, stateRoot: tempDir });
			wfStore = new ReverseWorkflowStore({ repositoryRoot: tempDir, stateRoot: tempDir });

			const makeWorkflow = async (idSuffix: string) =>
				await wfStore!.create({
					id: `wf_dyn_gate_${idSuffix}`,
					target: "sample.apk",
					format: "APK",
					acceptance_criteria: [
						{
							id: "ac_dyn",
							step_id: "dyn_step",
							title: "Frida runtime hook",
							subject: "native_sign",
							min_assurance: "dynamic_call_observation",
						},
					],
					steps: [
						{
							id: "dyn_step",
							title: "Frida runtime hook",
							tool: "frida",
							gate: "G2",
							params_summary: { action: "spawn" },
							status: "pending",
							attempts: 0,
							max_attempts: 3,
							created_at: new Date().toISOString(),
							updated_at: new Date().toISOString(),
						},
					],
				});
			// 1. Static verified conclusion cannot bypass dynamic step gate
			const staticFact = await store.addFact({
				kind: "fact",
				target: "sample.apk",
				sourceTool: "strings",
				locator: "offset:0x200",
				content: "Static symbol Java_com_app_sign",
				subject: "native_sign",
				assurance: "static_candidate",
			});
			const staticHyp = await store.addHypothesis({
				kind: "hypothesis",
				target: "sample.apk",
				claim: "Symbol exists",
				verificationPlan: "strings",
				subject: "native_sign",
				facts: [staticFact.id],
			});
			const staticConc = await store.verifyHypothesis({
				hypothesisId: staticHyp.id,
				method: "strings",
				command: "strings sample.apk",
				result: "found",
				conclusion: "Static symbol confirmed",
				status: "verified",
				assurance: "static_candidate",
			});

			const wf1 = await makeWorkflow("static_conc");
			const resStaticConc = await advanceWorkflow(
				wf1,
				{ step_id: "dyn_step", status: "completed", evidence_ids: [staticConc.id] },
				{ repositoryRoot: tempDir, evidenceStore: store },
			);
			expect(resStaticConc.advanced).toBe(false);
			expect(resStaticConc.status).toBe("held_pending_decision");
			expect(wf1.steps[0].status).toBe("pending");

			// 2. Session-locator fact WITHOUT dynamic assurance (e.g. console log or untrusted explicit event) cannot bypass
			const sessionOnlyFact = await store.addFact({
				kind: "fact",
				target: "sample.apk",
				sourceTool: "browser_reverse_session",
				locator: "session:sess_console:seq:1",
				content: "console.log('hello')",
				subject: "native_sign",
			});
			const wf2 = await makeWorkflow("session_only");
			const resSessionOnly = await advanceWorkflow(
				wf2,
				{ step_id: "dyn_step", status: "completed", evidence_ids: [sessionOnlyFact.id] },
				{ repositoryRoot: tempDir, evidenceStore: store },
			);
			expect(resSessionOnly.advanced).toBe(false);
			expect(resSessionOnly.status).toBe("held_pending_decision");

			// 3. Fact WITH dynamic assurance but WITHOUT legal dynamic session locator cannot bypass
			const nonSessionDynFact = await store.addFact({
				kind: "fact",
				target: "sample.apk",
				sourceTool: "logcat",
				locator: "logcat:line:42",
				content: "Observed sign marker",
				subject: "native_sign",
				assurance: "dynamic_call_observation",
			});
			const wf3 = await makeWorkflow("non_session_loc");
			const resNonSession = await advanceWorkflow(
				wf3,
				{ step_id: "dyn_step", status: "completed", evidence_ids: [nonSessionDynFact.id] },
				{ repositoryRoot: tempDir, evidenceStore: store },
			);
			expect(resNonSession.advanced).toBe(false);
			expect(resNonSession.status).toBe("held_pending_decision");

			// 4. Dynamic conclusion for wrong target/hash cannot bypass workflow gate for sample.apk
			const wrongTargetFact = await store.addFact({
				kind: "fact",
				target: "other.apk",
				sourceTool: "frida_session",
				locator: "session:sess_other:seq:1",
				content: "Hooked sign on other.apk",
				subject: "native_sign",
				assurance: "dynamic_call_observation",
			});
			const wrongTargetHyp = await store.addHypothesis({
				kind: "hypothesis",
				target: "other.apk",
				claim: "Other apk sign",
				verificationPlan: "frida",
				subject: "native_sign",
				facts: [wrongTargetFact.id],
			});
			const wrongTargetConc = await store.verifyHypothesis({
				hypothesisId: wrongTargetHyp.id,
				method: "frida",
				command: "frida -f other",
				result: "called",
				conclusion: "Called on other.apk",
				status: "verified",
				assurance: "dynamic_call_observation",
			});
			const wf4 = await makeWorkflow("wrong_target");
			const resWrongTarget = await advanceWorkflow(
				wf4,
				{ step_id: "dyn_step", status: "completed", evidence_ids: [wrongTargetConc.id] },
				{ repositoryRoot: tempDir, evidenceStore: store },
			);
			expect(resWrongTarget.advanced).toBe(false);
			expect(resWrongTarget.status).toBe("held_pending_decision");

			// 4b. Direct dynamic fact with anonymous session: target and no targetSha256 cannot bypass hashed workflow gate
			const anonSessionDynFact = await store.addFact({
				kind: "fact",
				target: "session:sess_anon",
				sourceTool: "frida_session",
				locator: "session:sess_anon:seq:1",
				content: "Anonymous session dynamic event without target hash",
				subject: "native_sign",
				assurance: "dynamic_call_observation",
			});
			const wfAnon = await makeWorkflow("anon_session_fact");
			const resAnonFact = await advanceWorkflow(
				wfAnon,
				{ step_id: "dyn_step", status: "completed", evidence_ids: [anonSessionDynFact.id] },
				{ repositoryRoot: tempDir, evidenceStore: store },
			);
			expect(resAnonFact.advanced).toBe(false);
			expect(resAnonFact.status).toBe("held_pending_decision");

			// 4c. Case-distinct target path ('VirtualApp.apk' vs 'virtualapp.apk') is not treated as equal
			const wfCaseSensitive = await wfStore!.create({
				id: "wf_dyn_gate_case_sensitive",
				target: "virtualapp.apk",
				format: "APK",
				acceptance_criteria: [
					{
						id: "ac_case",
						step_id: "dyn_step",
						title: "Case sensitive target check",
						subject: "native_sign",
						min_assurance: "dynamic_call_observation",
					},
				],
				steps: [
					{
						id: "dyn_step",
						title: "Frida runtime hook",
						tool: "frida",
						gate: "G2",
						params_summary: { action: "spawn" },
						status: "pending",
						attempts: 0,
						max_attempts: 3,
						created_at: new Date().toISOString(),
						updated_at: new Date().toISOString(),
					},
				],
			});
			const wrongCaseFact = await store.addFact({
				kind: "fact",
				target: "VirtualApp.apk",
				sourceTool: "frida_session",
				locator: "session:sess_case:seq:1",
				content: "Different case target name",
				subject: "native_sign",
				assurance: "dynamic_call_observation",
			});
			const resWrongCase = await advanceWorkflow(
				wfCaseSensitive,
				{ step_id: "dyn_step", status: "completed", evidence_ids: [wrongCaseFact.id] },
				{ repositoryRoot: tempDir, evidenceStore: store },
			);
			expect(resWrongCase.advanced).toBe(false);
			expect(resWrongCase.status).toBe("held_pending_decision");
			// 5. Qualified dynamic fact AND qualified dynamic conclusion matching target/hash and subject succeed
			const qualifiedDynFact = await store.addFact({
				kind: "fact",
				target: "sample.apk",
				sourceTool: "frida_session",
				locator: "session:sess_real:seq:7",
				content: "Observed libsign.so!0x1234 invocation",
				subject: "native_sign",
				assurance: "dynamic_call_observation",
			});
			const wf5 = await makeWorkflow("qualified_fact");
			const resQualFact = await advanceWorkflow(
				wf5,
				{ step_id: "dyn_step", status: "completed", evidence_ids: [qualifiedDynFact.id] },
				{ repositoryRoot: tempDir, evidenceStore: store },
			);
			expect(resQualFact.advanced).toBe(true);
			expect(resQualFact.status).toBe("recorded");
			expect(wf5.steps[0].status).toBe("completed");

			const qualifiedHyp = await store.addHypothesis({
				kind: "hypothesis",
				target: "sample.apk",
				claim: "libsign.so!0x1234 signs login request",
				verificationPlan: "Hook 0x1234 in Frida session",
				subject: "native_sign",
				facts: [qualifiedDynFact.id],
			});
			const qualifiedConc = await store.verifyHypothesis({
				hypothesisId: qualifiedHyp.id,
				method: "Frida interceptor",
				command: "frida -U -f com.sample -l sign.js",
				result: "Hit libsign.so+0x1234",
				conclusion: "Confirmed dynamic call observation at libsign.so+0x1234",
				status: "verified",
				assurance: "dynamic_call_observation",
			});
			const wf6 = await makeWorkflow("qualified_conc");
			const resQualConc = await advanceWorkflow(
				wf6,
				{ step_id: "dyn_step", status: "completed", evidence_ids: [qualifiedConc.id] },
				{ repositoryRoot: tempDir, evidenceStore: store },
			);
			expect(resQualConc.advanced).toBe(true);
			expect(resQualConc.status).toBe("recorded");
			expect(wf6.steps[0].status).toBe("completed");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});
});
