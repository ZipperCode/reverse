import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import type { AgentToolContext } from "@reverse/agent";
import { Settings } from "@reverse/coding-agent/config/settings";
import { ReverseWorkflowTool, type ToolSession } from "@reverse/coding-agent/tools";
import { ReverseWorkflowStore } from "@reverse/coding-agent/reverse-workflow/store";
import { advanceWorkflow } from "@reverse/coding-agent/reverse-workflow/progression";
import { EvidenceStore } from "@reverse/coding-agent/evidence/store";
import {
	computeWorkflowMetrics,
	type WorkflowDependencyRecord,
} from "@reverse/coding-agent/reverse-workflow/contracts";
import {
	getWorkflowAcceptanceCriteria,
	cascadeEvidenceRefutation,
} from "@reverse/coding-agent/reverse-workflow/acceptance";

function createSession(
	cwd: string,
	options: {
		hasUI?: boolean;
		confirmResult?: boolean;
	} = {},
): ToolSession {
	const hasUI = options.hasUI ?? false;
	return {
		cwd,
		hasUI,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
		getToolContext: () =>
			({
				hasUI,
				ui: hasUI
					? {
							select: async () => undefined,
							confirm: async () => options.confirmResult ?? false,
							input: async () => undefined,
							notify: () => undefined,
							onTerminalInput: () => () => {},
						}
					: undefined,
			}) as unknown as AgentToolContext,
	};
}

describe("Workflow Acceptance Criteria and Deployment Boundaries (#12, #13, Closed #6)", () => {
	it("enforces that proxy observations cannot close original criteria via advance and direct record", async () => {
		const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-test-proxy-"));
		let store: ReverseWorkflowStore | undefined;
		let evidenceStore: EvidenceStore | undefined;
		try {
			const targetFile = path.join(tmpDir, "app.apk");
			await fs.writeFile(targetFile, "dummy apk content");

			store = new ReverseWorkflowStore({ repositoryRoot: tmpDir });
			evidenceStore = new EvidenceStore({ repositoryRoot: tmpDir });

			const wf = await store.create({
				target: "app.apk",
				format: "APK",
				goal: "Verify independent login flow",
				acceptance_criteria: [
					{
						id: "ac_c5",
						step_id: "step_c5",
						title: "Login flow packet capture",
						subject: "login_flow_traffic",
						min_assurance: "dynamic_call_observation",
					},
				],
				steps: [
					{
						id: "step_c5",
						title: "Login flow packet capture",
						tool: "pcap_inspect",
						gate: "G1",
						params_summary: { filter: "login" },
						status: "pending",
						attempts: 0,
						max_attempts: 3,
						created_at: new Date().toISOString(),
						updated_at: new Date().toISOString(),
					},
				],
			});

			// Add proxy evidence: static API inventory
			const evProxy = await evidenceStore.addFact({
				kind: "fact",
				title: "Extracted 41 API names from static logs",
				classification: "internal",
				target: targetFile,
				sourceTool: "grep",
				locator: "static_strings:41",
				content: "API inventory: /api/v1/user, /api/v1/login",
				subject: "api_inventory",
				assurance: "static_candidate",
			});

			// Advance with proxy observation: must halt and mark criterion proxy_verified
			const resAdvance = await advanceWorkflow(
				wf,
				{
					step_id: "step_c5",
					status: "completed",
					evidence_ids: [evProxy.id],
				},
				{ repositoryRoot: tmpDir, evidenceStore },
			);

			expect(resAdvance.advanced).toBe(false);
			expect(resAdvance.status).toBe("held_pending_decision");
			expect(wf.steps[0].status).toBe("pending");

			const criteriaAfterAdvance = getWorkflowAcceptanceCriteria(wf, "step_c5");
			expect(criteriaAfterAdvance[0].status).toBe("proxy_verified");
			expect(criteriaAfterAdvance[0].is_proxy).toBe(true);

			// Direct record tool action with proxy evidence must also reject completion
			const tool = new ReverseWorkflowTool(createSession(tmpDir));
			let directRecordError: Error | undefined;
			try {
				await tool.execute("call_rec", {
					action: "record",
					workflow_id: wf.id,
					step_id: "step_c5",
					status: "completed",
					evidence_ids: [evProxy.id],
				});
			} catch (err) {
				directRecordError = err as Error;
			}

			expect(directRecordError).toBeDefined();
			expect(wf.steps[0].status).toBe("pending");

			// Provide genuine dynamic PCAP traffic matching canonical subject
			const evReal = await evidenceStore.addFact({
				kind: "fact",
				title: "Captured live login traffic PCAP",
				classification: "internal",
				target: targetFile,
				sourceTool: "pcap_inspect",
				locator: "pcap:login_stream_0",
				content: "Captured TCP stream: login packet payload exchanged",
				subject: "login_flow_traffic",
				assurance: "dynamic_call_observation",
			});

			const resReal = await advanceWorkflow(
				wf,
				{
					step_id: "step_c5",
					status: "completed",
					evidence_ids: [evReal.id],
				},
				{ repositoryRoot: tmpDir, evidenceStore },
			);

			expect(resReal.advanced).toBe(true);
			expect(resReal.status).toBe("recorded");
			expect(wf.steps[0].status).toBe("completed");

			const criteriaReal = getWorkflowAcceptanceCriteria(wf, "step_c5");
			expect(criteriaReal[0].status).toBe("satisfied");
			expect(criteriaReal[0].is_proxy).toBe(false);
		} finally {
			if (store) await fs.rm(store.projectDirectory, { recursive: true, force: true }).catch(() => undefined);
			if (evidenceStore)
				await fs.rm(evidenceStore.projectDirectory, { recursive: true, force: true }).catch(() => undefined);
			await fs.rm(tmpDir, { recursive: true, force: true });
		}
	});

	it("prevents renaming or rephrasing steps from inflating completion metrics", async () => {
		const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-test-rename-"));
		let store: ReverseWorkflowStore | undefined;
		try {
			const targetFile = path.join(tmpDir, "app.apk");
			await fs.writeFile(targetFile, "dummy apk content");

			store = new ReverseWorkflowStore({ repositoryRoot: tmpDir });
			const wf = await store.create({
				target: "app.apk",
				format: "APK",
				goal: "Verify protocol",
				acceptance_criteria: [
					{
						id: "ac_login",
						step_id: "step_c5",
						title: "Login flow packet capture",
						subject: "login_flow_traffic",
					},
				],
				steps: [
					{
						id: "step_c5",
						title: "Login flow packet capture",
						tool: "pcap_inspect",
						gate: "G1",
						params_summary: {},
						status: "pending",
						attempts: 0,
						max_attempts: 3,
						created_at: new Date().toISOString(),
						updated_at: new Date().toISOString(),
					},
				],
			});

			const m1 = computeWorkflowMetrics(wf.steps, wf.metadata);
			expect(m1.total_acceptance_criteria).toBe(1);
			expect(m1.satisfied_acceptance_criteria).toBe(0);
			expect(m1.acceptance_completion_ratio).toBe(0);

			// Rename step title arbitrarily
			wf.steps[0].title = "Static API names extracted from logcat";
			const m2 = computeWorkflowMetrics(wf.steps, wf.metadata);
			expect(m2.total_acceptance_criteria).toBe(1);
			expect(m2.satisfied_acceptance_criteria).toBe(0);
			expect(m2.acceptance_completion_ratio).toBe(0);
		} finally {
			if (store) await fs.rm(store.projectDirectory, { recursive: true, force: true }).catch(() => undefined);
			await fs.rm(tmpDir, { recursive: true, force: true });
		}
	});

	it("rejects caller attempts to inject initial satisfied or waived status on creation", async () => {
		const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-test-inject-"));
		let store: ReverseWorkflowStore | undefined;
		try {
			store = new ReverseWorkflowStore({ repositoryRoot: tmpDir });

			// Initial satisfied status injection must throw ToolError
			let errSatisfied: Error | undefined;
			try {
				await store.create({
					target: "app.apk",
					format: "APK",
					acceptance_criteria: [
						{
							id: "ac_fake",
							step_id: "s1",
							title: "Fake",
							subject: "fake_subject",
							status: "satisfied",
						},
					],
				});
			} catch (err) {
				errSatisfied = err as Error;
			}
			expect(errSatisfied).toBeDefined();
			expect(errSatisfied?.message).toContain("Initial acceptance criterion 'ac_fake' status must be 'pending'");

			// Initial approved_for_delivery=true injection must throw ToolError
			let errDelivery: Error | undefined;
			try {
				await store.create({
					target: "app.apk",
					format: "APK",
					dependencies: [
						{
							id: "dep_oracle",
							name: "Phone Oracle",
							kind: "external_service",
							scope: "delivery",
							approved_for_delivery: true,
						},
					],
				});
			} catch (err) {
				errDelivery = err as Error;
			}
			expect(errDelivery).toBeDefined();
			expect(errDelivery?.message).toContain("cannot be created with approved_for_delivery=true");
		} finally {
			if (store) await fs.rm(store.projectDirectory, { recursive: true, force: true }).catch(() => undefined);
			await fs.rm(tmpDir, { recursive: true, force: true });
		}
	});

	it("rejects duplicate criteria and dependency IDs upon creation", async () => {
		const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-test-dup-"));
		let store: ReverseWorkflowStore | undefined;
		try {
			store = new ReverseWorkflowStore({ repositoryRoot: tmpDir });

			let dupCritError: Error | undefined;
			try {
				await store.create({
					target: "app.apk",
					format: "APK",
					steps: [
						{
							id: "s1",
							title: "Step 1",
							tool: "triage",
							gate: "G0",
							params_summary: {},
							status: "pending",
							attempts: 0,
							max_attempts: 3,
							created_at: new Date().toISOString(),
							updated_at: new Date().toISOString(),
						},
						{
							id: "s2",
							title: "Step 2",
							tool: "triage",
							gate: "G0",
							params_summary: {},
							status: "pending",
							attempts: 0,
							max_attempts: 3,
							created_at: new Date().toISOString(),
							updated_at: new Date().toISOString(),
						},
					],
					acceptance_criteria: [
						{ id: "c1", step_id: "s1", title: "C1", subject: "sub1" },
						{ id: "c1", step_id: "s2", title: "C1 Duplicate", subject: "sub2" },
					],
				});
			} catch (err) {
				dupCritError = err as Error;
			}
			expect(dupCritError).toBeDefined();
			expect(dupCritError?.message).toContain("Duplicate acceptance criterion ID: 'c1'");

			let dupDepError: Error | undefined;
			try {
				await store.create({
					target: "app.apk",
					format: "APK",
					dependencies: [
						{ id: "d1", name: "Dep 1", kind: "framework", scope: "experiment" },
						{ id: "d1", name: "Dep 1 Dup", kind: "framework", scope: "experiment" },
					],
				});
			} catch (err) {
				dupDepError = err as Error;
			}
			expect(dupDepError).toBeDefined();
			expect(dupDepError?.message).toContain("Duplicate dependency ID: 'd1'");
		} finally {
			if (store) await fs.rm(store.projectDirectory, { recursive: true, force: true }).catch(() => undefined);
			await fs.rm(tmpDir, { recursive: true, force: true });
		}
	});

	it("enforces deployment constraints and blocks experimental phone oracle from standalone vehicle delivery", async () => {
		const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-test-constraints-"));
		let store: ReverseWorkflowStore | undefined;
		try {
			const targetFile = path.join(tmpDir, "app.apk");
			await fs.writeFile(targetFile, "dummy apk content");

			store = new ReverseWorkflowStore({ repositoryRoot: tmpDir });

			const wf = await store.create({
				target: "app.apk",
				format: "APK",
				goal: "Vehicle IVI standalone APK delivery",
				target_device_constraints: {
					target_environment: "vehicle_ivi",
					requires_standalone: true,
					disallowed_dependencies: ["phone_oracle", "lsposed"],
				},
				dependencies: [
					{
						id: "dep_oracle",
						name: "Phone LSPosed Oracle",
						kind: "external_service",
						scope: "experiment",
						target_host: "external_phone",
						approved_for_experiment: true,
					},
				],
			});

			// Attempt derivative registration targeting delivery
			let deliveryError: Error | undefined;
			try {
				await store.registerDerivative(wf.id, {
					target_path: targetFile,
					scope: "delivery",
				});
			} catch (err) {
				deliveryError = err as Error;
			}

			expect(deliveryError).toBeDefined();
			expect(deliveryError?.message).toContain("VIOLATION_EXPERIMENTAL_DEPENDENCY_IN_DELIVERY");
		} finally {
			if (store) await fs.rm(store.projectDirectory, { recursive: true, force: true }).catch(() => undefined);
			await fs.rm(tmpDir, { recursive: true, force: true });
		}
	});

	it("cascades evidence refutations and reopens steps/criteria without deleting history", async () => {
		const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-test-refute-"));
		let store: ReverseWorkflowStore | undefined;
		let evidenceStore: EvidenceStore | undefined;
		try {
			const targetFile = path.join(tmpDir, "app.apk");
			await fs.writeFile(targetFile, "dummy apk content");

			store = new ReverseWorkflowStore({ repositoryRoot: tmpDir });
			evidenceStore = new EvidenceStore({ repositoryRoot: tmpDir });

			const wf = await store.create({
				target: "app.apk",
				format: "APK",
				goal: "Verify crypto signing algorithm",
				acceptance_criteria: [
					{
						id: "ac_crypto",
						step_id: "s1",
						title: "Verify crypto signing",
						subject: "crypto_signing",
					},
				],
				steps: [
					{
						id: "s1",
						title: "Reverse native sign",
						tool: "triage",
						gate: "G0",
						params_summary: {},
						status: "pending",
						attempts: 0,
						max_attempts: 3,
						created_at: new Date().toISOString(),
						updated_at: new Date().toISOString(),
					},
				],
			});

			const hyp = await evidenceStore.addHypothesis({
				kind: "hypothesis",
				title: "Native signing algorithm",
				claim: "WirelessSDK native sign succeeds",
				verificationPlan: "Verify logcat marker and dlopen return",
				target: targetFile,
			});

			const fact1 = await evidenceStore.addFact({
				kind: "fact",
				title: "Logcat marker observed",
				classification: "internal",
				target: targetFile,
				sourceTool: "grep",
				locator: "logcat:1",
				content: "WirelessSDKSign start",
				subject: "crypto_signing",
				assurance: "dynamic_call_observation",
			});

			const conc1 = await evidenceStore.verifyHypothesis({
				hypothesisId: hyp.id,
				title: "WirelessSDK sign observed",
				conclusion: "Observed WirelessSDKSign start marker",
				status: "verified",
				method: "logcat_scan",
				command: "logcat",
				result: "pass",
				reproducibility: "1/1",
				facts: [fact1.id],
				target: targetFile,
				subject: "crypto_signing",
			});

			// Complete step with conclusion conc1
			await advanceWorkflow(
				wf,
				{
					step_id: "s1",
					status: "completed",
					evidence_ids: [conc1.id],
				},
				{ repositoryRoot: tmpDir, evidenceStore },
			);

			expect(wf.steps[0].status).toBe("completed");
			expect(getWorkflowAcceptanceCriteria(wf, "s1")[0].status).toBe("satisfied");

			// Later observation: UnsatisfiedLinkError refutes hypothesis
			await evidenceStore.verifyHypothesis({
				hypothesisId: hyp.id,
				title: "WirelessSDK sign failed",
				conclusion: "UnsatisfiedLinkError: WirelessSDK.sign dlopen failed",
				status: "refuted",
				method: "runtime_exec",
				command: "am start",
				result: "fail",
				reproducibility: "1/1",
				target: targetFile,
				subject: "crypto_signing",
				invalidatesConclusions: [conc1.id],
			});

			// Cascade refutation
			const cascade = await cascadeEvidenceRefutation(wf, evidenceStore);
			expect(cascade.invalidatedSteps).toContain("s1");
			expect(cascade.invalidatedCriteria).toContain("ac_crypto");

			expect(wf.steps[0].status).toBe("pending");
			expect(wf.steps[0].decision).toBe("invalidated_by_evidence");
			expect(getWorkflowAcceptanceCriteria(wf, "s1")[0].status).toBe("pending");

			// Historical evidence_ids remain intact
			expect(wf.steps[0].evidence_ids).toContain(conc1.id);
		} finally {
			if (store) await fs.rm(store.projectDirectory, { recursive: true, force: true }).catch(() => undefined);
			if (evidenceStore)
				await fs.rm(evidenceStore.projectDirectory, { recursive: true, force: true }).catch(() => undefined);
			await fs.rm(tmpDir, { recursive: true, force: true });
		}
	});

	it("strictly enforces interactive UI confirmation for waivers and delivery approvals", async () => {
		const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-test-approval-"));
		let store: ReverseWorkflowStore | undefined;
		try {
			const targetFile = path.join(tmpDir, "app.apk");
			await fs.writeFile(targetFile, "dummy apk content");

			store = new ReverseWorkflowStore({ repositoryRoot: tmpDir });
			const wf = await store.create({
				target: "app.apk",
				format: "APK",
				acceptance_criteria: [
					{
						id: "ac_req",
						step_id: "s1",
						title: "Required criterion",
						subject: "live_protocol",
					},
				],
				dependencies: [
					{
						id: "dep_ext",
						name: "Runtime Helper",
						kind: "runtime_library",
						scope: "experiment",
					},
				],
				steps: [
					{
						id: "s1",
						title: "Step 1",
						tool: "triage",
						gate: "G0",
						params_summary: {},
						status: "pending",
						attempts: 0,
						max_attempts: 3,
						created_at: new Date().toISOString(),
						updated_at: new Date().toISOString(),
					},
				],
			});

			// 1. Non-interactive waiver call must be rejected
			const nonInteractiveTool = new ReverseWorkflowTool(createSession(tmpDir, { hasUI: false }));
			let errNonInt: Error | undefined;
			try {
				await nonInteractiveTool.execute("c1", {
					action: "waive_acceptance",
					workflow_id: wf.id,
					criterion_id: "ac_req",
					reason: "Want to skip",
				});
			} catch (err) {
				errNonInt = err as Error;
			}
			expect(errNonInt).toBeDefined();
			expect(errNonInt?.message).toContain("requires explicit interactive user confirmation");

			// 2. Interactive denial
			const denyTool = new ReverseWorkflowTool(createSession(tmpDir, { hasUI: true, confirmResult: false }));
			let errDenied: Error | undefined;
			try {
				await denyTool.execute("c2", {
					action: "waive_acceptance",
					workflow_id: wf.id,
					criterion_id: "ac_req",
					reason: "Want to skip",
				});
			} catch (err) {
				errDenied = err as Error;
			}
			expect(errDenied).toBeDefined();
			expect(errDenied?.message).toContain("User denied waiver");

			// 3. Interactive approval
			const approveTool = new ReverseWorkflowTool(createSession(tmpDir, { hasUI: true, confirmResult: true }));
			const waiveResult = await approveTool.execute("c3", {
				action: "waive_acceptance",
				workflow_id: wf.id,
				criterion_id: "ac_req",
				reason: "User confirmed alternative acceptance",
			});
			expect(waiveResult.details.waiver_approved).toBe(true);
			const refreshedWf = await store.get(wf.id);
			expect(getWorkflowAcceptanceCriteria(refreshedWf!, "s1")[0].status).toBe("waived");

			// 4. Interactive delivery dependency approval
			const depResult = await approveTool.execute("c4", {
				action: "approve_dependency",
				workflow_id: wf.id,
				dependency_id: "dep_ext",
				reason: "User approved external helper on vehicle device",
			});
			expect(depResult.details.dependency_approved).toBe(true);
			const refreshedDepWf = await store.get(wf.id);
			const dep = (refreshedDepWf?.metadata?.dependencies as WorkflowDependencyRecord[] | undefined)?.find(
				d => d.id === "dep_ext",
			);
			expect(dep?.approved_for_delivery).toBe(true);
		} finally {
			if (store) await fs.rm(store.projectDirectory, { recursive: true, force: true }).catch(() => undefined);
			await fs.rm(tmpDir, { recursive: true, force: true });
		}
	});

	it("stably completes step when re-verified with evidence B after A was refuted without permanent failure", async () => {
		const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-test-reverify-"));
		let store: ReverseWorkflowStore | undefined;
		let evidenceStore: EvidenceStore | undefined;
		try {
			const targetFile = path.join(tmpDir, "app.apk");
			await fs.writeFile(targetFile, "dummy apk content");

			store = new ReverseWorkflowStore({ repositoryRoot: tmpDir });
			evidenceStore = new EvidenceStore({ repositoryRoot: tmpDir });

			const wf = await store.create({
				target: "app.apk",
				format: "APK",
				goal: "Verify algorithm",
				acceptance_criteria: [
					{ id: "ac_alg", step_id: "s1", title: "Algorithm verification", subject: "signing_algorithm" },
				],
				steps: [
					{
						id: "s1",
						title: "Step 1",
						tool: "triage",
						gate: "G0",
						params_summary: {},
						status: "pending",
						attempts: 0,
						max_attempts: 3,
						created_at: new Date().toISOString(),
						updated_at: new Date().toISOString(),
					},
				],
			});

			const hyp = await evidenceStore.addHypothesis({
				kind: "hypothesis",
				title: "Hypothesis",
				claim: "Algorithm signing works",
				verificationPlan: "Check signatures",
				target: targetFile,
			});

			const factA = await evidenceStore.addFact({
				kind: "fact",
				title: "Fact A",
				classification: "internal",
				target: targetFile,
				sourceTool: "grep",
				locator: "loc1",
				content: "data A",
				subject: "signing_algorithm",
				assurance: "static_candidate",
			});

			// First verification with A
			const concA = await evidenceStore.verifyHypothesis({
				hypothesisId: hyp.id,
				title: "Initial observation A",
				conclusion: "Algorithm candidate A works",
				status: "verified",
				method: "static_check",
				command: "check",
				result: "pass",
				reproducibility: "1/1",
				facts: [factA.id],
				target: targetFile,
				subject: "signing_algorithm",
			});

			await advanceWorkflow(
				wf,
				{ step_id: "s1", status: "completed", evidence_ids: [concA.id] },
				{ repositoryRoot: tmpDir, evidenceStore },
			);
			expect(wf.steps[0].status).toBe("completed");
			expect(getWorkflowAcceptanceCriteria(wf, "s1")[0].status).toBe("satisfied");

			// Refute A
			await evidenceStore.verifyHypothesis({
				hypothesisId: hyp.id,
				title: "Refutation of A",
				conclusion: "A proved incorrect at runtime",
				status: "refuted",
				method: "runtime_test",
				command: "run",
				result: "fail",
				reproducibility: "1/1",
				target: targetFile,
				subject: "signing_algorithm",
				invalidatesConclusions: [concA.id],
			});

			const cascade = await cascadeEvidenceRefutation(wf, evidenceStore);
			expect(cascade.invalidatedSteps).toContain("s1");
			expect(wf.steps[0].status).toBe("pending");

			const factB = await evidenceStore.addFact({
				kind: "fact",
				title: "Fact B",
				classification: "internal",
				target: targetFile,
				sourceTool: "grep",
				locator: "loc2",
				content: "data B",
				subject: "signing_algorithm",
				assurance: "static_candidate",
			});

			// Now re-verify with B
			const concB = await evidenceStore.verifyHypothesis({
				hypothesisId: hyp.id,
				title: "Corrected observation B",
				conclusion: "Algorithm candidate B verified",
				status: "verified",
				method: "fixed_check",
				command: "check_b",
				result: "pass",
				reproducibility: "1/1",
				facts: [factB.id],
				target: targetFile,
				subject: "signing_algorithm",
			});

			const resB = await advanceWorkflow(
				wf,
				{ step_id: "s1", status: "completed", evidence_ids: [concB.id] },
				{ repositoryRoot: tmpDir, evidenceStore },
			);
			expect(resB.advanced).toBe(true);
			expect(wf.steps[0].status).toBe("completed");
			expect(getWorkflowAcceptanceCriteria(wf, "s1")[0].status).toBe("satisfied");

			// Historical evidence_ids preserves both A and B for audit trail
			expect(wf.steps[0].evidence_ids).toContain(concA.id);
			expect(wf.steps[0].evidence_ids).toContain(concB.id);

			// Subsequent cascade check does NOT re-invalidate step because active proof is B!
			const subsequentCascade = await cascadeEvidenceRefutation(wf, evidenceStore);
			expect(subsequentCascade.invalidatedSteps.length).toBe(0);
			expect(wf.steps[0].status).toBe("completed");
		} finally {
			if (store) await fs.rm(store.projectDirectory, { recursive: true, force: true }).catch(() => undefined);
			if (evidenceStore)
				await fs.rm(evidenceStore.projectDirectory, { recursive: true, force: true }).catch(() => undefined);
			await fs.rm(tmpDir, { recursive: true, force: true });
		}
	});

	it("rejects acceptance criteria referencing unknown or orphan step IDs", async () => {
		const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-test-orphan-"));
		let store: ReverseWorkflowStore | undefined;
		try {
			store = new ReverseWorkflowStore({ repositoryRoot: tmpDir });
			let orphanError: Error | undefined;
			try {
				await store.create({
					target: "app.apk",
					format: "APK",
					steps: [
						{
							id: "s1",
							title: "Step 1",
							tool: "triage",
							gate: "G0",
							params_summary: {},
							status: "pending",
							attempts: 0,
							max_attempts: 3,
							created_at: new Date().toISOString(),
							updated_at: new Date().toISOString(),
						},
					],
					acceptance_criteria: [
						{ id: "ac_orphan", step_id: "nonexistent_step_5", title: "Orphan", subject: "some_subject" },
					],
				});
			} catch (err) {
				orphanError = err as Error;
			}

			expect(orphanError).toBeDefined();
			expect(orphanError?.message).toContain("references unknown step 'nonexistent_step_5'");
		} finally {
			if (store) await fs.rm(store.projectDirectory, { recursive: true, force: true }).catch(() => undefined);
			await fs.rm(tmpDir, { recursive: true, force: true });
		}
	});

	it("authorizes lab experimental builds with external phone oracle but blocks delivery builds", async () => {
		const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-test-lab-exp-"));
		let store: ReverseWorkflowStore | undefined;
		try {
			const targetFile = path.join(tmpDir, "app.apk");
			await fs.writeFile(targetFile, "dummy apk content");

			store = new ReverseWorkflowStore({ repositoryRoot: tmpDir });
			const wf = await store.create({
				target: "app.apk",
				format: "APK",
				goal: "Vehicle IVI deployment",
				target_device_constraints: {
					target_environment: "vehicle_ivi",
					requires_standalone: true,
					disallowed_dependencies: ["phone_oracle"],
				},
				dependencies: [
					{
						id: "dep_worker",
						name: "Arbitrary External Worker",
						kind: "external_service",
						scope: "experiment",
						target_host: "remote_server",
						approved_for_experiment: true,
					},
				],
			});

			// Lab experiment derivative registration is permitted
			const expBuild = await store.registerDerivative(wf.id, {
				target_path: targetFile,
				scope: "experiment",
			});
			expect(expBuild.build_id).toBeDefined();

			// Delivery derivative registration with same dependencies is rejected
			let deliveryError: Error | undefined;
			try {
				await store.registerDerivative(wf.id, {
					target_path: targetFile,
					scope: "delivery",
				});
			} catch (err) {
				deliveryError = err as Error;
			}
			expect(deliveryError).toBeDefined();
			expect(deliveryError?.message).toContain("VIOLATION_EXPERIMENTAL_DEPENDENCY_IN_DELIVERY");
		} finally {
			if (store) await fs.rm(store.projectDirectory, { recursive: true, force: true }).catch(() => undefined);
			await fs.rm(tmpDir, { recursive: true, force: true });
		}
	});

	it("cascades evidence refutation to derivative build lineage and invalidates runtime verified status", async () => {
		const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-test-build-refute-"));
		let store: ReverseWorkflowStore | undefined;
		let evidenceStore: EvidenceStore | undefined;
		try {
			const targetFile = path.join(tmpDir, "app.apk");
			await fs.writeFile(targetFile, "dummy apk content");

			store = new ReverseWorkflowStore({ repositoryRoot: tmpDir });
			evidenceStore = new EvidenceStore({ repositoryRoot: tmpDir });

			const wf = await store.create({
				target: "app.apk",
				format: "APK",
			});

			const hyp = await evidenceStore.addHypothesis({
				kind: "hypothesis",
				title: "Hypothesis",
				claim: "Derivative executes successfully",
				verificationPlan: "Check execution",
				target: targetFile,
			});

			const conc = await evidenceStore.verifyHypothesis({
				hypothesisId: hyp.id,
				title: "Execution verified",
				conclusion: "App started cleanly",
				status: "verified",
				method: "run",
				command: "start",
				result: "pass",
				reproducibility: "1/1",
				target: targetFile,
				targetSha256: wf.target_sha256,
			});

			// Register derivative with runtime evidence
			const bld = await store.registerDerivative(wf.id, {
				target_path: targetFile,
				runtime_evidence_ids: [conc.id],
			});
			expect(bld.verification_result.runtime_status).toBe("verified");

			// Now refute the runtime evidence
			await evidenceStore.verifyHypothesis({
				hypothesisId: hyp.id,
				title: "Execution refuted",
				conclusion: "Fatal exception PID 32936",
				status: "refuted",
				method: "run",
				command: "start",
				result: "fail",
				reproducibility: "1/1",
				target: targetFile,
				targetSha256: wf.target_sha256,
				invalidatesConclusions: [conc.id],
			});

			// Reload fresh workflow from store and cascade refutation
			const freshWf = (await store.get(wf.id))!;
			const cascade = await cascadeEvidenceRefutation(freshWf, evidenceStore);
			expect(cascade.invalidatedBuilds).toContain(bld.build_id);

			const updatedBuild = freshWf.build_lineage?.find(b => b.build_id === bld.build_id);
			expect(updatedBuild?.verification_result.runtime_status).toBe("failed");
			expect(updatedBuild?.verification_result.status).toBe("failed");
			expect(updatedBuild?.verification_result.failure_reason).toContain(
				"Runtime verification evidence was refuted",
			);

			// verifyDerivative also actively detects the refuted runtime evidence
			const verifyRes = await store.verifyDerivative(wf.id, bld.build_id);
			expect(verifyRes.runtime_status).toBe("failed");
			expect(verifyRes.status).toBe("failed");
		} finally {
			if (store) await fs.rm(store.projectDirectory, { recursive: true, force: true }).catch(() => undefined);
			if (evidenceStore)
				await fs.rm(evidenceStore.projectDirectory, { recursive: true, force: true }).catch(() => undefined);
			await fs.rm(tmpDir, { recursive: true, force: true });
		}
	});

	it("keeps workflow status active if steps complete or skip while criteria remain unresolved", async () => {
		const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-test-unresolved-"));
		let store: ReverseWorkflowStore | undefined;
		try {
			const targetFile = path.join(tmpDir, "app.apk");
			await fs.writeFile(targetFile, "dummy apk content");

			store = new ReverseWorkflowStore({ repositoryRoot: tmpDir });
			const wf = await store.create({
				target: "app.apk",
				format: "APK",
				acceptance_criteria: [{ id: "ac_req", step_id: "s1", title: "Mandatory", subject: "live_traffic" }],
				steps: [
					{
						id: "s1",
						title: "Step 1",
						tool: "triage",
						gate: "G0",
						params_summary: {},
						status: "pending",
						attempts: 0,
						max_attempts: 3,
						created_at: new Date().toISOString(),
						updated_at: new Date().toISOString(),
					},
				],
			});

			// Skip step 1: step status becomes skipped, but criterion is NOT satisfied
			const tool = new ReverseWorkflowTool(createSession(tmpDir));
			await tool.execute("c1", {
				action: "record",
				workflow_id: wf.id,
				step_id: "s1",
				status: "skipped",
			});

			const refreshed = await store.get(wf.id);
			expect(refreshed?.steps[0].status).toBe("skipped");
			expect(refreshed?.status).toBe("active"); // MUST REMAIN ACTIVE because ac_req is pending!

			const m = computeWorkflowMetrics(refreshed!.steps, refreshed!.metadata);
			expect(m.satisfied_acceptance_criteria).toBe(0);
			expect(m.acceptance_completion_ratio).toBe(0);
		} finally {
			if (store) await fs.rm(store.projectDirectory, { recursive: true, force: true }).catch(() => undefined);
			await fs.rm(tmpDir, { recursive: true, force: true });
		}
	});
});
