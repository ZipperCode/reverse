import { describe, expect, it } from "bun:test";
import { classifyFailure, resolveCapabilityRecovery, generateRecoveryPlan } from "../../src/reverse-workflow/recovery";
import { assessStepRisk } from "../../src/reverse-workflow/progression";
import type { WorkflowStepRecord, ReverseWorkflowRecord } from "../../src/reverse-workflow/contracts";

describe("Protection Analysis Routing & Recovery Plans", () => {
	it("classifies missing protection tool dependencies with canonical setup commands", () => {
		const protectionTools = [
			{ error: "command not found: frida-dexdump", expectedTool: "frida-dexdump" },
			{ error: "frida-dexdump: command not found", expectedTool: "frida-dexdump" },
			{ error: "frida: command not found", expectedTool: "frida" },
			{ error: "dexkit native library not found on path", expectedTool: "dexkit" },
			{ error: "d810-ng package not found in python environment", expectedTool: "d810-ng" },
			{ error: "cannot find simplify jar on path", expectedTool: "simplify" },
			{ error: "msynth python module not found", expectedTool: "msynth" },
			{ error: "blackdex apk not found on device", expectedTool: "blackdex" },
			{ error: "qbdi native runtime not found on path", expectedTool: "qbdi" },
			{ error: "tritondse: command not found", expectedTool: "tritondse" },
		];

		for (const { error, expectedTool } of protectionTools) {
			const attribution = classifyFailure(error);
			expect(attribution.category).toBe("missing_dependency");
			expect(attribution.missing_tool).toBe(expectedTool);
			expect(attribution.install_hint).toBeDefined();
			expect(attribution.setup_command).toContain(expectedTool);
		}
	});

	it("resolves structured capability recovery for DEX unpacking and repair without device execution", () => {
		const unpackRecovery = resolveCapabilityRecovery("dex_runtime_unpacking", {
			targetPath: "sample.apk",
			targetFormat: "APK",
		});
		expect(unpackRecovery).toBeDefined();
		expect(unpackRecovery!.nextTool).toBe("android_package_inspect");
		expect(unpackRecovery!.nextParams).toEqual({ path: "sample.apk", action: "dex" });

		const repairRecovery = resolveCapabilityRecovery("dex_codeitem_repair", {
			targetPath: "classes.dex",
			targetFormat: "APK",
		});
		expect(repairRecovery).toBeDefined();
		expect(repairRecovery!.nextTool).toBe("dex_patch");
		expect(repairRecovery!.nextParams).toEqual({ path: "classes.dex", dry_run: true });
	});

	it("resolves structured capability recovery for instruction trace and native recovery without arbitrary seeds", () => {
		const traceRecovery = resolveCapabilityRecovery("instruction_trace_capture", {
			targetPath: "sample.elf",
			targetFormat: "ELF",
		});
		expect(traceRecovery).toBeDefined();
		expect(traceRecovery!.nextTool).toBe("r2_inspect");

		const nativeRecovery = resolveCapabilityRecovery("native_path_recovery", {
			targetPath: "sample.so",
			targetFormat: "ELF",
		});
		expect(nativeRecovery).toBeDefined();
		expect(nativeRecovery!.nextTool).toBe("triton_analyze");
		expect(nativeRecovery!.nextParams).toEqual({ action: "status" });
		// Must not contain arbitrary default seeds or fabricated parameters
		expect((nativeRecovery!.nextParams as Record<string, unknown>).seed).toBeUndefined();
	});

	it("restricts progression to low risk only for status read actions on protection tools", () => {
		const protectionTools = [
			"dex_unpack",
			"dex_repair",
			"instruction_trace",
			"dex_search",
			"deobfuscate",
			"native_recover",
			"triton_analyze",
		];

		const now = new Date().toISOString();

		for (const tool of protectionTools) {
			// Status read action MUST be classified as low risk
			const statusStep: WorkflowStepRecord = {
				id: `${tool}_status_step`,
				title: `Check ${tool} status`,
				tool,
				gate: "G1",
				params_summary: { action: "status" },
				status: "pending",
				attempts: 0,
				max_attempts: 3,
				created_at: now,
				updated_at: now,
			};
			const statusRisk = assessStepRisk(statusStep);
			expect(statusRisk.is_low_risk).toBe(true);
			expect(statusRisk.risk_level).toBe("low");

			// Any execution/write action MUST be classified as high risk or dynamic
			const execAction =
				tool === "dex_unpack"
					? "dump"
					: tool === "dex_repair"
						? "repair"
						: tool === "instruction_trace"
							? "capture"
							: tool === "deobfuscate"
								? "analyze"
								: tool === "native_recover"
									? "explore"
									: "replay";

			const execStep: WorkflowStepRecord = {
				id: `${tool}_exec_step`,
				title: `Execute ${tool}`,
				tool,
				gate: "G3",
				params_summary: { action: execAction },
				status: "pending",
				attempts: 0,
				max_attempts: 3,
				created_at: now,
				updated_at: now,
			};
			const execRisk = assessStepRisk(execStep);
			expect(execRisk.is_low_risk).toBe(false);
			expect(["high", "dynamic"]).toContain(execRisk.risk_level);
		}
	});

	it("generates deterministic recovery plan for failed protection steps without arbitrary device serials", () => {
		const now = new Date().toISOString();
		const mockWorkflow: ReverseWorkflowRecord = {
			id: "wf_test_protection",
			target: "app.apk",
			target_abs_path: "/tmp/app.apk",
			format: "APK",
			status: "active",
			created_at: now,
			updated_at: now,
			steps: [],
			metadata: {
				current_gate: "G2",
				evidence_ledger_ids: [],
				knowledge_record_ids: [],
				environment: { target_architecture: "arm64-v8a" },
			},
		};

		const failedStep: WorkflowStepRecord = {
			id: "step_unpack",
			title: "Unpack DEX via frida-dexdump",
			tool: "dex_unpack",
			gate: "G2",
			params_summary: { action: "dump", backend: "frida-dexdump" },
			status: "failed",
			attempts: 1,
			max_attempts: 3,
			created_at: now,
			updated_at: now,
			error: "command not found: frida-dexdump",
		};

		const plan = generateRecoveryPlan(failedStep, mockWorkflow);
		expect(plan.suggested_action).toBe("fallback");
		expect(plan.next_tool).toBe("android_package_inspect");
		expect(plan.can_retry).toBe(true);
		// Crucially, must not invent a fake device serial like 'emulator-5554'
		const nextParams = plan.next_params as Record<string, unknown>;
		expect(nextParams.device).toBeUndefined();
		expect(nextParams.action).toBe("dex");
	});
});
