import { describe, expect, it } from "bun:test";
import { Settings } from "../../src/config/settings";
import { resolveApproval, type ApprovalMode } from "../../src/tools/approval";
import { AndroidNativeWorkflowTool } from "../../src/tools/android-native-workflow";
import { UnidbgTool } from "../../src/tools/unidbg";
import { ApkArtifactTool } from "../../src/tools/apk-artifact";
import { FridaSessionTool } from "../../src/tools/frida-session";
import { WriteTool } from "../../src/tools/write";
import { resolveXdevTool, type XdevState } from "../../src/tools/xdev";
import type { Tool, ToolSession } from "../../src/tools";
import { assessStepRisk } from "../../src/reverse-workflow/progression";
import type { WorkflowStepRecord } from "../../src/reverse-workflow/contracts";

function createTestSession(cwd = "/tmp", overrides: Partial<ToolSession> = {}): ToolSession {
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
		...overrides,
	};
}

function createTestXdevState(tools: Tool[]): XdevState {
	const state: XdevState = {
		tools: new Map(tools.map(t => [t.name, t])),
		mountedNames: new Set(tools.map(t => t.name)),
		builtInNames: new Set(tools.map(t => t.name)),
		isActive: () => false,
		resolve: name => resolveXdevTool(state, name),
	};
	return state;
}

describe("P1 Reverse Tools Approval Tiers Matrix", () => {
	const session = createTestSession();
	const nativeWorkflow = new AndroidNativeWorkflowTool(session);
	const unidbg = new UnidbgTool(session);
	const apkArtifact = new ApkArtifactTool(session);
	const fridaSession = new FridaSessionTool(session);

	// 1. Table-driven essential read / write / exec policy boundaries
	interface TierCase {
		tool: Tool;
		args: Record<string, unknown>;
		tier: "read" | "write" | "exec";
		alwaysAskPolicy: "allow" | "prompt";
		writeModePolicy: "allow" | "prompt";
	}

	const TIER_CASES: TierCase[] = [
		// android_native_workflow
		{
			tool: nativeWorkflow,
			args: { action: "inspect" },
			tier: "read",
			alwaysAskPolicy: "allow",
			writeModePolicy: "allow",
		},
		{
			tool: nativeWorkflow,
			args: { action: "plan" },
			tier: "read",
			alwaysAskPolicy: "allow",
			writeModePolicy: "allow",
		},
		{
			tool: nativeWorkflow,
			args: { action: "status" },
			tier: "read",
			alwaysAskPolicy: "allow",
			writeModePolicy: "allow",
		},
		{
			tool: nativeWorkflow,
			args: { action: "extract" },
			tier: "write",
			alwaysAskPolicy: "prompt",
			writeModePolicy: "allow",
		},
		// unidbg
		{ tool: unidbg, args: { action: "status" }, tier: "read", alwaysAskPolicy: "allow", writeModePolicy: "allow" },
		{
			tool: unidbg,
			args: { action: "scaffold" },
			tier: "write",
			alwaysAskPolicy: "prompt",
			writeModePolicy: "allow",
		},
		{ tool: unidbg, args: { action: "build" }, tier: "exec", alwaysAskPolicy: "prompt", writeModePolicy: "prompt" },
		{ tool: unidbg, args: { action: "launch" }, tier: "exec", alwaysAskPolicy: "prompt", writeModePolicy: "prompt" },
		{ tool: unidbg, args: { action: "probe" }, tier: "exec", alwaysAskPolicy: "prompt", writeModePolicy: "prompt" },
		{ tool: unidbg, args: { action: "stop" }, tier: "exec", alwaysAskPolicy: "prompt", writeModePolicy: "prompt" },
		// apk_artifact
		{ tool: apkArtifact, args: { action: "diff" }, tier: "read", alwaysAskPolicy: "allow", writeModePolicy: "allow" },
		{
			tool: apkArtifact,
			args: { action: "verify" },
			tier: "read",
			alwaysAskPolicy: "allow",
			writeModePolicy: "allow",
		},
		{
			tool: apkArtifact,
			args: { action: "repack" },
			tier: "write",
			alwaysAskPolicy: "prompt",
			writeModePolicy: "allow",
		},
		{
			tool: apkArtifact,
			args: { action: "sign" },
			tier: "write",
			alwaysAskPolicy: "prompt",
			writeModePolicy: "allow",
		},
		{
			tool: apkArtifact,
			args: { action: "install_verify" },
			tier: "exec",
			alwaysAskPolicy: "prompt",
			writeModePolicy: "prompt",
		},
		// frida_session
		{
			tool: fridaSession,
			args: { action: "list" },
			tier: "read",
			alwaysAskPolicy: "allow",
			writeModePolicy: "allow",
		},
		{
			tool: fridaSession,
			args: { action: "events", clear: true },
			tier: "write",
			alwaysAskPolicy: "prompt",
			writeModePolicy: "allow",
		},
		{
			tool: fridaSession,
			args: { action: "run" },
			tier: "exec",
			alwaysAskPolicy: "prompt",
			writeModePolicy: "prompt",
		},
	];

	it("resolves essential read/write/exec policy boundaries across tools", () => {
		for (const { tool, args, tier, alwaysAskPolicy, writeModePolicy } of TIER_CASES) {
			const alwaysAsk = resolveApproval(tool, args, "always-ask");
			expect(alwaysAsk.tier).toBe(tier);
			expect(alwaysAsk.policy).toBe(alwaysAskPolicy);

			const writeMode = resolveApproval(tool, args, "write");
			expect(writeMode.tier).toBe(tier);
			expect(writeMode.policy).toBe(writeModePolicy);
		}
	});

	// 2. Unknown or missing actions fail closed to exec tier
	it("fails closed to exec for unknown or missing actions", () => {
		const unknownSubjects: Array<[Tool, unknown]> = [
			[nativeWorkflow, { action: "unrecognized" }],
			[nativeWorkflow, {}],
			[nativeWorkflow, null],
			[unidbg, { action: "unknown_act" }],
			[unidbg, {}],
			[apkArtifact, { action: "evil_action" }],
			[apkArtifact, null],
		];

		for (const [tool, args] of unknownSubjects) {
			const res = resolveApproval(tool, args, "write");
			expect(res.tier).toBe("exec");
			expect(res.policy).toBe("prompt");
		}
	});

	// 3. Explicit user policy deny wins over mode and tool declaration
	it("enforces that explicit user policy deny wins over mode", () => {
		const denyCases: Array<[Tool, string, Record<string, unknown>]> = [
			[nativeWorkflow, "android_native_workflow", { action: "inspect" }],
			[unidbg, "unidbg", { action: "status" }],
			[apkArtifact, "apk_artifact", { action: "diff" }],
		];

		for (const [tool, name, args] of denyCases) {
			const res = resolveApproval(tool, args, "yolo", { [name]: "deny" });
			expect(res.policy).toBe("deny");
			expect(res.source).toBe("user");
		}
	});

	// 4. Wrapped xd:// write dispatch preserves inner tool tier and policyKey (no bypass)
	it("preserves inner tool tier and policyKey on xd:// write dispatch without bypass", () => {
		const xdev = createTestXdevState([nativeWorkflow, unidbg, apkArtifact]);
		const writeTool = new WriteTool(createTestSession("/tmp", { xdev }));

		const xdDispatches: Array<{
			device: string;
			args: Record<string, unknown>;
			tier: "read" | "write" | "exec";
			mode: ApprovalMode;
			expectedPolicy: "allow" | "prompt";
		}> = [
			{
				device: "android_native_workflow",
				args: { action: "inspect" },
				tier: "read",
				mode: "always-ask",
				expectedPolicy: "allow",
			},
			{
				device: "android_native_workflow",
				args: { action: "extract" },
				tier: "write",
				mode: "always-ask",
				expectedPolicy: "prompt",
			},
			{ device: "unidbg", args: { action: "launch" }, tier: "exec", mode: "write", expectedPolicy: "prompt" },
			{
				device: "apk_artifact",
				args: { action: "install_verify" },
				tier: "exec",
				mode: "write",
				expectedPolicy: "prompt",
			},
		];

		for (const { device, args, tier, mode, expectedPolicy } of xdDispatches) {
			const payload = { path: `xd://${device}`, content: JSON.stringify(args) };
			const res = resolveApproval(writeTool, payload, mode);
			expect(res.tier).toBe(tier);
			expect(res.policy).toBe(expectedPolicy);
		}
		// Device-scoped user policy takes precedence over write blanket policy
		const deviceDeny = resolveApproval(
			writeTool,
			{ path: "xd://unidbg", content: JSON.stringify({ action: "status" }) },
			"yolo",
			{ unidbg: "deny" },
		);
		expect(deviceDeny.policy).toBe("deny");
		expect(deviceDeny.policyKey).toBe("unidbg");
	});

	// 5. Progression assessStepRisk action-level safety
	describe("Progression assessStepRisk action-level safety", () => {
		const now = new Date().toISOString();
		const makeStep = (tool: string, params: Record<string, unknown> | string): WorkflowStepRecord => ({
			id: "step_test",
			title: "Risk Step",
			tool,
			gate: "G1",
			params_summary: params,
			status: "pending",
			attempts: 0,
			max_attempts: 3,
			created_at: now,
			updated_at: now,
		});

		it("classifies read-only actions as low risk", () => {
			for (const action of ["inspect", "plan", "status"]) {
				const res = assessStepRisk(makeStep("android_native_workflow", { action }));
				expect(res.is_low_risk).toBe(true);
				expect(res.risk_level).toBe("low");
			}
			for (const action of ["list", "resolve", "status", "get"]) {
				const res = assessStepRisk(makeStep("reverse_capability", { action }));
				expect(res.is_low_risk).toBe(true);
				expect(res.risk_level).toBe("low");
			}
		});

		it("blocks extract and install from low-risk auto-progression", () => {
			const extractRes = assessStepRisk(makeStep("android_native_workflow", { action: "extract" }));
			expect(extractRes.is_low_risk).toBe(false);
			expect(extractRes.risk_level).toBe("high");

			const installRes = assessStepRisk(makeStep("reverse_capability", { action: "install" }));
			expect(installRes.is_low_risk).toBe(false);
			expect(installRes.risk_level).toBe("high");
		});

		it("defaults unlisted tools to high risk", () => {
			const res = assessStepRisk(makeStep("app_experiment", { action: "observe" }));
			expect(res.is_low_risk).toBe(false);
			expect(res.risk_level).toBe("high");
		});
	});
});
