import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "@reverse/coding-agent/config/settings";
import { createTools, ReverseDynamicEvidenceTool, type ToolSession, BUILTIN_TOOLS } from "@reverse/coding-agent/tools";
import { BUILTIN_TOOL_NAMES, normalizeToolName } from "@reverse/coding-agent/tools/builtin-names";
import { removeWithRetries } from "@reverse/utils";
import { EvidenceStore, type FactEvidence, type ConclusionEvidence } from "@reverse/coding-agent/evidence";
import { ReverseWorkflowStore, advanceWorkflow } from "@reverse/coding-agent/reverse-workflow";
import { ReverseKnowledgeStore } from "@reverse/coding-agent/reverse-knowledge";
import { ReverseRuntimeSessionStore, type RuntimeSessionRecord } from "@reverse/coding-agent/reverse-runtime-session";
import {
	formatDynamicLocator,
	parseDynamicLocator,
	isDynamicLocator,
	normalizeFridaEvent,
	normalizeBrowserEvent,
	normalizeDapEvent,
	filterDynamicEvents,
	appendDynamicEvents,
	dynamicEventToFactInput,
	isQualifiedDynamicCallEvent,
	type UniversalDynamicEvent,
} from "@reverse/coding-agent/reverse-runtime-session/dynamic-events";

function createTestSession(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
	};
}

function textOf(result: { content: Array<{ type: string; text?: string } | { type: string }> }): string {
	return result.content
		.map(item => ("text" in item && typeof item.text === "string" ? item.text : ""))
		.join("\n")
		.trim();
}

function createRuntimeSessionFixture(
	id: string,
	kind: RuntimeSessionRecord["kind"],
	events: unknown[],
	status: RuntimeSessionRecord["status"] = "active",
): RuntimeSessionRecord {
	const now = new Date().toISOString();
	return {
		id,
		name: `Session ${id}`,
		kind,
		status,
		target_summary: "target",
		target_details: {},
		connection: {},
		recovery_hints: {
			restore_tool: kind === "browser" ? "browser_reverse_session" : "frida_session",
			restore_action: "open",
			restore_params: {},
			instructions: [],
		},
		created_at: now,
		updated_at: now,
		last_heartbeat_at: now,
		heartbeat_count: 1,
		stale_timeout_sec: 300,
		status_source: "registered",
		metadata: {
			events,
		},
	};
}

describe("reverse_dynamic_evidence tool registration and discovery", () => {
	it("registers in BUILTIN_TOOL_NAMES", () => {
		expect(BUILTIN_TOOL_NAMES).toContain("reverse_dynamic_evidence");
	});

	it("normalizes tool aliases to reverse_dynamic_evidence", () => {
		expect(normalizeToolName("reverse_dynamic_evidence")).toBe("reverse_dynamic_evidence");
		expect(normalizeToolName("dynamic_evidence")).toBe("reverse_dynamic_evidence");
		expect(normalizeToolName("reverse-dynamic-evidence")).toBe("reverse_dynamic_evidence");
		expect(normalizeToolName("dynamic_closure")).toBe("reverse_dynamic_evidence");
		expect(normalizeToolName("reverse_dynamic_closure")).toBe("reverse_dynamic_evidence");
	});

	it("instantiates via createTools and BUILTIN_TOOLS", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "dyn-ev-reg-"));
		try {
			const session = createTestSession(tempDir);
			const tools = await createTools(session, ["reverse_dynamic_evidence"]);
			const tool = tools.find(t => t.name === "reverse_dynamic_evidence");
			expect(tool).toBeDefined();
			expect(tool?.label).toBe("Reverse Dynamic Evidence & Closure");
			expect(tool?.strict).toBe(true);

			const direct = BUILTIN_TOOLS.reverse_dynamic_evidence(session);
			expect(direct).toBeInstanceOf(ReverseDynamicEvidenceTool);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("universal dynamic event normalization and contracts", () => {
	it("formats and parses dynamic locators deterministically", () => {
		const loc = formatDynamicLocator("runt_frida_abc", 42);
		expect(loc).toBe("session:runt_frida_abc:seq:42");
		expect(isDynamicLocator(loc)).toBe(true);
		expect(isDynamicLocator("0x14001A240")).toBe(false);
		expect(isDynamicLocator("main.c:50")).toBe(false);

		const parsed = parseDynamicLocator(loc);
		expect(parsed).toEqual({ sessionId: "runt_frida_abc", seq: 42 });
	});

	it("normalizes Frida events accurately", () => {
		const fridaMsg = {
			type: "send",
			payload: {
				action: "crypto_encrypt",
				algorithm: "AES/CBC/PKCS5Padding",
				key: "00112233445566778899aabbccddeeff",
			},
			channel: "send",
			seq: 3,
		};
		const normalized = normalizeFridaEvent(fridaMsg, "runt_frida_01", { target: "com.example.app" });
		expect(normalized.source).toBe("frida");
		expect(normalized.sessionId).toBe("runt_frida_01");
		expect(normalized.seq).toBe(3);
		expect(normalized.kind).toBe("message");
		expect(normalized.channel).toBe("send");
		expect(normalized.target).toBe("com.example.app");
	});

	it("normalizes Browser CDP / Hook events", () => {
		const hookEvent = {
			type: "crypto",
			operation: "subtle.encrypt",
			algorithm: "AES-GCM",
			keyLength: 256,
			url: "https://example.com/api/login",
			seq: 7,
		};
		const normalized = normalizeBrowserEvent(hookEvent, "browser_tab_main");
		expect(normalized.source).toBe("browser");
		expect(normalized.kind).toBe("crypto");
		expect(normalized.channel).toBe("crypto");
		expect(normalized.target).toBe("https://example.com/api/login");
		expect(normalized.seq).toBe(7);
	});

	it("retains CDP request initiators and top-level stack when event data exists", () => {
		const frame = {
			functionName: "sendRequest",
			scriptId: "12",
			url: "http://fixture/caller.js",
			lineNumber: 0,
			columnNumber: 9,
		};
		const event = normalizeBrowserEvent(
			{
				type: "request",
				id: "network:req_1",
				requestId: "req_1",
				seq: 8,
				url: "http://fixture/api",
				data: { method: "POST" },
				initiator: { type: "script", stack: { callFrames: [frame] } },
				stack: "hook clue only",
			},
			"browser_fixture",
		);
		expect(event.metadata?.callsite).toEqual({ url: frame.url, lineNumber: 0, columnNumber: 9 });
		expect(event.metadata?.stack).toBe("hook clue only");
		expect(event.metadata?.requestId).toBe("req_1");
		expect(event.metadata?.originalType).toBe("request");
		expect(event.payload).toEqual({ method: "POST" });
		expect(isQualifiedDynamicCallEvent(event)).toBe(true);
		const fact = dynamicEventToFactInput(event, { trustedSessionEvent: true });
		expect(fact.assurance).toBe("dynamic_call_observation");
		expect(fact.content).toContain("caller.js");
	});

	it("recognizes actual hook prefixes without upgrading self-reported string stacks", () => {
		for (const [type, kind, channel] of [
			["fetch_request", "network", "fetch"],
			["xhr_response", "network", "xhr"],
			["websocket_message", "network", "websocket"],
			["crypto_call", "crypto", "crypto"],
		] as const) {
			const event = normalizeBrowserEvent(
				{ type, data: "payload", stack: "at invented (bundle.js:1:1)" },
				"browser_fixture",
			);
			expect(event.kind).toBe(kind);
			expect(event.channel).toBe(channel);
			expect(event.metadata?.originalType).toBe(type);
			expect(event.metadata?.stack).toContain("bundle.js");
			expect(event.metadata?.callsite).toBeUndefined();
			expect(dynamicEventToFactInput(event, { trustedSessionEvent: true }).assurance).toBeUndefined();
		}
		const missing = normalizeBrowserEvent({ type: "request", initiator: { type: "parser" } }, "browser_fixture");
		expect(missing.metadata?.callsite).toBeUndefined();
		const invalid = normalizeBrowserEvent(
			{
				type: "request",
				initiator: {
					type: "script",
					stack: {
						callFrames: [{ url: "bundle.js", lineNumber: -1, columnNumber: 0 }],
					},
				},
			},
			"browser_fixture",
		);
		expect(invalid.metadata?.callsite).toBeUndefined();
	});

	it("normalizes DAP debugger events", () => {
		const dapEvent = {
			event: "stopped",
			body: {
				reason: "breakpoint",
				threadId: 1,
				description: "hit breakpoint 1 at 0x401240",
			},
			seq: 2,
		};
		const normalized = normalizeDapEvent(dapEvent, "dap_session_01", { target: "bin/target.elf" });
		expect(normalized.source).toBe("dap");
		expect(normalized.kind).toBe("breakpoint");
		expect(normalized.channel).toBe("stopped");
		expect(normalized.target).toBe("bin/target.elf");
		expect(normalized.seq).toBe(2);
	});

	it("filters and slices dynamic events boundedly", () => {
		const events: UniversalDynamicEvent[] = [
			{ id: "e1", source: "frida", sessionId: "s1", seq: 1, timestamp: "t1", kind: "stdout", channel: "output" },
			{ id: "e2", source: "frida", sessionId: "s1", seq: 2, timestamp: "t2", kind: "crypto", channel: "crypto" },
			{ id: "e3", source: "frida", sessionId: "s1", seq: 3, timestamp: "t3", kind: "network", channel: "ws" },
			{ id: "e4", source: "frida", sessionId: "s1", seq: 4, timestamp: "t4", kind: "crypto", channel: "crypto" },
		];

		const cryptoEvents = filterDynamicEvents(events, { kind: "crypto" });
		expect(cryptoEvents.length).toBe(2);
		expect(cryptoEvents.map(e => e.seq)).toEqual([2, 4]);

		const sinceSeq2 = filterDynamicEvents(events, { sinceSeq: 2 });
		expect(sinceSeq2.length).toBe(2);
		expect(sinceSeq2.map(e => e.seq)).toEqual([3, 4]);

		const limited = filterDynamicEvents(events, { limit: 2 });
		expect(limited.length).toBe(2);
	});

	it("enforces capacity cap when appending dynamic events", () => {
		let buffer: UniversalDynamicEvent[] = [];
		const batch: UniversalDynamicEvent[] = Array.from({ length: 50 }, (_, i) => ({
			id: `e_${i}`,
			source: "frida",
			sessionId: "s",
			seq: i + 1,
			timestamp: "t",
			kind: "message",
		}));

		buffer = appendDynamicEvents(buffer, batch, 20);
		expect(buffer.length).toBe(20);
		expect(buffer[0].seq).toBe(31);
		expect(buffer[19].seq).toBe(50);
	});

	it("converts dynamic events to sanitized Evidence facts", () => {
		const ev: UniversalDynamicEvent = {
			id: "ev_1",
			source: "browser",
			sessionId: "tab_1",
			seq: 12,
			timestamp: "2026-10-18T00:00:00Z",
			kind: "crypto",
			channel: "crypto",
			target: "https://example.com/auth",
			payload: {
				cipher: "AES-CBC",
				token: "super_secret_bearer_token_1234567890",
			},
			raw: "crypto.subtle.encrypt(AES-CBC, token: super_secret_bearer_token_1234567890)",
		};

		const fact = dynamicEventToFactInput(ev);
		expect(fact.kind).toBe("fact");
		expect(fact.sourceTool).toBe("browser_reverse_session");
		expect(fact.locator).toBe("session:tab_1:seq:12");
		expect(fact.target).toBe("https://example.com/auth");
		expect(fact.classification).toBe("CWE-311");
		expect(fact.tags).toContain("dynamic");
		expect(fact.tags).toContain("crypto");
		expect(fact.content).not.toContain("super_secret_bearer_token_1234567890");
	});

	it("validates structured callsites and assigns dynamic_call_observation only to trusted call events", () => {
		const webCallEvent: UniversalDynamicEvent = {
			id: "ev_web_1",
			source: "browser",
			sessionId: "browser_1",
			seq: 1,
			timestamp: "2026-10-18T00:00:00Z",
			kind: "network",
			channel: "request",
			target: "https://example.com/page",
			payload: { method: "POST", url: "https://example.com/api/sign" },
			metadata: {
				callsite: {
					url: "https://example.com/static/caller.js",
					lineNumber: 0,
					columnNumber: 14,
				},
			},
		};
		expect(isQualifiedDynamicCallEvent(webCallEvent)).toBe(true);

		const untrustedFact = dynamicEventToFactInput(webCallEvent, { subject: "sign_request" });
		expect(untrustedFact.assurance).toBeUndefined();
		expect(untrustedFact.subject).toBe("sign_request");

		const trustedFact = dynamicEventToFactInput(webCallEvent, {
			subject: "sign_request",
			trustedSessionEvent: true,
		});
		expect(trustedFact.assurance).toBe("dynamic_call_observation");
		expect(trustedFact.subject).toBe("sign_request");
		expect(trustedFact.content).toContain("https://example.com/static/caller.js:1:15");

		const nativeCallEvent: UniversalDynamicEvent = {
			id: "ev_native_1",
			source: "frida",
			sessionId: "frida_1",
			seq: 2,
			timestamp: "2026-10-18T00:00:00Z",
			kind: "trace",
			channel: "trace",
			target: "libnative.so",
			payload: "AES_encrypt entered",
			metadata: {
				callsite: {
					module: "libnative.so",
					address: "0x401240",
				},
			},
		};
		expect(isQualifiedDynamicCallEvent(nativeCallEvent)).toBe(true);
		expect(dynamicEventToFactInput(nativeCallEvent, { trustedSessionEvent: true }).assurance).toBe(
			"dynamic_call_observation",
		);

		// Console/message event even with valid callsite cannot qualify as dynamic call observation
		const consoleWithCallsite: UniversalDynamicEvent = {
			...webCallEvent,
			id: "ev_console_1",
			kind: "message",
			channel: "console",
		};
		expect(isQualifiedDynamicCallEvent(consoleWithCallsite)).toBe(false);
		expect(dynamicEventToFactInput(consoleWithCallsite, { trustedSessionEvent: true }).assurance).toBeUndefined();

		// Free-form stack string without structured callsite is rejected
		const stringStackOnly: UniversalDynamicEvent = {
			...webCallEvent,
			id: "ev_stack_1",
			metadata: {
				stack: "Error\n    at sign (https://example.com/static/caller.js:1:15)",
			},
		};
		expect(isQualifiedDynamicCallEvent(stringStackOnly)).toBe(false);
		const noCallsiteFact = dynamicEventToFactInput(stringStackOnly, { trustedSessionEvent: true });
		expect(noCallsiteFact.assurance).toBeUndefined();
		expect(noCallsiteFact.content).toContain("Callsite: unavailable");

		// Unprefixed all-alpha hex address ("deadbeef") and omitted columnNumber are valid
		expect(
			isQualifiedDynamicCallEvent({
				...nativeCallEvent,
				metadata: { callsite: { module: "libnative.so", address: "deadbeef" } },
			}),
		).toBe(true);
		expect(
			isQualifiedDynamicCallEvent({
				...webCallEvent,
				metadata: { callsite: { url: "https://example.com/a.js", lineNumber: 0 } },
			}),
		).toBe(true);

		// Negative lineNumber, null/negative/float columnNumber, or non-hex address is rejected
		expect(
			isQualifiedDynamicCallEvent({
				...webCallEvent,
				metadata: { callsite: { url: "https://example.com/a.js", lineNumber: -1 } },
			}),
		).toBe(false);
		expect(
			isQualifiedDynamicCallEvent({
				...webCallEvent,
				metadata: { callsite: { url: "https://example.com/a.js", lineNumber: 0, columnNumber: null } },
			}),
		).toBe(false);
		expect(
			isQualifiedDynamicCallEvent({
				...webCallEvent,
				metadata: { callsite: { url: "https://example.com/a.js", lineNumber: 0, columnNumber: -1 } },
			}),
		).toBe(false);
		expect(
			isQualifiedDynamicCallEvent({
				...webCallEvent,
				metadata: { callsite: { url: "https://example.com/a.js", lineNumber: 0, columnNumber: 1.5 } },
			}),
		).toBe(false);
		expect(
			isQualifiedDynamicCallEvent({
				...nativeCallEvent,
				metadata: { callsite: { module: "libnative.so", address: "not_hex_addr" } },
			}),
		).toBe(false);
		expect(
			isQualifiedDynamicCallEvent({
				...nativeCallEvent,
				metadata: { callsite: { module: "libnative.so", address: "0x" } },
			}),
		).toBe(false);
	});
});

describe("reverse_dynamic_evidence tool operations", () => {
	it("ingests explicit dynamic events into Evidence ledger", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "dyn-ev-ingest-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new ReverseDynamicEvidenceTool(session);

			const events = [
				{
					type: "send",
					channel: "crypto",
					payload: { op: "AES_encrypt", key: "0011223344" },
					seq: 1,
				},
				{
					type: "send",
					channel: "network",
					payload: { method: "POST", url: "/api/verify" },
					seq: 2,
				},
			];

			const res = await tool.execute("call_1", {
				action: "ingest",
				session_id: "frida_apk_session",
				source: "frida",
				target: "com.target.app",
				events,
			});

			expect(res.details.eventsCount).toBe(2);
			expect(res.details.factIds?.length).toBe(2);
			expect(textOf(res)).toContain("Ingested 2 dynamic fact(s)");

			// Verify in EvidenceStore
			const evidenceStore = EvidenceStore.forSession(tempDir);
			const allFacts = await evidenceStore.listRecords();
			expect(allFacts.items.length).toBe(2);
			expect(allFacts.items[0].kind).toBe("fact");
			const firstFact = allFacts.items[0] as FactEvidence;
			expect(firstFact.locator).toBe("session:frida_apk_session:seq:1");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("blocks static conclusions and untrusted events at dynamic workflow gate, and advances only on trusted dynamic call observation", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "dyn-ev-wf-"));
		try {
			const session = createTestSession(tempDir);
			const evidenceStore = EvidenceStore.forSession(tempDir);
			const workflowStore = ReverseWorkflowStore.forSession(tempDir);
			const runtimeStore = ReverseRuntimeSessionStore.forSession(tempDir);

			// Setup real sample file and workflow with actual dynamic frida step (G3)
			await fs.writeFile(path.join(tempDir, "libdecrypt.so"), "fake-elf-jni-sample");
			const wf = await workflowStore.create({
				target: "libdecrypt.so",
				format: "ELF",
				goal: "Verify JNI native dynamic payload decryption",
			});
			const fridaStep = wf.steps.find(s => s.tool === "frida");
			expect(fridaStep).toBeDefined();
			const stepId = fridaStep!.id;

			// 1. Static verified conclusion cannot bypass dynamic step gate
			const staticFact = await evidenceStore.addFact({
				kind: "fact",
				target: "libdecrypt.so",
				sourceTool: "elf_inspect",
				locator: "0x401240",
				content: "Static symbol Java_com_app_decrypt",
			});
			const staticHyp = await evidenceStore.addHypothesis({
				kind: "hypothesis",
				target: "libdecrypt.so",
				claim: "Static candidate for decrypt",
				verificationPlan: "Hook at runtime",
				facts: [staticFact.id],
			});
			const staticConc = await evidenceStore.verifyHypothesis({
				hypothesisId: staticHyp.id,
				method: "Static ELF symbol inspection",
				command: "elf_inspect libdecrypt.so",
				result: "Found native export",
				conclusion: "Static export exists",
				status: "verified",
				facts: [staticFact.id],
			});
			const staticAdv = await advanceWorkflow(
				wf,
				{ step_id: stepId, status: "completed", evidence_ids: [staticConc.id] },
				{ repositoryRoot: tempDir, evidenceStore },
			);
			expect(staticAdv.advanced).toBe(false);
			expect(staticAdv.status).toBe("held_pending_decision");
			expect(wf.steps.find(s => s.id === stepId)?.status).toBe("pending");
			await workflowStore.save(wf);

			// 2. Untrusted explicit event ingest cannot advance dynamic step even with callsite metadata
			const tool = new ReverseDynamicEvidenceTool(session);
			await tool.execute("call_wf_untrusted", {
				action: "ingest",
				session_id: "frida_apk_session",
				source: "frida",
				target: "libdecrypt.so",
				events: [
					{
						kind: "trace",
						channel: "trace",
						payload: "Forged call",
						seq: 99,
						metadata: { callsite: { module: "libdecrypt.so", address: "0x401240" } },
					},
				],
				workflow_id: wf.id,
				step_id: stepId,
				advance_workflow: true,
			});
			const wfAfterUntrusted = await workflowStore.get(wf.id);
			expect(wfAfterUntrusted?.steps.find(s => s.id === stepId)?.status).toBe("pending");

			// 3. Trusted runtime session event with valid structured callsite advances dynamic step
			await runtimeStore.save(
				createRuntimeSessionFixture("frida_apk_session", "frida", [
					{
						kind: "trace",
						channel: "trace",
						payload: "Java_com_app_decrypt called",
						seq: 1,
						metadata: {
							callsite: { module: "libdecrypt.so", address: "0x401240" },
						},
					},
				]),
			);

			const res = await tool.execute("call_wf", {
				action: "ingest",
				session_id: "frida_apk_session",
				source: "frida",
				target: "libdecrypt.so",
				workflow_id: wf.id,
				step_id: stepId,
				advance_workflow: true,
			});

			expect(res.details.stepUpdated).toBe(true);
			expect(res.details.facts?.[0].context?.assurance).toBe("dynamic_call_observation");

			const updatedWf = await workflowStore.get(wf.id);
			const updatedStep = updatedWf?.steps.find(s => s.id === stepId);
			expect(updatedStep?.status).toBe("completed");
			expect(updatedWf?.runtime_session_ids).toContain("frida_apk_session");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("ingests trusted session events then verifies hypothesis and promotes only current conclusion", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "dyn-ev-learn-"));
		try {
			const session = createTestSession(tempDir);
			const evidenceStore = EvidenceStore.forSession(tempDir);
			const runtimeStore = ReverseRuntimeSessionStore.forSession(tempDir);
			const workflowStore = ReverseWorkflowStore.forSession(tempDir);

			// Pre-existing unrelated static verified conclusion and recovery audit must NOT be promoted by verify
			const oldFact = await evidenceStore.addFact({
				kind: "fact",
				target: "other.bin",
				sourceTool: "r2_inspect",
				locator: "0x400500",
				content: "Static AES S-box constant table",
			});
			const oldHyp = await evidenceStore.addHypothesis({
				kind: "hypothesis",
				target: "other.bin",
				claim: "Old unrelated static AES hypothesis",
				verificationPlan: "Inspect table",
				facts: [oldFact.id],
			});
			await evidenceStore.verifyHypothesis({
				hypothesisId: oldHyp.id,
				method: "Static disassembly",
				command: "r2 -qc pdf other.bin",
				result: "Found S-box",
				conclusion: "Unrelated static AES table confirmed",
				status: "verified",
				facts: [oldFact.id],
			});

			const now = new Date().toISOString();
			await workflowStore.save({
				id: "wf_unrelated_recovery",
				target: "other.bin",
				format: "ELF",
				status: "completed",
				created_at: now,
				updated_at: now,
				steps: [
					{
						id: "step_rec",
						title: "Recover tool",
						tool: "r2_inspect",
						gate: "G1",
						params_summary: "{}",
						status: "completed",
						attempts: 2,
						max_attempts: 3,
						recovery_metadata: {
							recovery_audit: [
								{
									attempt: 2,
									timestamp: now,
									action: "recover",
									category: "timeout",
									cause: "timed out",
									previous_tool: "ghidra_inspect",
									proposed_tool: "r2_inspect",
									proposed_params: {},
									decision: "fallback",
									applied: true,
								},
							],
						},
						created_at: now,
						updated_at: now,
					},
				],
			});

			// Add target hypothesis with subject
			const hyp = await evidenceStore.addHypothesis({
				kind: "hypothesis",
				target: "app.apk",
				subject: "Cipher.init",
				claim: "Target uses AES-CBC with static IV for license verification",
				verificationPlan: "Hook Cipher.init using Frida to observe algorithm parameters",
			});

			// Register closed runtime session with persisted structured callsite event (closed sessions are permitted)
			await runtimeStore.save(
				createRuntimeSessionFixture(
					"frida_test_session",
					"frida",
					[
						{
							kind: "crypto",
							channel: "crypto",
							payload: { cipher: "AES/CBC/PKCS5Padding", iv: "0102030405060708" },
							seq: 1,
							metadata: {
								callsite: { module: "libcrypto_jni.so", address: "0x7f001240" },
							},
						},
					],
					"closed",
				),
			);

			const tool = new ReverseDynamicEvidenceTool(session);
			const ingestRes = await tool.execute("call_ingest", {
				action: "ingest",
				session_id: "frida_test_session",
				source: "frida",
				target: "app.apk",
				subject: "Cipher.init",
			});
			expect(ingestRes.details.factIds?.length).toBe(1);
			expect(ingestRes.details.conclusionId).toBeUndefined();

			const res = await tool.execute("call_verify", {
				action: "verify",
				session_id: "frida_test_session",
				source: "frida",
				hypothesis_id: hyp.id,
				fact_ids: ingestRes.details.factIds,
				subject: "Cipher.init",
				method: "Frida JNI hook on Cipher.init",
				command: "frida -U -f com.example.app -l hook_cipher.js",
				result: "Observed AES/CBC/PKCS5Padding with IV 0102030405060708 at libcrypto_jni.so@0x7f001240",
				conclusion: "Confirmed AES-CBC algorithm with hardcoded IV 0102030405060708.",
				learn: true,
			});

			expect(res.details.conclusionId).toBeDefined();
			expect(res.details.knowledgeCreatedCount).toBe(1);

			// Verify conclusion in EvidenceStore: reproducibility not specified != 100%, assurance = dynamic_call_observation
			const conc = await evidenceStore.getRecord(res.details.conclusionId!);
			expect(conc?.kind).toBe("conclusion");
			const verifiedConc = conc as ConclusionEvidence;
			expect(verifiedConc.status).toBe("verified");
			expect(verifiedConc.reproducibility).toBe("not specified");
			expect(verifiedConc.reproducibility).not.toBe("100%");
			expect(verifiedConc.context?.assurance).toBe("dynamic_call_observation");

			// Verify retained knowledge in ReverseKnowledgeStore: only current conclusion promoted, not old unrelated conclusion or recovery
			const knowledgeStore = ReverseKnowledgeStore.forSession(tempDir);
			const knowledge = await knowledgeStore.list();
			expect(knowledge.length).toBe(1);
			const item = knowledge[0];
			expect(item.kind).toBe("verified_conclusion");
			expect(item.source_evidence_ids).toContain(verifiedConc.id);
			expect(item.source_evidence_ids).not.toContain(oldHyp.id);
			expect(item.pattern).toBe("dynamic_crypto_verification");
			expect(item.metadata?.dynamic_verified).toBe(true);
			expect(item.metadata?.dynamic_locators).toContain("session:frida_test_session:seq:1");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects empty facts, missing/refuted/stale facts, console-only, explicit untrusted events, and mismatched session/source/target/subject/hash without side effects", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "dyn-ev-rejects-"));
		try {
			const session = createTestSession(tempDir);
			const evidenceStore = EvidenceStore.forSession(tempDir);
			const runtimeStore = ReverseRuntimeSessionStore.forSession(tempDir);
			const workflowStore = ReverseWorkflowStore.forSession(tempDir);
			const knowledgeStore = ReverseKnowledgeStore.forSession(tempDir);
			const tool = new ReverseDynamicEvidenceTool(session);

			// Create a real sample file so targetSha256 is computed
			const samplePath = path.join(tempDir, "sample.bin");
			await fs.writeFile(samplePath, "original-sample-bytes-v1");
			const sampleSha = Bun.SHA256.hash("original-sample-bytes-v1", "hex");

			const wf = await workflowStore.create({
				target: "sample.bin",
				format: "ELF",
				goal: "Verify dynamic call observation",
			});
			const dynamicStep = wf.steps.find(s => s.gate === "G2") ?? wf.steps[0];

			const hyp = await evidenceStore.addHypothesis({
				kind: "hypothesis",
				target: "sample.bin",
				subject: "verify_token",
				claim: "verify_token is invoked during handshake",
				verificationPlan: "Observe call via runtime trace",
			});

			// Register browser session with both a console event and a valid network request event
			await runtimeStore.save(
				createRuntimeSessionFixture("browser_sess_1", "browser", [
					{
						type: "console",
						payload: "console log from caller.js",
						seq: 1,
						metadata: {
							callsite: { url: "http://127.0.0.1/caller.js", lineNumber: 2, columnNumber: 4 },
						},
					},
					{
						type: "request",
						payload: { method: "POST", url: "http://127.0.0.1/api" },
						seq: 2,
						metadata: {
							artifactSha256: sampleSha,
							callsite: { url: "http://127.0.0.1/caller.js", lineNumber: 10, columnNumber: 6 },
						},
					},
				]),
			);

			// Ingest from trusted session
			const ingested = await tool.execute("ing_trusted", {
				action: "ingest",
				session_id: "browser_sess_1",
				source: "browser",
				target: "sample.bin",
				subject: "verify_token",
			});
			const [consoleFactId, validCallFactId] = ingested.details.factIds!;
			expect(consoleFactId).toBeDefined();
			expect(validCallFactId).toBeDefined();

			// Ingest forged explicit events with structured callsite
			const forgedIngest = await tool.execute("ing_forged", {
				action: "ingest",
				session_id: "browser_sess_1",
				source: "browser",
				target: "sample.bin",
				subject: "verify_token",
				events: [
					{
						type: "request",
						payload: { method: "POST", url: "http://127.0.0.1/forged" },
						seq: 99,
						metadata: {
							artifactSha256: sampleSha,
							callsite: { url: "http://127.0.0.1/caller.js", lineNumber: 1, columnNumber: 1 },
						},
					},
				],
			});
			const forgedFactId = forgedIngest.details.factIds![0];

			const baseVerify = {
				action: "verify" as const,
				session_id: "browser_sess_1",
				source: "browser" as const,
				hypothesis_id: hyp.id,
				fact_ids: [validCallFactId],
				method: "CDP request initiator observation",
				command: "browser_reverse_session(action: 'capture')",
				result: "POST /api initiated at caller.js:10:6",
				conclusion: "verify_token initiates POST /api",
				workflow_id: wf.id,
				step_id: dynamicStep.id,
				advance_workflow: true,
				learn: true,
			};

			// 1. Empty fact_ids rejected
			await expect(tool.execute("v_empty", { ...baseVerify, fact_ids: [] })).rejects.toThrow(/fact_ids/);

			// 2. Missing required fields (method/command/result/session_id) rejected
			await expect(tool.execute("v_no_session", { ...baseVerify, session_id: "" })).rejects.toThrow(/session_id/);
			await expect(tool.execute("v_no_method", { ...baseVerify, method: "" })).rejects.toThrow(/method/);
			await expect(tool.execute("v_no_cmd", { ...baseVerify, command: "" })).rejects.toThrow(/command/);
			await expect(tool.execute("v_no_res", { ...baseVerify, result: "" })).rejects.toThrow(/result/);

			// 3. Unregistered session_id rejected
			await expect(
				tool.execute("v_unreg_session", { ...baseVerify, session_id: "unregistered_session" }),
			).rejects.toThrow(/not registered/);

			// 4. Missing fact ID rejected
			await expect(
				tool.execute("v_missing_fact", { ...baseVerify, fact_ids: ["ev_fact_nonexistent"] }),
			).rejects.toThrow(/not found/);

			// 5. Console-only fact rejected (lacks dynamic_call_observation assurance)
			await expect(tool.execute("v_console", { ...baseVerify, fact_ids: [consoleFactId] })).rejects.toThrow(
				/dynamic_call_observation/,
			);

			// 6. Forged explicit event fact rejected (untrusted import lacks dynamic_call_observation assurance)
			await expect(tool.execute("v_forged", { ...baseVerify, fact_ids: [forgedFactId] })).rejects.toThrow(
				/dynamic_call_observation/,
			);

			// 7. Wrong source rejected
			await expect(tool.execute("v_wrong_source", { ...baseVerify, source: "frida" })).rejects.toThrow(
				/Source mismatch/,
			);

			// 8. Target rebinding rejected
			await expect(tool.execute("v_wrong_target", { ...baseVerify, target: "other.bin" })).rejects.toThrow(
				/Target mismatch/,
			);

			// 9. Subject mismatch rejected
			await expect(tool.execute("v_wrong_subject", { ...baseVerify, subject: "wrong_subject" })).rejects.toThrow(
				/Subject mismatch/,
			);

			// 10. Fact from another session rejected
			await runtimeStore.save(
				createRuntimeSessionFixture("browser_sess_2", "browser", [
					{
						type: "request",
						payload: { method: "GET", url: "http://127.0.0.1/api" },
						seq: 1,
						metadata: {
							artifactSha256: sampleSha,
							callsite: { url: "http://127.0.0.1/caller.js", lineNumber: 5, columnNumber: 2 },
						},
					},
				]),
			);
			const otherSessionIngest = await tool.execute("ing_other_sess", {
				action: "ingest",
				session_id: "browser_sess_2",
				source: "browser",
				target: "sample.bin",
				subject: "verify_token",
			});
			await expect(
				tool.execute("v_other_sess_fact", {
					...baseVerify,
					fact_ids: otherSessionIngest.details.factIds,
				}),
			).rejects.toThrow(/does not match verify session_id/);

			// 11. Mismatched target SHA-256 hash rejected
			const wrongHashFact = await evidenceStore.addFact({
				kind: "fact",
				target: "other_nonexistent.bin",
				sourceTool: "browser_reverse_session",
				locator: "session:browser_sess_1:seq:77",
				content: "Mismatched hash fact",
				subject: "verify_token",
				assurance: "dynamic_call_observation",
				executionBinding: { artifactSha256: "f".repeat(64) },
			});
			await expect(
				tool.execute("v_wrong_target_fact", { ...baseVerify, fact_ids: [wrongHashFact.id] }),
			).rejects.toThrow(/target/);

			const hypNoTargetFile = await evidenceStore.addHypothesis({
				kind: "hypothesis",
				target: "virtual_target",
				subject: "verify_token",
				claim: "Claim bound to artifact hash A",
				verificationPlan: "Verify hash",
				executionBinding: { artifactSha256: "a".repeat(64) },
			});
			const mismatchedShaFact = await evidenceStore.addFact({
				kind: "fact",
				target: "virtual_target",
				sourceTool: "browser_reverse_session",
				locator: "session:browser_sess_1:seq:78",
				content: "Bound to artifact hash B",
				subject: "verify_token",
				assurance: "dynamic_call_observation",
				executionBinding: { artifactSha256: "b".repeat(64) },
			});
			await expect(
				tool.execute("v_wrong_hash", {
					...baseVerify,
					hypothesis_id: hypNoTargetFile.id,
					fact_ids: [mismatchedShaFact.id],
				}),
			).rejects.toThrow(/SHA-256/);

			// 12. Refuted hypothesis rejected
			const refutedHyp = await evidenceStore.addHypothesis({
				kind: "hypothesis",
				target: "sample.bin",
				subject: "verify_token",
				claim: "Already refuted claim",
				verificationPlan: "Test",
			});
			await evidenceStore.verifyHypothesis({
				hypothesisId: refutedHyp.id,
				method: "Test",
				command: "test",
				result: "Counterexample observed",
				conclusion: "Refuted",
				status: "refuted",
			});
			await expect(
				tool.execute("v_refuted", {
					...baseVerify,
					hypothesis_id: refutedHyp.id,
				}),
			).rejects.toThrow(/refuted/);

			// 12b. Stale (explicitly invalidated) hypothesis rejected
			const staleHyp = await evidenceStore.addHypothesis({
				kind: "hypothesis",
				target: "sample.bin",
				subject: "verify_token",
				claim: "Invalidated hypothesis claim",
				verificationPlan: "Test",
			});
			const hypInvalidator = await evidenceStore.addHypothesis({
				kind: "hypothesis",
				target: "sample.bin",
				claim: "Supersede stale hypothesis",
				verificationPlan: "Audit",
			});
			await evidenceStore.verifyHypothesis({
				hypothesisId: hypInvalidator.id,
				method: "Audit",
				command: "audit",
				result: "Superseded",
				conclusion: "Invalidated prior hypothesis",
				status: "refuted",
				invalidatesConclusions: [staleHyp.id],
			});
			await expect(
				tool.execute("v_stale_hyp", {
					...baseVerify,
					hypothesis_id: staleHyp.id,
				}),
			).rejects.toThrow(/stale/);

			// 13. Stale (explicitly invalidated) fact rejected
			const staleFact = await evidenceStore.addFact({
				kind: "fact",
				target: "sample.bin",
				sourceTool: "browser_reverse_session",
				locator: "session:browser_sess_1:seq:79",
				content: "Superseded call observation",
				subject: "verify_token",
				assurance: "dynamic_call_observation",
				executionBinding: { artifactSha256: sampleSha },
			});
			const invalidatorHyp = await evidenceStore.addHypothesis({
				kind: "hypothesis",
				target: "sample.bin",
				claim: "Invalidate outdated fact",
				verificationPlan: "Invalidate",
			});
			await evidenceStore.verifyHypothesis({
				hypothesisId: invalidatorHyp.id,
				method: "Audit",
				command: "audit",
				result: "Outdated capture",
				conclusion: "Invalidated",
				status: "refuted",
				invalidatesConclusions: [staleFact.id],
			});
			await expect(
				tool.execute("v_stale_fact", {
					...baseVerify,
					fact_ids: [staleFact.id],
				}),
			).rejects.toThrow(/stale/);

			// 14. Static locator fact rejected
			const staticFact = await evidenceStore.addFact({
				kind: "fact",
				target: "sample.bin",
				sourceTool: "r2_inspect",
				locator: "0x401000",
				content: "Static xref only",
				subject: "verify_token",
			});
			await expect(
				tool.execute("v_static_fact", {
					...baseVerify,
					fact_ids: [staticFact.id],
				}),
			).rejects.toThrow(/dynamic session locator/);
			// Verify ZERO side effects on target hypothesis, knowledge store, and workflow step after all rejections
			const allRecords = await evidenceStore.listRecords({ limit: 100 });
			const conclusionsForTargetHyp = allRecords.items.filter(
				r => r.kind === "conclusion" && (r as ConclusionEvidence).hypothesisId === hyp.id,
			);
			expect(conclusionsForTargetHyp.length).toBe(0);

			const learnedSoFar = await knowledgeStore.list();
			expect(learnedSoFar.length).toBe(0);

			const wfAfterRejects = await workflowStore.get(wf.id);
			const stepAfterRejects = wfAfterRejects?.steps.find(s => s.id === dynamicStep.id);
			expect(stepAfterRejects?.status).toBe("pending");
			expect(stepAfterRejects?.evidence_ids ?? []).toEqual([]);

			// Finally, valid verification with qualified trusted fact succeeds and advances the step
			const okRes = await tool.execute("v_success", baseVerify);
			expect(okRes.details.conclusionId).toBeDefined();
			expect(okRes.details.knowledgeCreatedCount).toBe(1);
			const wfAfterSuccess = await workflowStore.get(wf.id);
			const stepAfterSuccess = wfAfterSuccess?.steps.find(s => s.id === dynamicStep.id);
			expect(stepAfterSuccess?.status).toBe("completed");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("supports browser page URL target in ingest/verify while preserving raw /api request URL and metadata", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "dyn-ev-browser-page-"));
		try {
			const session = createTestSession(tempDir);
			const evidenceStore = EvidenceStore.forSession(tempDir);
			const runtimeStore = ReverseRuntimeSessionStore.forSession(tempDir);
			const tool = new ReverseDynamicEvidenceTool(session);

			const pageUrl = "http://127.0.0.1:18080/index.html";
			const apiUrl = "http://127.0.0.1:18080/api";
			const callerUrl = "http://127.0.0.1:18080/caller.js";

			const runtimeRecord = createRuntimeSessionFixture("browser_page_sess", "browser", [
				{
					id: "network:req_1",
					type: "request",
					method: "POST",
					url: apiUrl,
					seq: 1,
					payload: { method: "POST", url: apiUrl },
					metadata: {
						initiator: { type: "script", url: callerUrl, lineNumber: 3, columnNumber: 8 },
						callsite: { url: callerUrl, lineNumber: 3, columnNumber: 8 },
					},
				},
			]);
			runtimeRecord.target_summary = pageUrl;
			await runtimeStore.save(runtimeRecord);

			const hyp = await evidenceStore.addHypothesis({
				kind: "hypothesis",
				target: pageUrl,
				subject: "api_fetch",
				claim: "Page triggers POST /api via caller.js",
				verificationPlan: "Capture browser network initiator and verify",
			});

			const ingRes = await tool.execute("ing_page", {
				action: "ingest",
				session_id: "browser_page_sess",
				source: "browser",
				target: pageUrl,
				subject: "api_fetch",
			});
			expect(ingRes.details.factIds?.length).toBe(1);
			const fact = ingRes.details.facts![0];
			expect(fact.target).toBe(pageUrl);
			expect(fact.content).toContain(apiUrl);
			expect(fact.content).toContain(`${callerUrl}:4:9`);
			expect(fact.context?.assurance).toBe("dynamic_call_observation");

			const verRes = await tool.execute("ver_page", {
				action: "verify",
				session_id: "browser_page_sess",
				source: "browser",
				hypothesis_id: hyp.id,
				fact_ids: ingRes.details.factIds,
				method: "CDP Network.Initiator capture",
				command: "browser_reverse_session(action: 'capture')",
				result: `Observed POST ${apiUrl} initiated from ${callerUrl}:3:8`,
				conclusion: "Confirmed POST /api callsite at caller.js:3:8.",
			});
			expect(verRes.details.conclusion?.target).toBe(pageUrl);
			expect(verRes.details.conclusion?.context?.assurance).toBe("dynamic_call_observation");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("queries dynamic events via 'events' action without writing to disk", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "dyn-ev-query-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new ReverseDynamicEvidenceTool(session);

			const events = [
				{ type: "send", channel: "stdout", payload: "Log line 1", seq: 1 },
				{ type: "send", channel: "crypto", payload: "AES init", seq: 2 },
				{ type: "send", channel: "stdout", payload: "Log line 2", seq: 3 },
			];

			const res = await tool.execute("call_events", {
				action: "events",
				session_id: "test_session",
				events,
				kind: "message",
			});

			expect(res.details.eventsCount).toBe(3);
			expect(res.details.factIds).toBeUndefined();

			// Evidence store should have 0 facts
			const evidenceStore = EvidenceStore.forSession(tempDir);
			const facts = await evidenceStore.listRecords();
			expect(facts.items.length).toBe(0);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("audits dynamic evidence closure via 'status' action", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "dyn-ev-status-"));
		try {
			const session = createTestSession(tempDir);
			const evidenceStore = EvidenceStore.forSession(tempDir);

			// Add a dynamic fact and a regular fact
			await evidenceStore.addFact({
				kind: "fact",
				sourceTool: "frida_session",
				locator: "session:test:seq:1",
				content: "Dynamic trace 1",
			});
			await evidenceStore.addFact({
				kind: "fact",
				sourceTool: "triage",
				locator: "0x14001A240",
				content: "Static header entry",
			});

			const tool = new ReverseDynamicEvidenceTool(session);
			const res = await tool.execute("call_status", { action: "status" });

			expect(res.details.eventsCount).toBe(1); // Only 1 dynamic fact
			expect(res.details.statusSummary?.dynamicFactsCount).toBe(1);
			expect(textOf(res)).toContain("Dynamic Facts Recorded: 1");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
	it("queries DAP events and converts to debug evidence facts", () => {
		const fakeEvent = {
			event: "output",
			body: {
				category: "stdout",
				output: "Decrypted payload: 0xfeedface\n",
			},
			seq: 1,
		};
		const ev = normalizeDapEvent(fakeEvent, "dap_session_test", { target: "bin/target.elf" });
		expect(ev.source).toBe("dap");
		expect(ev.kind).toBe("stdout");
		expect(ev.raw).toContain("0xfeedface");

		const fact = dynamicEventToFactInput(ev);
		expect(fact.sourceTool).toBe("debug");
		expect(fact.locator).toBe("session:dap_session_test:seq:1");
		expect(fact.target).toBe("bin/target.elf");
	});
});
