import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "@rva/coding-agent/config/settings";
import {
	createTools,
	ReverseDynamicEvidenceTool,
	type ToolSession,
	BUILTIN_TOOLS,
} from "@rva/coding-agent/tools";
import { BUILTIN_TOOL_NAMES, normalizeToolName } from "@rva/coding-agent/tools/builtin-names";
import { removeWithRetries } from "@rva/utils";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { EvidenceStore } from "@rva/coding-agent/evidence";
import { ReverseWorkflowStore } from "@rva/coding-agent/reverse-workflow";
import { ReverseKnowledgeStore } from "@rva/coding-agent/reverse-knowledge";
import {
	formatDynamicLocator,
	parseDynamicLocator,
	isDynamicLocator,
	normalizeFridaEvent,
	normalizeBrowserEvent,
	normalizeDapEvent,
	normalizeDynamicEvent,
	filterDynamicEvents,
	appendDynamicEvents,
	dynamicEventToFactInput,
	type UniversalDynamicEvent,
} from "@rva/coding-agent/reverse-runtime-session/dynamic-events";
import { dapSessionManager } from "@rva/coding-agent/dap";

function createTestSession(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
	};
}

function textOf(result: { content: Array<{ type: string; text?: string }> }): string {
	return result.content
		.map(item => item.text ?? "")
		.join("\n")
		.trim();
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

	it("attaches dynamic facts to workflow step and advances workflow", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "dyn-ev-wf-"));
		try {
			const session = createTestSession(tempDir);
			const workflowStore = ReverseWorkflowStore.forSession(tempDir);

			// Setup workflow with dynamic step
			const wf = await workflowStore.create({
				target: "target.apk",
				format: "APK",
				goal: "Verify native dynamic payload decryption",
			});
			const stepId = wf.steps[0].id;

			const tool = new ReverseDynamicEvidenceTool(session);
			const res = await tool.execute("call_wf", {
				action: "ingest",
				session_id: "frida_apk_session",
				source: "frida",
				target: "target.apk",
				events: [{ type: "send", channel: "trace", payload: "Java_com_app_decrypt called", seq: 1 }],
				workflow_id: wf.id,
				step_id: stepId,
				advance_workflow: true,
			});

			expect(res.details.stepUpdated).toBe(true);

			// Verify updated workflow
			const updatedWf = await workflowStore.get(wf.id);
			const updatedStep = updatedWf?.steps.find(s => s.id === stepId);
			expect(updatedStep?.status).toBe("completed");
			expect(updatedStep?.evidence_ids?.length).toBe(1);
			expect(updatedWf?.runtime_session_ids).toContain("frida_apk_session");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("verifies hypothesis and auto-learns into ReverseKnowledgeStore", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "dyn-ev-learn-"));
		try {
			const session = createTestSession(tempDir);
			const evidenceStore = EvidenceStore.forSession(tempDir);

			// Add hypothesis
			const hyp = await evidenceStore.addHypothesis({
				target: "app.apk",
				claim: "Target uses AES-CBC with static IV for license verification",
				verificationPlan: "Hook Cipher.init using Frida to observe algorithm parameters",
			});

			const tool = new ReverseDynamicEvidenceTool(session);
			const res = await tool.execute("call_verify", {
				action: "ingest",
				session_id: "frida_test_session",
				source: "frida",
				target: "app.apk",
				events: [
					{
						type: "send",
						channel: "crypto",
						payload: { cipher: "AES/CBC/PKCS5Padding", iv: "0102030405060708" },
						seq: 1,
					},
				],
				hypothesis_id: hyp.id,
				conclusion: "Confirmed AES-CBC algorithm with hardcoded IV 0102030405060708.",
				learn: true,
			});

			expect(res.details.conclusionId).toBeDefined();
			expect(res.details.knowledgeCreatedCount).toBeGreaterThanOrEqual(1);

			// Verify conclusion in EvidenceStore
			const conc = await evidenceStore.getRecord(res.details.conclusionId!);
			expect(conc?.kind).toBe("conclusion");
			const verifiedConc = conc as ConclusionEvidence;
			expect(verifiedConc.status).toBe("verified");

			// Verify retained knowledge in ReverseKnowledgeStore
			const knowledgeStore = ReverseKnowledgeStore.forSession(tempDir);
			const knowledge = await knowledgeStore.list();
			expect(knowledge.length).toBeGreaterThanOrEqual(1);
			const item = knowledge[0];
			expect(item.kind).toBe("verified_conclusion");
			expect(item.pattern).toBe("dynamic_crypto_verification");
			expect(item.metadata?.dynamic_verified).toBe(true);
			expect(item.metadata?.dynamic_locators).toContain("session:frida_test_session:seq:1");
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
				sourceTool: "frida_session",
				locator: "session:test:seq:1",
				content: "Dynamic trace 1",
			});
			await evidenceStore.addFact({
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
