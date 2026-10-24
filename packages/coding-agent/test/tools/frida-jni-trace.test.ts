/**
 * Focused behavior and boundary tests for jnitrace-engine integration,
 * bounded JNI API tracing, and Frida 16/17 compatibility.
 */

import { describe, expect, it } from "bun:test";
import { resolveTemplateScript, parseFridaTrace } from "@reverse/coding-agent/tools/frida";
import {
	buildEvidenceReference,
	type DynamicSessionEvent,
	type FridaSessionRecord,
} from "@reverse/coding-agent/tools/frida-session";
const sampleSession: FridaSessionRecord = {
	id: "test-jni-sess",
	name: "JNI Session",
	createdAt: "2026-10-24T00:00:00.000Z",
	updatedAt: "2026-10-24T00:00:00.000Z",
	mode: "live",
	target: { type: "spawn", value: "com.example.smoke" },
	status: "active",
	runsCount: 0,
	history: [],
	events: [],
	eventsCount: 0,
};

describe("resolveTemplateScript validation", () => {
	it("rejects unknown template names", () => {
		expect(() => resolveTemplateScript({ template: "unknown_xyz" })).toThrow("Unknown template 'unknown_xyz'");
	});

	it("rejects jni_trace when neither module nor libraries is provided to prevent unbounded overhead", () => {
		expect(() => resolveTemplateScript({ template: "jni_trace" })).toThrow("Must provide 'module'");
	});

	it("rejects unknown JNI API names in jni_apis", () => {
		expect(() =>
			resolveTemplateScript({
				template: "jni_trace",
				module: "libtarget.so",
				jni_apis: ["NonExistentApi"],
			}),
		).toThrow("Unknown JNI API 'NonExistentApi'");
	});

	it("accepts valid module and JNI APIs", () => {
		const script = resolveTemplateScript({
			template: "jni_trace",
			module: "libtarget.so",
			jni_apis: ["FindClass", "GetMethodID"],
		});
		expect(typeof script).toBe("string");
		expect(script.length).toBeGreaterThan(1000);
	});
});
describe("parseFridaTrace structured event decoding", () => {
	it("parses single-block and multi-block jni_trace events", () => {
		const output = `
[frida] Starting trace...
__FRIDA_TRACE_START__{"event":"jni_trace","api":"FindClass","category":"class","class":"com/example/Target","retval":"0x1000","threadId":1234}__FRIDA_TRACE_END__
some log output
__FRIDA_TRACE_START__{"event":"jni_trace","api":"GetMethodID","category":"method","class":"com/example/Target","method":"encrypt","signature":"([B)[B","retval":"0x2000","threadId":1234}__FRIDA_TRACE_END__
`;
		const result = parseFridaTrace(output);
		expect(result.events).toHaveLength(2);
		expect(result.events[0].api).toBe("FindClass");
		expect(result.events[0].class).toBe("com/example/Target");
		expect(result.events[1].api).toBe("GetMethodID");
		expect(result.events[1].method).toBe("encrypt");
		expect(result.events[1].signature).toBe("([B)[B");
	});

	it("parses RegisterNatives events within trace stream", () => {
		const output = `__FRIDA_TRACE_START__{"event":"jni_register_natives","status":"confirmed","retval":0,"class":"com/example/Native","nMethods":1,"methods":[{"name":"foo","signature":"()V","fnPtr":"0x7f000100"}]}__FRIDA_TRACE_END__`;
		const result = parseFridaTrace(output);
		expect(result.events).toHaveLength(1);
		expect(result.events[0].event).toBe("jni_register_natives");
		expect(result.events[0].status).toBe("confirmed");
		expect(result.events[0].retval).toBe(0);
		expect(result.events[0].class).toBe("com/example/Native");
	});
});

describe("buildEvidenceReference confirmation and JNI trace gates", () => {
	it("rejects confirmation when retval !== 0 even if status is confirmed", () => {
		const unconfirmedEvent: DynamicSessionEvent = {
			id: "ev_gate_1",
			seq: 10,
			timestamp: new Date().toISOString(),
			sessionId: "test-jni-sess",
			kind: "message",
			channel: "send",
			payload: {
				event: "jni_register_natives",
				status: "confirmed",
				retval: -1,
				class: "com.example.Unconfirmed",
				nMethods: 1,
			},
		};

		const ref = buildEvidenceReference(sampleSession, unconfirmedEvent);
		expect(ref.metadata?.confirmed).toBe(false);
		expect(ref.metadata?.rejected).toBe(true);
	});

	it("rejects confirmation when retval is non-numeric string 0, null, or undefined", () => {
		const testValues = ["0", null, undefined];
		for (const val of testValues) {
			const event: DynamicSessionEvent = {
				id: `ev_gate_edge_${String(val)}`,
				seq: 11,
				timestamp: new Date().toISOString(),
				sessionId: "test-jni-sess",
				kind: "message",
				channel: "send",
				payload: {
					event: "jni_register_natives",
					status: "confirmed",
					retval: val,
					class: "com.example.Edge",
					nMethods: 1,
				},
			};
			const ref = buildEvidenceReference(sampleSession, event);
			expect(ref.metadata?.confirmed).toBe(false);
			expect(ref.metadata?.rejected).toBe(true);
		}
	});

	it("confirms fact only when retval is strictly numeric 0", () => {
		const confirmedEvent: DynamicSessionEvent = {
			id: "ev_gate_2",
			seq: 12,
			timestamp: new Date().toISOString(),
			sessionId: "test-jni-sess",
			kind: "message",
			channel: "send",
			payload: {
				event: "jni_register_natives",
				status: "confirmed",
				retval: 0,
				class: "com.example.Confirmed",
				nMethods: 2,
				methods: [
					{ name: "calc", signature: "()I", fnPtr: "0x1234" },
					{ name: "sign", signature: "([B)[B", fnPtr: "0x5678" },
				],
			},
		};

		const ref = buildEvidenceReference(sampleSession, confirmedEvent);
		expect(ref.metadata?.confirmed).toBe(true);
		expect(ref.metadata?.rejected).toBe(false);
	});

	it("formats jni_trace event into structured fact evidence with metadata", () => {
		const traceEvent: DynamicSessionEvent = {
			id: "ev_gate_3",
			seq: 13,
			timestamp: new Date().toISOString(),
			sessionId: "test-jni-sess",
			kind: "trace",
			channel: "jni_trace",
			payload: {
				event: "jni_trace",
				api: "GetMethodID",
				category: "method",
				class: "com/example/SecurityService",
				method: "verifyPin",
				signature: "(Ljava/lang/String;)Z",
				retval: "0xCAFE1000",
			},
		};

		const ref = buildEvidenceReference(sampleSession, traceEvent);
		expect(ref.kind).toBe("fact");
		expect(ref.metadata?.api).toBe("GetMethodID");
		expect(ref.metadata?.method).toBe("verifyPin");
		expect(ref.metadata?.signature).toBe("(Ljava/lang/String;)Z");
	});
});
