import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "@reverse/coding-agent/config/settings";
import type { ToolSession } from "@reverse/coding-agent/tools";
import { FridaSessionTool, isProcessAlive, type DynamicSessionEvent } from "../../src/tools/frida-session";
import { probeFridaLiveDependency } from "../../src/tools/frida-live-env";
import { FridaLiveClient } from "../../src/tools/frida-live-client";
import { EvidenceStore } from "../../src/evidence/store";
import type { FactEvidence } from "../../src/evidence/contracts";

function createTestSession(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
	};
}

async function removeTestDir(dirPath: string): Promise<void> {
	await fs.rm(dirPath, { recursive: true, force: true }).catch(() => {});
}

describe("FridaLiveClient subprocess IPC lifecycle", () => {
	it("starts worker and responds to status query", async () => {
		const dep = await probeFridaLiveDependency();
		if (!dep.available || !dep.pythonPath) {
			return;
		}

		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-live-ipc-"));
		const client = new FridaLiveClient({ pythonPath: dep.pythonPath, cwd: tempDir });
		try {
			await client.start();
			const status = await client.status(5000);
			expect(status.status).toBe("ok");
			expect(status.alive).toBe(false);
			expect(status.hasScript).toBe(false);
		} finally {
			await client.stop();
			await removeTestDir(tempDir);
		}
	});

	it("handles malformed IPC and safe error rejection", async () => {
		const dep = await probeFridaLiveDependency();
		if (!dep.available || !dep.pythonPath) {
			return;
		}

		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-live-err-"));
		const client = new FridaLiveClient({ pythonPath: dep.pythonPath, cwd: tempDir });
		try {
			await client.start();
			await expect(client.rpc("nonExistent", [])).rejects.toThrow("No script loaded");
		} finally {
			await client.stop();
			await removeTestDir(tempDir);
		}
	});

	it("terminates worker cleanly on AbortSignal cancellation", async () => {
		const dep = await probeFridaLiveDependency();
		if (!dep.available || !dep.pythonPath) {
			return;
		}

		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-live-abort-"));
		const client = new FridaLiveClient({ pythonPath: dep.pythonPath, cwd: tempDir });
		try {
			await client.start();
			const controller = new AbortController();
			const pending = client.status(5000, controller.signal);
			controller.abort();
			await expect(pending).rejects.toThrow("Request aborted");
		} finally {
			await client.stop();
			await removeTestDir(tempDir);
		}
	});
});

describe("FridaSessionTool persistent live sessions", () => {
	it("rejects live mode create if target is missing", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-live-val-"));
		try {
			const tool = new FridaSessionTool(createTestSession(tempDir), { stateRoot: tempDir });
			await expect(tool.execute("call-1", { action: "create", mode: "live" })).rejects.toThrow(
				"Must specify target: 'pid', 'process', or 'spawn'",
			);
		} finally {
			await removeTestDir(tempDir);
		}
	});

	it("rejects action: 'load' on batch mode sessions", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-batch-load-"));
		try {
			const tool = new FridaSessionTool(createTestSession(tempDir), {
				stateRoot: tempDir,
				runner: async () => ({
					stdout: new Uint8Array(),
					stderr: "",
					exitCode: 0,
					outputBytes: 0,
					truncated: false,
					timedOut: false,
				}),
			});
			await tool.execute("c1", { action: "create", pid: 99999, session_id: "batch-test" });
			await expect(
				tool.execute("c2", { action: "load", session_id: "batch-test", script: "console.log('hi')" }),
			).rejects.toThrow("Action 'load' is only supported on live mode sessions");
		} finally {
			await removeTestDir(tempDir);
		}
	});

	it("manages live session attachment, RPC invocation, hot reloading, and stop without killing target", async () => {
		const dep = await probeFridaLiveDependency();
		if (!dep.available || !dep.pythonPath) {
			return;
		}

		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-live-e2e-"));
		const targetBin = path.join(tempDir, "live_target");

		const sourceCode = `
#include <stdio.h>
#include <unistd.h>

__attribute__((visibility("default")))
int calc(int a) {
    return a * 10;
}

int main() {
    printf("READY\\n");
    fflush(stdout);
    for (int i = 0; i < 60; i++) {
        calc(i);
        sleep(1);
    }
    return 0;
}
`;
		await fs.writeFile(path.join(tempDir, "target.c"), sourceCode);

		const compile = Bun.spawn(["clang", "-Wl,-export_dynamic", "-o", targetBin, path.join(tempDir, "target.c")], {
			cwd: tempDir,
		});
		const compileCode = await compile.exited;
		if (compileCode !== 0) {
			await removeTestDir(tempDir);
			return;
		}

		const targetChild = Bun.spawn([targetBin], {
			cwd: tempDir,
			stdout: "pipe",
			stderr: "pipe",
		});
		const targetPid = targetChild.pid;

		try {
			const reader = targetChild.stdout.getReader();
			let targetOutput = "";
			while (true) {
				const { done, value } = await reader.read();
				if (done) break;
				targetOutput += Buffer.from(value).toString("utf8");
				if (targetOutput.includes("READY")) break;
			}
			reader.releaseLock();

			const tool = new FridaSessionTool(createTestSession(tempDir), { stateRoot: tempDir });
			const sessionId = "live-audit-test";

			// 1. Create live session and load initial script with RPC and hook
			const createRes = await tool.execute("c1", {
				action: "create",
				mode: "live",
				pid: targetPid,
				session_id: sessionId,
				script: `
rpc.exports = {
    transform: function(val) {
        return "transformed:" + val;
    }
};
var calcAddr = Module.findGlobalExportByName("calc");
if (calcAddr) {
    Interceptor.attach(calcAddr, {
        onEnter: function(args) {
            send({ event: "calc_called", arg: args[0].toInt32() });
        }
    });
}
`,
			});

			expect(createRes.details?.status).toBe("ok");
			expect(createRes.details?.mode).toBe("live");
			expect(createRes.details?.exports).toContain("transform");

			// 2. Call RPC method
			const rpcRes1 = await tool.execute("c2", {
				action: "rpc",
				session_id: sessionId,
				rpc_method: "transform",
				rpc_args: ["sample_input"],
			});

			expect(rpcRes1.details?.status).toBe("ok");
			expect(rpcRes1.details?.rpcResult).toBe("transformed:sample_input");

			// 3. Hot reload script: update transform logic
			const loadRes2 = await tool.execute("c3", {
				action: "load",
				session_id: sessionId,
				script: `
rpc.exports = {
    transform: function(val) {
        return "v2_transformed:" + val;
    }
};
`,
			});

			expect(loadRes2.details?.status).toBe("ok");
			expect(loadRes2.details?.exports).toContain("transform");

			// 4. Verify RPC returns updated v2 result
			const rpcRes2 = await tool.execute("c4", {
				action: "rpc",
				session_id: sessionId,
				rpc_method: "transform",
				rpc_args: ["sample_input"],
			});

			expect(rpcRes2.details?.status).toBe("ok");
			expect(rpcRes2.details?.rpcResult).toBe("v2_transformed:sample_input");

			// 5. Query status
			const statusRes = await tool.execute("c5", {
				action: "status",
				session_id: sessionId,
			});

			expect(statusRes.details?.status).toBe("ok");
			expect(statusRes.details?.mode).toBe("live");
			expect(statusRes.details?.liveStatus).toBe("connected");

			// 6. Unload script
			const unloadRes = await tool.execute("c6", {
				action: "unload",
				session_id: sessionId,
			});
			expect(unloadRes.details?.status).toBe("ok");

			// 7. Stop session: verifies clean detach without killing user target process
			const stopRes = await tool.execute("c7", {
				action: "stop",
				session_id: sessionId,
			});
			expect(stopRes.details?.status).toBe("ok");
			expect(stopRes.details?.action).toBe("stop");
			expect(isProcessAlive(targetPid)).toBe(true);
		} finally {
			try {
				targetChild.kill();
			} catch {}
			await removeTestDir(tempDir);
		}
	});
	it("traces native function calls and JNI RegisterNatives on real compiled C sample via live persistent session", async () => {
		const dep = await probeFridaLiveDependency();
		if (!dep.available || !dep.pythonPath) {
			throw new Error(`Frida live dependency unavailable: ${dep.error ?? "No python with frida found"}`);
		}

		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-smoke-e2e-"));
		const targetBin = path.join(tempDir, "native_smoke_target");

		const sourceCode = `
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

__attribute__((visibility("default")))
int calc(int a) {
    return a * 10;
}

__attribute__((visibility("default")))
int native_add(void* env, void* clazz, int x, int y) {
    return x + y;
}

typedef void* jclass;
typedef void* jobject;
typedef void* jstring;
typedef void* jmethodID;
typedef unsigned char jboolean;
typedef int32_t jint;

typedef struct {
    char *name;
    char *signature;
    void *fnPtr;
} JNINativeMethod;

static void* s_mock_vtable[300];
static void* s_mock_env = &s_mock_vtable;
static int s_register_retval = 0;

__attribute__((visibility("default")))
jint mock_RegisterNatives(void* env, jclass clazz, const JNINativeMethod* methods, jint nMethods) {
    return s_register_retval;
}

static uint8_t mock_ExceptionCheck(void* env) {
    return 0;
}

static void mock_ExceptionClear(void* env) {}

static void* mock_GetObjectClass(void* env, jobject obj) {
    return (void*)0x2001;
}

static void* mock_GetMethodID(void* env, jclass cls, const char* name, const char* sig) {
    return (void*)0x3001;
}

static void* mock_CallObjectMethodA(void* env, jobject obj, jmethodID mid, const void* args) {
    return (void*)0x4001;
}

static const char* mock_GetStringUTFChars(void* env, jstring str, jboolean* isCopy) {
    return "com.example.app.NativeSample";
}

static void mock_ReleaseStringUTFChars(void* env, jstring str, const char* chars) {}
static void mock_DeleteLocalRef(void* env, jobject obj) {}

static void setup_mock_jni_table() {
    memset(s_mock_vtable, 0, sizeof(s_mock_vtable));
    s_mock_vtable[17] = (void*)mock_ExceptionClear;
    s_mock_vtable[23] = (void*)mock_DeleteLocalRef;
    s_mock_vtable[31] = (void*)mock_GetObjectClass;
    s_mock_vtable[33] = (void*)mock_GetMethodID;
    s_mock_vtable[36] = (void*)mock_CallObjectMethodA;
    s_mock_vtable[169] = (void*)mock_GetStringUTFChars;
    s_mock_vtable[170] = (void*)mock_ReleaseStringUTFChars;
    s_mock_vtable[215] = (void*)mock_RegisterNatives;
    s_mock_vtable[228] = (void*)mock_ExceptionCheck;
}

__attribute__((visibility("default")))
void trigger_registration(int success) {
    s_register_retval = success ? 0 : -1;
    JNINativeMethod methods[2];
    methods[0].name = "addNumbers";
    methods[0].signature = "(II)I";
    methods[0].fnPtr = (void*)native_add;

    methods[1].name = "compute";
    methods[1].signature = "(I)I";
    methods[1].fnPtr = (void*)calc;

    mock_RegisterNatives(&s_mock_env, (void*)0x1001, methods, 2);
}

int main() {
    setup_mock_jni_table();
    printf("READY\\n");
    fflush(stdout);

    for (int i = 0; i < 60; i++) {
        calc(i);
        if (i % 2 == 1) {
            trigger_registration(1);
        } else if (i > 0) {
            trigger_registration(0);
        }
        usleep(300000);
    }
    return 0;
}
`;
		await fs.writeFile(path.join(tempDir, "target.c"), sourceCode);

		const compile = Bun.spawn(["clang", "-Wl,-export_dynamic", "-o", targetBin, path.join(tempDir, "target.c")], {
			cwd: tempDir,
		});
		const compileCode = await compile.exited;
		if (compileCode !== 0) {
			await removeTestDir(tempDir);
			throw new Error(`Failed to compile native C target with clang (exit code ${compileCode})`);
		}

		const targetChild = Bun.spawn([targetBin], {
			cwd: tempDir,
			stdout: "pipe",
			stderr: "pipe",
		});
		const targetPid = targetChild.pid;

		try {
			const reader = targetChild.stdout.getReader();
			let targetOutput = "";
			while (true) {
				const { done, value } = await reader.read();
				if (done) break;
				targetOutput += Buffer.from(value).toString("utf8");
				if (targetOutput.includes("READY")) break;
			}
			reader.releaseLock();

			const tool = new FridaSessionTool(createTestSession(tempDir), { stateRoot: tempDir });
			const sessionId = "live-native-smoke-test";

			// 1. Create live session using native_functions template
			const createRes = await tool.execute("c1", {
				action: "create",
				mode: "live",
				pid: targetPid,
				session_id: sessionId,
				template: "native_functions",
				symbol: "calc",
				args_decode: { "0": "int" },
				retval: true,
			});

			expect(createRes.details?.status).toBe("ok");
			expect(createRes.details?.mode).toBe("live");

			// Await real event emitted by the target C subprocess into the session ring buffer.
			// Note: Interacting with an external OS subprocess clock requires polling with small delay intervals.
			const waitForSessionEvent = async (
				predicate: (ev: DynamicSessionEvent) => boolean,
				timeoutMs = 5000,
			): Promise<DynamicSessionEvent> => {
				const start = Date.now();
				while (Date.now() - start < timeoutMs) {
					const res = await tool.execute(`poll_${Date.now()}`, {
						action: "events",
						session_id: sessionId,
					});
					const evs = (res.details?.events ?? []) as DynamicSessionEvent[];
					const matched = evs.find(predicate);
					if (matched) return matched;
					await Bun.sleep(100);
				}
				throw new Error("Timed out awaiting expected dynamic event from C subprocess");
			};

			// Wait for native_call event
			const nativeCallEv = await waitForSessionEvent((ev: DynamicSessionEvent) =>
				Boolean(
					ev.payload &&
					typeof ev.payload === "object" &&
					(ev.payload as Record<string, unknown>).event === "native_call",
				),
			);
			const firstCall = nativeCallEv.payload as Record<string, unknown>;
			expect(firstCall.target).toBe("calc");
			expect(Array.isArray(firstCall.args)).toBe(true);
			const numericArg = (firstCall.args as unknown[])[0];
			expect(typeof numericArg).toBe("number");
			expect(numericArg as number).toBeGreaterThanOrEqual(0);
			// Verify exact mathematical relation between decoded numeric arg and retval (calc(x) returns x * 10)
			const expectedRetHex = "0x" + ((numericArg as number) * 10).toString(16);
			expect(firstCall.retval).toBe(expectedRetHex);
			// Verify pointer - base === offset arithmetic
			expect(typeof firstCall.address).toBe("string");
			expect(typeof firstCall.base).toBe("string");
			expect(typeof firstCall.offset).toBe("string");
			expect(BigInt(firstCall.address as string) - BigInt(firstCall.base as string)).toBe(
				BigInt(firstCall.offset as string),
			);

			// 2. Hot-reload with jni_register template targeting mock_RegisterNatives
			const loadRes = await tool.execute("c3", {
				action: "load",
				session_id: sessionId,
				template: "jni_register",
				symbol: "mock_RegisterNatives",
			});

			expect(loadRes.details?.status).toBe("ok");

			// Wait for confirmed JNI event (retval: 0)
			const confirmedEv = await waitForSessionEvent((ev: DynamicSessionEvent) =>
				Boolean(
					ev.payload &&
					typeof ev.payload === "object" &&
					(ev.payload as Record<string, unknown>).event === "jni_register_natives" &&
					(ev.payload as Record<string, unknown>).status === "confirmed",
				),
			);
			const confirmedPayload = confirmedEv.payload as Record<string, unknown>;
			expect(confirmedPayload.class).toBe("com.example.app.NativeSample");
			const methods = confirmedPayload.methods as Array<Record<string, unknown>>;
			expect(methods).toHaveLength(2);
			expect(methods[0].name).toBe("addNumbers");
			expect(methods[0].signature).toBe("(II)I");
			expect(typeof methods[0].fnPtr).toBe("string");
			expect(typeof methods[0].base).toBe("string");
			expect(typeof methods[0].offset).toBe("string");
			// Verify pointer - base === offset arithmetic for registered methods
			expect(BigInt(methods[0].fnPtr as string) - BigInt(methods[0].base as string)).toBe(
				BigInt(methods[0].offset as string),
			);

			expect(methods[1].name).toBe("compute");
			expect(methods[1].signature).toBe("(I)I");
			expect(typeof methods[1].fnPtr).toBe("string");
			expect(BigInt(methods[1].fnPtr as string) - BigInt(methods[1].base as string)).toBe(
				BigInt(methods[1].offset as string),
			);

			// Wait for rejected JNI event (retval: -1)
			const rejectedEv = await waitForSessionEvent((ev: DynamicSessionEvent) =>
				Boolean(
					ev.payload &&
					typeof ev.payload === "object" &&
					(ev.payload as Record<string, unknown>).event === "jni_register_natives" &&
					(ev.payload as Record<string, unknown>).status === "rejected",
				),
			);
			const rejectedPayload = rejectedEv.payload as Record<string, unknown>;
			expect(rejectedPayload.retval).toBe(-1);

			// Export evidence to ledger
			const exportRes = await tool.execute("c4_export", {
				action: "events",
				session_id: sessionId,
				export_evidence: true,
			});
			expect(exportRes.details?.status).toBe("ok");

			// Ingest and query EvidenceStore to assert verified confirmed vs rejected metadata
			const evidenceStore = new EvidenceStore({ repositoryRoot: tempDir, stateRoot: tempDir });
			const factList = await evidenceStore.listRecords({ kind: "fact", limit: 200 });
			expect(factList.total).toBeGreaterThan(0);

			// Confirmed mapping MUST be ingested with class tag and confirmed title
			const confirmedFact = factList.items.find(
				(r): r is FactEvidence => r.kind === "fact" && r.title.includes("com.example.app.NativeSample"),
			);
			expect(confirmedFact).toBeDefined();
			if (confirmedFact) {
				expect(confirmedFact.sourceTool).toBe("frida_session");
				expect(confirmedFact.locator).toMatch(/^session:live-native-smoke-test:seq:\d+$/);
				expect(confirmedFact.content).toContain("com.example.app.NativeSample");
			}

			// Rejected mapping MUST NOT be admitted into EvidenceStore ledger
			const rejectedFact = factList.items.find(
				(r): r is FactEvidence => r.kind === "fact" && r.title.includes("[Rejected]"),
			);
			expect(rejectedFact).toBeUndefined();

			// 3. Stop session cleanly
			const stopRes = await tool.execute("c5", {
				action: "stop",
				session_id: sessionId,
			});
			expect(stopRes.details?.status).toBe("ok");
			expect(isProcessAlive(targetPid)).toBe(true);
		} finally {
			try {
				targetChild.kill();
			} catch {}
			await removeTestDir(tempDir);
		}
	});
});
