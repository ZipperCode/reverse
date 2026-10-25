import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
	resolveFridaSessionTarget,
	FridaSessionStore,
	encodeProjectKey,
	type FridaSessionRecord,
} from "../../src/tools/frida-session";
import { resolveInstructionTraceTarget } from "../../src/tools/instruction-trace-session";
import { ToolError } from "@reverse/tui/tools/tool-errors";

function createStoreForTest(cwd: string, stateRoot: string): FridaSessionStore {
	const projectKey = encodeProjectKey(cwd);
	const baseDir = path.join(path.resolve(stateRoot), "frida-sessions");
	return new FridaSessionStore(path.join(baseDir, projectKey));
}

describe("instruction-trace-session lifecycle and target resolution", () => {
	it("resolves active live spawned session to actual child PID without re-spawning", async () => {
		const tmpCwd = await fs.mkdtemp(path.join(os.tmpdir(), "rev-trace-session-live-"));
		const tmpState = path.join(tmpCwd, "state");
		const store = createStoreForTest(tmpCwd, tmpState);
		const sessionId = "sess_live_spawn_123";

		const record: FridaSessionRecord = {
			id: sessionId,
			mode: "live",
			status: "active",
			liveStatus: "connected",
			target: {
				type: "spawn",
				value: "/usr/local/bin/dummy_target",
				spawn: "/usr/local/bin/dummy_target",
			},
			activeChildPid: 54321,
			createdAt: new Date().toISOString(),
			updatedAt: new Date().toISOString(),
			runsCount: 1,
			history: [],
		};

		await store.save(record);

		try {
			// 1. Narrow lifecycle API resolution
			const resolved = await resolveFridaSessionTarget(tmpCwd, sessionId, tmpState);
			expect(resolved).not.toBeNull();
			expect(resolved?.mode).toBe("live");
			expect(resolved?.activeChildPid).toBe(54321);
			// Crucial: mapped activeChildPid to pid, cleared spawn so consumer does not re-spawn
			expect(resolved?.pid).toBe(54321);
			expect(resolved?.spawn).toBeUndefined();

			// 2. Helper module resolution for instruction_trace
			const traceTarget = await resolveInstructionTraceTarget({
				cwd: tmpCwd,
				sessionId,
				stateRoot: tmpState,
			});

			expect(traceTarget.pid).toBe(54321);
			expect(traceTarget.spawn).toBeUndefined();
			expect(traceTarget.resolvedFromSession).toBe(true);
			expect(traceTarget.activeChildPid).toBe(54321);
		} finally {
			await fs.rm(tmpCwd, { recursive: true, force: true }).catch(() => {});
		}
	});

	it("resolves persisted disk session with activeChildPid to child PID", async () => {
		const tmpCwd = await fs.mkdtemp(path.join(os.tmpdir(), "rev-trace-session-disk-"));
		const tmpState = path.join(tmpCwd, "state");
		const store = createStoreForTest(tmpCwd, tmpState);

		const sessionId = "sess_disk_spawn_456";
		const record: FridaSessionRecord = {
			id: sessionId,
			mode: "batch",
			status: "active",
			target: {
				type: "spawn",
				value: "/bin/sleep",
				spawn: "/bin/sleep",
				device: "remote_usb_1",
				usb: true,
			},
			activeChildPid: 77889,
			createdAt: new Date().toISOString(),
			updatedAt: new Date().toISOString(),
			runsCount: 0,
			history: [],
		};

		await store.save(record);

		try {
			const resolved = await resolveFridaSessionTarget(tmpCwd, sessionId, tmpState);
			expect(resolved).not.toBeNull();
			expect(resolved?.pid).toBe(77889);
			expect(resolved?.spawn).toBeUndefined();
			expect(resolved?.device).toBe("remote_usb_1");
			expect(resolved?.usb).toBe(true);

			const traceTarget = await resolveInstructionTraceTarget({
				cwd: tmpCwd,
				sessionId,
				stateRoot: tmpState,
			});

			expect(traceTarget.pid).toBe(77889);
			expect(traceTarget.spawn).toBeUndefined();
			expect(traceTarget.device).toBe("remote_usb_1");
			expect(traceTarget.usb).toBe(true);
		} finally {
			await fs.rm(tmpCwd, { recursive: true, force: true }).catch(() => {});
		}
	});

	it("falls back to spawn target when session has no activeChildPid", async () => {
		const tmpCwd = await fs.mkdtemp(path.join(os.tmpdir(), "rev-trace-session-fallback-"));
		const tmpState = path.join(tmpCwd, "state");
		const store = createStoreForTest(tmpCwd, tmpState);

		const sessionId = "sess_disk_nospawn_pid";
		const record: FridaSessionRecord = {
			id: sessionId,
			mode: "batch",
			status: "stopped",
			target: {
				type: "spawn",
				value: "/tmp/sample_binary",
				spawn: "/tmp/sample_binary",
			},
			createdAt: new Date().toISOString(),
			updatedAt: new Date().toISOString(),
			runsCount: 0,
			history: [],
		};

		await store.save(record);

		try {
			const traceTarget = await resolveInstructionTraceTarget({
				cwd: tmpCwd,
				sessionId,
				stateRoot: tmpState,
			});

			expect(traceTarget.pid).toBeUndefined();
			expect(traceTarget.spawn).toBe("/tmp/sample_binary");
		} finally {
			await fs.rm(tmpCwd, { recursive: true, force: true }).catch(() => {});
		}
	});

	it("resolves target by pid and process targets correctly", async () => {
		const tmpCwd = await fs.mkdtemp(path.join(os.tmpdir(), "rev-trace-session-pid-"));
		const tmpState = path.join(tmpCwd, "state");
		const store = createStoreForTest(tmpCwd, tmpState);

		const pidSession: FridaSessionRecord = {
			id: "sess_pid_target",
			mode: "batch",
			status: "active",
			target: {
				type: "pid",
				value: 1234,
				pid: 1234,
			},
			createdAt: new Date().toISOString(),
			updatedAt: new Date().toISOString(),
			runsCount: 0,
			history: [],
		};

		const processSession: FridaSessionRecord = {
			id: "sess_proc_target",
			mode: "batch",
			status: "active",
			target: {
				type: "process",
				value: "com.example.app",
				process: "com.example.app",
			},
			createdAt: new Date().toISOString(),
			updatedAt: new Date().toISOString(),
			runsCount: 0,
			history: [],
		};

		await store.save(pidSession);
		await store.save(processSession);

		try {
			const pidTarget = await resolveInstructionTraceTarget({
				cwd: tmpCwd,
				sessionId: "sess_pid_target",
				stateRoot: tmpState,
			});
			expect(pidTarget.pid).toBe(1234);

			const procTarget = await resolveInstructionTraceTarget({
				cwd: tmpCwd,
				sessionId: "sess_proc_target",
				stateRoot: tmpState,
			});
			expect(procTarget.process).toBe("com.example.app");
		} finally {
			await fs.rm(tmpCwd, { recursive: true, force: true }).catch(() => {});
		}
	});

	it("throws ToolError when session_id does not exist", async () => {
		const tmpCwd = await fs.mkdtemp(path.join(os.tmpdir(), "rev-trace-session-err-"));
		try {
			await expect(
				resolveInstructionTraceTarget({
					cwd: tmpCwd,
					sessionId: "non_existent_session_id",
				}),
			).rejects.toThrow(ToolError);
		} finally {
			await fs.rm(tmpCwd, { recursive: true, force: true }).catch(() => {});
		}
	});

	it("throws ToolError when no target parameters or session are provided", async () => {
		const tmpCwd = await fs.mkdtemp(path.join(os.tmpdir(), "rev-trace-session-notarget-"));
		try {
			await expect(
				resolveInstructionTraceTarget({
					cwd: tmpCwd,
				}),
			).rejects.toThrow(ToolError);
		} finally {
			await fs.rm(tmpCwd, { recursive: true, force: true }).catch(() => {});
		}
	});

	it("allows explicit caller overrides over session defaults", async () => {
		const tmpCwd = await fs.mkdtemp(path.join(os.tmpdir(), "rev-trace-session-overrides-"));
		const tmpState = path.join(tmpCwd, "state");
		const store = createStoreForTest(tmpCwd, tmpState);

		const session: FridaSessionRecord = {
			id: "sess_with_defaults",
			mode: "batch",
			status: "active",
			target: {
				type: "pid",
				value: 1111,
				pid: 1111,
				device: "default_device",
				usb: false,
			},
			createdAt: new Date().toISOString(),
			updatedAt: new Date().toISOString(),
			runsCount: 0,
			history: [],
		};

		await store.save(session);

		try {
			const overridden = await resolveInstructionTraceTarget({
				cwd: tmpCwd,
				sessionId: "sess_with_defaults",
				device: "caller_override_device",
				usb: true,
				stateRoot: tmpState,
			});

			expect(overridden.pid).toBe(1111);
			expect(overridden.device).toBe("caller_override_device");
			expect(overridden.usb).toBe(true);
		} finally {
			await fs.rm(tmpCwd, { recursive: true, force: true }).catch(() => {});
		}
	});
});
