import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "bun:test";
import { executePython, disposeKernelSessionsByOwner } from "../../src/eval/py/executor";
import { executeJs } from "../../src/eval/js/executor";
import { disposeVmContextsByOwner } from "../../src/eval/js/context-manager";
import { getEvalState } from "../../src/eval/state";
import type { ToolSession } from "../../src/tools";
import { Settings } from "../../src/config/settings";

function createMockSession(sessionId: string, ownerId: string, cwd: string, settings: Settings): ToolSession {
	return {
		cwd,
		sessionId,
		settings,
		getEvalSessionId: () => sessionId,
		getEvalKernelOwnerId: () => ownerId,
	} as unknown as ToolSession;
}

describe("Issue #7: kernel reset and recovery lifecycle behavioral invariants", () => {
	const activeCleanups: Array<() => Promise<void>> = [];

	afterEach(async () => {
		while (activeCleanups.length > 0) {
			const cleanup = activeCleanups.pop();
			if (cleanup) await cleanup();
		}
	});

	it("surfaces structured loss notice and recreation event across controlled Python termination", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "rev-test-py-loss-"));
		const ownerId = `test-py-owner-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
		const sessionId = `test-py-session-${Date.now()}`;
		const settings = await Settings.init();
		const toolSession = createMockSession(sessionId, ownerId, tempDir, settings);

		activeCleanups.push(async () => {
			await disposeKernelSessionsByOwner(ownerId);
			fs.rmSync(tempDir, { recursive: true, force: true });
		});

		const sideEffectFile = path.join(tempDir, "partial_artifact.txt");

		// Cell 1: setup initial symbol and write disk side effect in generation 1
		const cell1 = await executePython(
			`my_symbol = 42\nwith open(${JSON.stringify(sideEffectFile)}, 'w') as f:\n    f.write('side_effect_gen1')\nprint(f'init:{my_symbol}')`,
			{
				sessionId,
				kernelOwnerId: ownerId,
				toolSession,
				cwd: tempDir,
			},
		);
		expect(cell1.exitCode).toBe(0);
		expect(cell1.output).toContain("init:42");

		// Verify disk side effect was recorded
		expect(fs.existsSync(sideEffectFile)).toBe(true);
		expect(fs.readFileSync(sideEffectFile, "utf-8")).toBe("side_effect_gen1");

		const state1 = getEvalState(toolSession);
		const pyRuntime1 = state1?.runtimes.find(r => r.language === "python");
		expect(pyRuntime1?.alive).toBe(true);
		expect(pyRuntime1?.generation).toBe(1);

		// Cell 2: controlled forced termination (exit code 130 as in Issue #7)
		const cell2 = await executePython("import os\nos._exit(130)", {
			sessionId,
			kernelOwnerId: ownerId,
			toolSession,
			cwd: tempDir,
		});
		expect(cell2.cancelled).toBe(true);
		expect(cell2.exitCode).toBeUndefined();

		// Structured loss event must be present on killing cell
		const lossStatus = cell2.displayOutputs.find(d => d.type === "status" && d.event.op === "kernel_reset");
		expect(lossStatus).toBeDefined();
		if (lossStatus && lossStatus.type === "status") {
			expect(lossStatus.event.op).toBe("kernel_reset");
			expect(lossStatus.event.language).toBe("python");
			expect(lossStatus.event.generation).toBe(1);
			expect(lossStatus.event.nextGeneration).toBe(2);
			expect(lossStatus.event.kernelKilled).toBe(true);
			expect(lossStatus.event.action).toBe("reimport_dependencies");
		}

		// Tool session runtime state must record dead
		const stateDead = getEvalState(toolSession);
		const pyRuntimeDead = stateDead?.runtimes.find(r => r.language === "python");
		expect(pyRuntimeDead?.alive).toBe(false);

		// Cell 3: attempting to access old symbol without re-import
		// Must run on fresh generation 2, expose truthful NameError, and emit recreation event
		const cell3 = await executePython("print(my_symbol)", {
			sessionId,
			kernelOwnerId: ownerId,
			toolSession,
			cwd: tempDir,
		});
		expect(cell3.exitCode).toBe(1);
		expect(cell3.output).toContain("NameError");
		expect(cell3.output).toContain("my_symbol");

		// Recreation event must be emitted with generation 2 and previousGeneration 1
		const recreatedStatus = cell3.displayOutputs.find(d => d.type === "status" && d.event.op === "kernel_reset");
		expect(recreatedStatus).toBeDefined();
		if (recreatedStatus && recreatedStatus.type === "status") {
			expect(recreatedStatus.event.op).toBe("kernel_reset");
			expect(recreatedStatus.event.language).toBe("python");
			expect(recreatedStatus.event.generation).toBe(2);
			expect(recreatedStatus.event.previousGeneration).toBe(1);
			expect(recreatedStatus.event.recreated).toBe(true);
			expect(recreatedStatus.event.action).toBe("reimport_dependencies");
		}

		const stateAlive2 = getEvalState(toolSession);
		const pyRuntimeAlive2 = stateAlive2?.runtimes.find(r => r.language === "python");
		expect(pyRuntimeAlive2?.alive).toBe(true);
		expect(pyRuntimeAlive2?.generation).toBe(2);

		// Cell 4: explicit recovery: re-initialize dependency
		const cell4 = await executePython("my_symbol = 99\nprint(f'recovered:{my_symbol}')", {
			sessionId,
			kernelOwnerId: ownerId,
			toolSession,
			cwd: tempDir,
		});
		expect(cell4.exitCode).toBe(0);
		expect(cell4.output).toContain("recovered:99");

		// Recreation event is NOT repeated on subsequent calls on same generation
		const subsequentResetStatus = cell4.displayOutputs.find(
			d => d.type === "status" && d.event.op === "kernel_reset",
		);
		expect(subsequentResetStatus).toBeUndefined();
	});

	it("surfaces structured loss notice and recreation event across controlled JavaScript worker termination", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "rev-test-js-loss-"));
		const ownerId = `test-js-owner-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
		const sessionId = `test-js-session-${Date.now()}`;
		const settings = await Settings.init();
		const toolSession = createMockSession(sessionId, ownerId, tempDir, settings);

		activeCleanups.push(async () => {
			await disposeVmContextsByOwner(ownerId);
			fs.rmSync(tempDir, { recursive: true, force: true });
		});

		const sideEffectFile = path.join(tempDir, "js_side_effect.txt");

		// Cell 1: setup initial symbol and write side effect
		const cell1 = await executeJs(
			`globalThis.persisted_var = 'active'; import fs from 'fs'; fs.writeFileSync(${JSON.stringify(sideEffectFile)}, 'js_gen1');`,
			{
				sessionId,
				kernelOwnerId: ownerId,
				session: toolSession,
				cwd: tempDir,
			},
		);
		expect(cell1.exitCode).toBe(0);
		expect(fs.existsSync(sideEffectFile)).toBe(true);
		expect(fs.readFileSync(sideEffectFile, "utf-8")).toBe("js_gen1");

		// Cell 2: controlled forced termination
		const cell2 = await executeJs("process.exit(137);", {
			sessionId,
			kernelOwnerId: ownerId,
			session: toolSession,
			cwd: tempDir,
		});
		expect(cell2.exitCode).toBe(1);

		// Structured loss event on killing cell
		const lossStatus = cell2.displayOutputs.find(d => d.type === "status" && d.event.op === "kernel_reset");
		expect(lossStatus).toBeDefined();
		if (lossStatus && lossStatus.type === "status") {
			expect(lossStatus.event.op).toBe("kernel_reset");
			expect(lossStatus.event.language).toBe("js");
			expect(lossStatus.event.generation).toBe(1);
			expect(lossStatus.event.nextGeneration).toBe(2);
			expect(lossStatus.event.kernelKilled).toBe(true);
			expect(lossStatus.event.action).toBe("reimport_dependencies");
		}

		// Cell 3: attempting to access old symbol without re-declaring in gen 2
		const cell3 = await executeJs("console.log(String(globalThis.persisted_var));", {
			sessionId,
			kernelOwnerId: ownerId,
			session: toolSession,
			cwd: tempDir,
		});
		expect(cell3.exitCode).toBe(0);
		// Prior in-memory variable was wiped; string representation is undefined
		expect(cell3.output).toContain("undefined");

		// Structured recreation event
		const recreatedStatus = cell3.displayOutputs.find(d => d.type === "status" && d.event.op === "kernel_reset");
		expect(recreatedStatus).toBeDefined();
		if (recreatedStatus && recreatedStatus.type === "status") {
			expect(recreatedStatus.event.op).toBe("kernel_reset");
			expect(recreatedStatus.event.language).toBe("js");
			expect(recreatedStatus.event.generation).toBe(2);
			expect(recreatedStatus.event.previousGeneration).toBe(1);
			expect(recreatedStatus.event.recreated).toBe(true);
			expect(recreatedStatus.event.action).toBe("reimport_dependencies");
		}

		// Cell 4: explicit recovery
		const cell4 = await executeJs("globalThis.persisted_var = 'restored'; console.log(globalThis.persisted_var);", {
			sessionId,
			kernelOwnerId: ownerId,
			session: toolSession,
			cwd: tempDir,
		});
		expect(cell4.exitCode).toBe(0);
		expect(cell4.output).toContain("restored");
	});

	it("handles explicit reset cleanly without claiming unconfirmed termination", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "rev-test-reset-"));
		const ownerId = `test-reset-owner-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
		const sessionId = `test-reset-session-${Date.now()}`;
		const settings = await Settings.init();
		const toolSession = createMockSession(sessionId, ownerId, tempDir, settings);

		activeCleanups.push(async () => {
			await disposeKernelSessionsByOwner(ownerId);
			fs.rmSync(tempDir, { recursive: true, force: true });
		});

		const cell1 = await executePython("x = 1", {
			sessionId,
			kernelOwnerId: ownerId,
			toolSession,
			cwd: tempDir,
		});
		expect(cell1.exitCode).toBe(0);

		const cell2 = await executePython("x = 2\nprint(f'val:{x}')", {
			sessionId,
			kernelOwnerId: ownerId,
			toolSession,
			cwd: tempDir,
			reset: true,
		});
		expect(cell2.exitCode).toBe(0);
		expect(cell2.output).toContain("val:2");

		const resetStatus = cell2.displayOutputs.find(d => d.type === "status" && d.event.op === "kernel_reset");
		expect(resetStatus).toBeDefined();
		if (resetStatus && resetStatus.type === "status") {
			expect(resetStatus.event.op).toBe("kernel_reset");
			expect(resetStatus.event.reason).toBe("reset");
			expect(resetStatus.event.generation).toBe(2);
			expect(resetStatus.event.recreated).toBe(true);
		}

		// Cell 3: next call on same live kernel remains generation 2 (no double-increment)
		const cell3 = await executePython("print(f'next:{x}')", {
			sessionId,
			kernelOwnerId: ownerId,
			toolSession,
			cwd: tempDir,
		});
		expect(cell3.exitCode).toBe(0);
		expect(cell3.output).toContain("next:2");
		const state3 = getEvalState(toolSession);
		expect(state3?.runtimes.find(r => r.language === "python")?.generation).toBe(2);
		const cell3ResetStatus = cell3.displayOutputs.find(d => d.type === "status" && d.event.op === "kernel_reset");
		expect(cell3ResetStatus).toBeUndefined();
	});

	it("does not leave retained state or queue false recreation notices in per-call mode", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "rev-test-percall-"));
		const ownerId = `test-percall-owner-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
		const sessionId = `test-percall-session-${Date.now()}`;
		const settings = await Settings.init();
		const toolSession = createMockSession(sessionId, ownerId, tempDir, settings);

		activeCleanups.push(async () => {
			await disposeKernelSessionsByOwner(ownerId);
			fs.rmSync(tempDir, { recursive: true, force: true });
		});

		const cell1 = await executePython("a = 10\nprint(f'val:{a}')", {
			sessionId,
			kernelOwnerId: ownerId,
			toolSession,
			cwd: tempDir,
			kernelMode: "per-call",
		});
		expect(cell1.exitCode).toBe(0);
		expect(cell1.output).toContain("val:10");

		// In per-call mode, retained state is not registered
		const state = getEvalState(toolSession);
		expect(state).toBeUndefined();

		const cell2 = await executePython("b = 20\nprint(f'val:{b}')", {
			sessionId,
			kernelOwnerId: ownerId,
			toolSession,
			cwd: tempDir,
			kernelMode: "per-call",
		});
		expect(cell2.exitCode).toBe(0);
		expect(cell2.output).toContain("val:20");
		const status = cell2.displayOutputs.find(d => d.type === "status" && d.event.op === "kernel_reset");
		expect(status).toBeUndefined();
	});

	it("records loadedPath only after successful execution", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "rev-test-loaded-"));
		const ownerId = `test-loaded-owner-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
		const sessionId = `test-loaded-session-${Date.now()}`;
		const settings = await Settings.init();
		const toolSession = createMockSession(sessionId, ownerId, tempDir, settings);

		activeCleanups.push(async () => {
			await disposeKernelSessionsByOwner(ownerId);
			fs.rmSync(tempDir, { recursive: true, force: true });
		});

		const failingScript = path.join(tempDir, "failing.py");
		fs.writeFileSync(failingScript, "raise RuntimeError('intentional load failure')\n");

		const cellFail = await executePython(fs.readFileSync(failingScript, "utf-8"), {
			sessionId,
			kernelOwnerId: ownerId,
			toolSession,
			cwd: tempDir,
			filename: failingScript,
		});
		expect(cellFail.exitCode).toBe(1);

		// Failing load must NOT be recorded in loadedPaths
		const stateAfterFail = getEvalState(toolSession);
		const pyRuntimeAfterFail = stateAfterFail?.runtimes.find(r => r.language === "python");
		expect(pyRuntimeAfterFail?.loadedPaths).toEqual([]);

		const successScript = path.join(tempDir, "success.py");
		fs.writeFileSync(successScript, "success_val = 42\n");

		const cellSuccess = await executePython(fs.readFileSync(successScript, "utf-8"), {
			sessionId,
			kernelOwnerId: ownerId,
			toolSession,
			cwd: tempDir,
			filename: successScript,
		});
		expect(cellSuccess.exitCode).toBe(0);

		// Successful load must be recorded
		const stateAfterSuccess = getEvalState(toolSession);
		const pyRuntimeAfterSuccess = stateAfterSuccess?.runtimes.find(r => r.language === "python");
		expect(pyRuntimeAfterSuccess?.loadedPaths).toEqual([path.resolve(successScript)]);
	});
});
