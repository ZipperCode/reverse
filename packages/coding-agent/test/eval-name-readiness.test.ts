import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "bun:test";
import { Settings } from "../src/config/settings";
import { disposeVmContextsByOwner } from "../src/eval/js/context-manager";
import { executeJs } from "../src/eval/js/executor";
import { disposeKernelSessionsByOwner, executePython } from "../src/eval/py/executor";
import { formatEvalStateContext, getEvalState } from "../src/eval/state";
import type { ToolSession } from "../src/tools";
import { EvalTool } from "../src/tools/eval";

function createTestSession(sessionId: string, ownerId: string, cwd: string, settings: Settings): ToolSession {
	return {
		cwd,
		hasUI: false,
		settings,
		getSessionFile: () => null,
		getSessionSpawns: () => null,
		getEvalSessionId: () => sessionId,
		getEvalKernelOwnerId: () => ownerId,
	} as unknown as ToolSession;
}

describe("Issue #19: eval variable readiness, partial failed cell handoff, and structured missing-name diagnostics", () => {
	const cleanups: Array<() => Promise<void>> = [];

	afterEach(async () => {
		while (cleanups.length > 0) {
			const fn = cleanups.pop();
			if (fn) await fn();
		}
	});

	it("retains Python assignments before an exception, excludes assignments after it, keeps generation stable, and avoids auto-replaying side effects", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "rev-eval-readiness-py-"));
		const ownerId = `owner-py-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
		const sessionId = `session-py-${Date.now()}`;
		const settings = await Settings.init();
		const session = createTestSession(sessionId, ownerId, tempDir, settings);
		const tool = new EvalTool(session);

		cleanups.push(async () => {
			await disposeKernelSessionsByOwner(ownerId);
			fs.rmSync(tempDir, { recursive: true, force: true });
		});

		const sideEffectCounterFile = path.join(tempDir, "setup_runs.txt");

		// Cell 1: increments side-effect counter, defines BAR and lowercase root, fails on nonexistent import before LIBC_PATH
		const cell1 = await tool.execute("call-1", {
			language: "py",
			code: [
				`from pathlib import Path`,
				`p = Path(${JSON.stringify(sideEffectCounterFile)})`,
				`count = int(p.read_text()) if p.exists() else 0`,
				`p.write_text(str(count + 1))`,
				`BAR = 456`,
				`root = Path('.')`,
				`import nonexistent_lief_module_19`,
				`LIBC_PATH = 'artifacts/realsdk/device_libc.so'`,
			].join("\n"),
		});

		expect(cell1.details?.isError).toBe(true);
		expect(fs.readFileSync(sideEffectCounterFile, "utf-8")).toBe("1");

		// Host state must remain generation=1, alive=true, with observed namespace containing BAR and root, NOT LIBC_PATH
		const stateAfterCell1 = getEvalState(session);
		const pyRuntime1 = stateAfterCell1?.runtimes.find(r => r.language === "python");
		expect(pyRuntime1?.alive).toBe(true);
		expect(pyRuntime1?.generation).toBe(1);
		expect(pyRuntime1?.namespaceStatus).toBe("observed");
		expect(pyRuntime1?.definedNames).toContain("BAR");
		expect(pyRuntime1?.definedNames).toContain("root");
		expect(pyRuntime1?.definedNames).toContain("Path");
		expect(pyRuntime1?.definedNames).not.toContain("LIBC_PATH");

		const contextText = formatEvalStateContext(session) ?? "";
		expect(contextText).toContain("generation=1");
		expect(contextText).toContain("namespace=observed");
		expect(contextText).toContain("BAR");
		expect(contextText).not.toContain("LIBC_PATH");

		// Cell 2: references LIBC_PATH (never executed in Cell 1) -> structured missingNames + observed names + recovery guidance
		const cell2 = await tool.execute("call-2", {
			language: "py",
			code: "print(LIBC_PATH)",
		});
		expect(cell2.details?.isError).toBe(true);
		expect(cell2.details?.missingNames).toEqual(["LIBC_PATH"]);
		expect(cell2.details?.definedNames).toContain("BAR");
		expect(cell2.details?.definedNames).not.toContain("LIBC_PATH");
		expect(cell2.details?.recoveryGuidance).toContain("Define or import the missing name explicitly");
		const cell2Text = cell2.content[0]?.type === "text" ? cell2.content[0].text : "";
		expect(cell2Text).toContain("NameError");
		expect(cell2Text).toContain("Missing names: LIBC_PATH");
		expect(cell2Text).toContain("Observed namespace names:");
		expect(cell2Text).toContain("BAR");
		expect(cell2Text).toContain("Recovery:");

		// Side-effect counter must still be 1 (no automatic replay of Cell 1 setup)
		expect(fs.readFileSync(sideEffectCounterFile, "utf-8")).toBe("1");

		// Cell 3: references uppercase ROOT when lowercase 'root' exists -> surfaces case-variant hint and keeps BAR usable
		const cell3 = await tool.execute("call-3", {
			language: "py",
			code: "print(BAR, ROOT)",
		});
		expect(cell3.details?.isError).toBe(true);
		expect(cell3.details?.missingNames).toEqual(["ROOT"]);
		expect(cell3.details?.recoveryGuidance).toContain("'root'");

		// Cell 4: uses retained BAR and defines LIBC_PATH explicitly -> succeeds on same generation 1
		const cell4 = await tool.execute("call-4", {
			language: "py",
			code: "LIBC_PATH = 'artifacts/realsdk/device_libc.so'\nprint(f'{BAR}:{LIBC_PATH}')",
		});
		expect(cell4.details?.isError).toBeUndefined();
		const cell4Text = cell4.content[0]?.type === "text" ? cell4.content[0].text : "";
		expect(cell4Text).toContain("456:artifacts/realsdk/device_libc.so");
		expect(getEvalState(session)?.runtimes.find(r => r.language === "python")?.definedNames).toContain("LIBC_PATH");
		expect(getEvalState(session)?.runtimes.find(r => r.language === "python")?.generation).toBe(1);
		expect(fs.readFileSync(sideEffectCounterFile, "utf-8")).toBe("1");
	});

	it("bounds Python namespace snapshots without invoking object repr/getters, and clears snapshot on kernel kill", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "rev-eval-bounds-py-"));
		const ownerId = `owner-bounds-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
		const sessionId = `session-bounds-${Date.now()}`;
		const settings = await Settings.init();
		const session = createTestSession(sessionId, ownerId, tempDir, settings);

		cleanups.push(async () => {
			await disposeKernelSessionsByOwner(ownerId);
			fs.rmSync(tempDir, { recursive: true, force: true });
		});

		const res1 = await executePython(
			[
				"class PoisonRepr:",
				"    def __repr__(self):",
				"        raise RuntimeError('repr must never be called by namespace snapshot')",
				"poison_obj = PoisonRepr()",
				"_secret_internal = 'hidden'",
				"for idx in range(80):",
				"    globals()[f'user_sym_{idx:03d}'] = idx",
				"print('ok')",
			].join("\n"),
			{
				cwd: tempDir,
				sessionId: `python:${sessionId}`,
				kernelOwnerId: ownerId,
				toolSession: session,
			},
		);

		expect(res1.exitCode).toBe(0);
		expect(res1.definedNames).toHaveLength(64);
		expect(res1.definedNames).toContain("poison_obj");
		expect(res1.definedNames).not.toContain("_secret_internal");
		expect(res1.definedNamesOmitted).toBeGreaterThan(15);

		// Also verify Python 3.9 fallback when NameError.name attribute is absent/cleared
		const resPy39 = await executePython(
			[
				"err = NameError(\"name 'legacy_py39_symbol' is not defined\")",
				"try:",
				"    err.name = None",
				"except Exception:",
				"    pass",
				"raise err",
			].join("\n"),
			{
				cwd: tempDir,
				sessionId: `python:${sessionId}`,
				kernelOwnerId: ownerId,
				toolSession: session,
			},
		);
		expect(resPy39.exitCode).toBe(1);
		expect(resPy39.missingNames).toEqual(["legacy_py39_symbol"]);

		// Kill the kernel: snapshot must clear immediately and next cell must increment generation
		await executePython("import os; os._exit(130)", {
			cwd: tempDir,
			sessionId: `python:${sessionId}`,
			kernelOwnerId: ownerId,
			toolSession: session,
		});
		const deadRuntime = getEvalState(session)?.runtimes.find(r => r.language === "python");
		expect(deadRuntime?.alive).toBe(false);
		expect(deadRuntime?.namespaceStatus).toBe("unverified");
		expect(deadRuntime?.definedNames).toEqual([]);

		const resGen2 = await executePython("fresh_gen2_var = 1\nprint(fresh_gen2_var)", {
			cwd: tempDir,
			sessionId: `python:${sessionId}`,
			kernelOwnerId: ownerId,
			toolSession: session,
		});
		expect(resGen2.exitCode).toBe(0);
		const gen2Runtime = getEvalState(session)?.runtimes.find(r => r.language === "python");
		expect(gen2Runtime?.alive).toBe(true);
		expect(gen2Runtime?.generation).toBe(2);
		expect(gen2Runtime?.namespaceStatus).toBe("observed");
		expect(gen2Runtime?.definedNames).toContain("fresh_gen2_var");
		expect(gen2Runtime?.definedNames).not.toContain("poison_obj");
	});

	it("surfaces structured missingNames and unverified namespace guidance on JavaScript ReferenceError", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "rev-eval-readiness-js-"));
		const ownerId = `owner-js-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
		const sessionId = `session-js-${Date.now()}`;
		const settings = await Settings.init();
		const session = createTestSession(sessionId, ownerId, tempDir, settings);
		const tool = new EvalTool(session);

		cleanups.push(async () => {
			await disposeVmContextsByOwner(ownerId);
			fs.rmSync(tempDir, { recursive: true, force: true });
		});

		const jsFail = await executeJs("console.log(missingJsSymbol19);", {
			cwd: tempDir,
			sessionId: `js:${sessionId}`,
			kernelOwnerId: ownerId,
			session,
		});
		expect(jsFail.exitCode).toBe(1);
		expect(jsFail.missingNames).toEqual(["missingJsSymbol19"]);
		expect(jsFail.recoveryGuidance).toContain("Define or import the missing binding explicitly");
		expect(jsFail.output).toContain("Missing names: missingJsSymbol19");
		expect(jsFail.output).toContain("Observed namespace names: unverified");

		const toolRes = await tool.execute("call-js-1", {
			language: "js",
			code: "console.log(anotherMissingJsBinding);",
		});
		expect(toolRes.details?.isError).toBe(true);
		expect(toolRes.details?.missingNames).toEqual(["anotherMissingJsBinding"]);
		expect(toolRes.details?.recoveryGuidance).toBeDefined();

		const jsRuntime = getEvalState(session)?.runtimes.find(r => r.language === "js");
		expect(jsRuntime?.alive).toBe(true);
		expect(jsRuntime?.namespaceStatus).toBe("unverified");
		expect(formatEvalStateContext(session)).toContain("namespace=unverified");
	});
});
