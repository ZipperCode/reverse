import { describe, expect, it } from "bun:test";
import * as child_process from "node:child_process";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { isRecord } from "@reverse/utils";
import { Settings } from "../src/config/settings";
import { callSessionTool } from "../src/eval/js/tool-bridge";
import {
	computeLiefReadinessFingerprint,
	type LiefDetailedProbeResult,
	probePythonForLiefDetailed,
	resolveLiefPythonDetailed,
} from "../src/extensibility/lief-install";
import { DependencyGate, getSessionDependencyGate } from "../src/session/dependency-gate";
import type { SessionEntry } from "../src/session/session-entries";
import type { Tool, ToolSession } from "../src/tools";
import {
	type ElfInspectDetails,
	ElfInspectTool,
	type ElfPrerequisiteBlockedDetails,
	type ElfProbeFailedDetails,
	type ElfQueryDetails,
} from "../src/tools/elf-inspect";
import { dispatchXdevTool, type XdevState } from "../src/tools/xdev";

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

function isBlockedDetails(details: unknown): details is ElfPrerequisiteBlockedDetails {
	return isRecord(details) && details.status === "blocked_prerequisite" && details.deterministicFailure === true;
}

function isProbeFailedDetails(details: unknown): details is ElfProbeFailedDetails {
	return isRecord(details) && details.status === "probe_failed" && details.deterministicFailure === false;
}

function isQueryDetails(details: ElfInspectDetails): details is ElfQueryDetails {
	return details.action === "query" && !("status" in details);
}

function createHarnessSession(cwd: string, branchEntries: SessionEntry[] = []): ToolSession {
	const toolRegistry = new Map<string, Tool>();
	const sessionManager = {
		getSessionId: () => "session-dep-gate-test",
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
		getSessionId: () => "session-dep-gate-test",
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": true }),
		getPlanModeState: () => ({ enabled: false, planFilePath: path.join(cwd, "PLAN.md") }),
		sessionManager,
		toolRegistry,
		getToolByName: name => toolRegistry.get(name),
		getToolForEvalBridge: name => toolRegistry.get(name),
		getEvalBridgeToolNames: () => [...toolRegistry.keys()],
	};
}

describe("DependencyGate & ElfInspectTool deterministic prerequisite gating (#17)", () => {
	it("coalesces concurrent fanout and blocks repeated missing-LIEF queries with single probe dispatch", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "elf-gate-fanout-"));
		const elfPath = path.join(tempDir, "libtarget.so");
		await fs.writeFile(elfPath, createMinimalElf64FileBuffer());

		try {
			const branch: SessionEntry[] = [];
			const session = createHarnessSession(tempDir, branch);
			let probeCalls = 0;
			let workerCalls = 0;
			const fingerprint = "fp:missing-lief-v1";
			const probeEntered = Promise.withResolvers<void>();
			const releaseProbe = Promise.withResolvers<void>();

			const tool = new ElfInspectTool(session, {
				computeFingerprint: () => fingerprint,
				resolveLiefDetailed: async () => {
					probeCalls += 1;
					probeEntered.resolve();
					await releaseProbe.promise;
					return {
						status: "missing_module",
						available: false,
						deterministic: true,
						pythonBin: "/usr/bin/python3",
						version: null,
						modulePath: null,
						error: "No module named 'lief'",
						readinessFingerprint: fingerprint,
						checkedCandidates: ["/usr/bin/python3"],
					};
				},
				runWorker: async () => {
					workerCalls += 1;
					return { status: "ok", result: { status: "ok", result: {} } };
				},
			});

			// Launch 3-way concurrent fanout while holding the single-flight probe gate open deterministically
			const p1 = tool.execute("call-fanout-1", { action: "query", path: elfPath });
			await probeEntered.promise;
			const p2 = tool.execute("call-fanout-2", { action: "query", path: elfPath });
			const p3 = tool.execute("call-fanout-3", { action: "query", path: elfPath });
			releaseProbe.resolve();

			const [res1, res2, res3] = await Promise.all([p1, p2, p3]);

			expect(probeCalls).toBe(1);
			expect(workerCalls).toBe(0);

			expect(res1.isError).toBe(true);
			expect(res2.isError).toBe(true);
			expect(res3.isError).toBe(true);

			expect(isBlockedDetails(res1.details)).toBe(true);
			expect(isBlockedDetails(res2.details)).toBe(true);
			expect(isBlockedDetails(res3.details)).toBe(true);
			if (!isBlockedDetails(res1.details) || !isBlockedDetails(res2.details) || !isBlockedDetails(res3.details)) {
				throw new Error("Expected structured blocked prerequisite details");
			}

			expect(res1.details.missingDependency).toBe("lief");
			expect(res1.details.failureKind).toBe("missing_module");
			expect(res1.details.setupCommand).toBe("reverse setup reverse lief");
			expect(res1.details.blockedByGate).toBe(false);
			expect(res1.details.sourceToolCallId).toBe("call-fanout-1");
			expect(res1.details.attemptCount).toBe(1);

			expect(res2.details.blockedByGate).toBe(true);
			expect(res2.details.sourceToolCallId).toBe("call-fanout-1");
			expect(res3.details.blockedByGate).toBe(true);
			expect(res3.details.sourceToolCallId).toBe("call-fanout-1");
			expect([res2.details.attemptCount, res3.details.attemptCount].sort()).toEqual([2, 3]);

			// Simulate journal persistence of the first failure followed by shake compaction eliding text
			branch.push({
				type: "message",
				id: "entry-lief-fail-1",
				parentId: null,
				timestamp: new Date().toISOString(),
				message: {
					role: "toolResult",
					toolCallId: "call-fanout-1",
					toolName: "elf_inspect",
					content: [{ type: "text", text: "[shaken ~26 tokens — recover: artifact://389 (region 13)]" }],
					details: res1.details,
					isError: true,
					timestamp: Date.now(),
				},
			});

			const res4 = await tool.execute("call-seq-4", { action: "query", path: elfPath });
			expect(probeCalls).toBe(1);
			expect(workerCalls).toBe(0);
			expect(isBlockedDetails(res4.details)).toBe(true);
			if (isBlockedDetails(res4.details)) {
				expect(res4.details.blockedByGate).toBe(true);
				expect(res4.details.sourceToolCallId).toBe("call-fanout-1");
				expect(res4.details.sourceEntryId).toBe("entry-lief-fail-1");
				expect(res4.details.attemptCount).toBe(4);
			}
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("survives compaction via branch details, unlocks on status/fingerprint update, and never rehydrates cleared failures", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "elf-gate-rehydrate-"));
		const elfPath = path.join(tempDir, "libtest.so");
		await fs.writeFile(elfPath, createMinimalElf64FileBuffer());

		try {
			const branch: SessionEntry[] = [];
			const currentFingerprint = "fp:before-install";
			let liefInstalled = false;
			let probeCalls = 0;

			const makeDeps = (gate: DependencyGate) => ({
				gate,
				computeFingerprint: () => currentFingerprint,
				resolveLiefDetailed: async (): Promise<LiefDetailedProbeResult> => {
					probeCalls += 1;
					if (!liefInstalled) {
						return {
							status: "missing_module",
							available: false,
							deterministic: true,
							pythonBin: "/usr/bin/python3",
							version: null,
							modulePath: null,
							error: "No module named 'lief'",
							readinessFingerprint: currentFingerprint,
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
						readinessFingerprint: currentFingerprint,
						checkedCandidates: ["/usr/bin/python3"],
					};
				},
				runWorker: async () => ({
					status: "ok" as const,
					result: {
						status: "ok",
						result: { header: { machine: "AARCH64", bitness: 64 } },
					},
				}),
			});

			const session = createHarnessSession(tempDir, branch);
			const tool1 = new ElfInspectTool(session, makeDeps(new DependencyGate(session)));
			const firstFail = await tool1.execute("call-initial", { action: "query", path: elfPath });
			expect(firstFail.isError).toBe(true);
			expect(probeCalls).toBe(1);

			branch.push({
				type: "message",
				id: "entry-initial-fail",
				parentId: null,
				timestamp: new Date().toISOString(),
				message: {
					role: "toolResult",
					toolCallId: "call-initial",
					toolName: "elf_inspect",
					content: [{ type: "text", text: "[shaken ~26 tokens]" }],
					details: firstFail.details,
					isError: true,
					timestamp: Date.now(),
				},
			});

			// Fresh DependencyGate rehydrates from branch journal without re-probing
			const rehydratedGate = new DependencyGate(session);
			const toolAfterCompaction = new ElfInspectTool(session, makeDeps(rehydratedGate));
			const secondCall = await toolAfterCompaction.execute("call-post-handoff", {
				action: "query",
				path: elfPath,
			});
			expect(secondCall.isError).toBe(true);
			expect(probeCalls).toBe(1);
			expect(isBlockedDetails(secondCall.details)).toBe(true);
			if (isBlockedDetails(secondCall.details)) {
				expect(secondCall.details.blockedByGate).toBe(true);
				expect(secondCall.details.sourceToolCallId).toBe("call-initial");
				expect(secondCall.details.sourceEntryId).toBe("entry-initial-fail");
			}

			// Even BEFORE fingerprint changes, an explicit `status` refresh when LIEF becomes available clears the gate
			// and does NOT rehydrate the older failure from `branch` on subsequent queries!
			liefInstalled = true;
			const statusRes = await toolAfterCompaction.execute("call-status-refresh", { action: "status" });
			expect(statusRes.details.action).toBe("status");
			if (statusRes.details.action === "status") {
				expect(statusRes.details.ready).toBe(true);
				expect(statusRes.details.lief.available).toBe(true);
			}
			expect(probeCalls).toBe(2);

			const thirdCall = await toolAfterCompaction.execute("call-after-status-clear", {
				action: "query",
				path: elfPath,
			});
			expect(thirdCall.isError).toBeUndefined();
			expect(isQueryDetails(thirdCall.details)).toBe(true);
			if (isQueryDetails(thirdCall.details)) {
				expect(thirdCall.details.data).toEqual({ header: { machine: "AARCH64", bitness: 64 } });
			}
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("distinguishes probe_failed and transient worker errors from missing_module without caching permanent blocks", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "elf-probe-failed-"));
		const elfPath = path.join(tempDir, "libtransient.so");
		await fs.writeFile(elfPath, createMinimalElf64FileBuffer());

		try {
			const session = createHarnessSession(tempDir);
			let probeAttempt = 0;
			let workerAttempt = 0;
			const fingerprint = "fp:same-env";

			const tool = new ElfInspectTool(session, {
				computeFingerprint: () => fingerprint,
				resolveLiefDetailed: async () => {
					probeAttempt += 1;
					if (probeAttempt === 1) {
						return {
							status: "probe_failed",
							available: false,
							deterministic: false,
							pythonBin: "/usr/bin/python3",
							version: null,
							modulePath: null,
							error: "Subprocess probe timed out after 4000ms (ETIMEDOUT)",
							readinessFingerprint: fingerprint,
							checkedCandidates: ["/usr/bin/python3"],
						};
					}
					return {
						status: "available",
						available: true,
						deterministic: true,
						pythonBin: "/usr/bin/python3",
						version: "1.0.0",
						modulePath: "/usr/lib/python3/dist-packages/lief/__init__.py",
						readinessFingerprint: fingerprint,
						checkedCandidates: ["/usr/bin/python3"],
					};
				},
				runWorker: async () => {
					workerAttempt += 1;
					if (workerAttempt === 1) {
						return {
							status: "error",
							error: "Execution timed out after 60000ms",
						};
					}
					return {
						status: "ok",
						result: { status: "ok", result: { segments: [] } },
					};
				},
			});

			// 1. Subprocess probe failure returns probe_failed and is NOT cached as missing LIEF
			const first = await tool.execute("call-timeout-1", { action: "query", path: elfPath });
			expect(first.isError).toBe(true);
			expect(isProbeFailedDetails(first.details)).toBe(true);
			if (isProbeFailedDetails(first.details)) {
				expect(first.details.probeError).toContain("ETIMEDOUT");
			}

			// 2. Transient worker timeout throws ToolError and does NOT arm missing-LIEF gate
			await expect(tool.execute("call-worker-timeout-2", { action: "query", path: elfPath })).rejects.toBeInstanceOf(
				ToolError,
			);
			expect(probeAttempt).toBe(2);
			expect(workerAttempt).toBe(1);

			// 3. Subsequent retry succeeds cleanly under unchanged fingerprint
			const third = await tool.execute("call-ok-3", { action: "query", path: elfPath });
			expect(third.isError).toBeUndefined();
			expect(workerAttempt).toBe(2);
			expect(isQueryDetails(third.details)).toBe(true);
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("maintains consistent gate and structured blocker details across direct tool, xd://, and eval bridge", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "elf-paths-consistency-"));
		const elfPath = path.join(tempDir, "libbridge.so");
		await fs.writeFile(elfPath, createMinimalElf64FileBuffer());

		try {
			const session = createHarnessSession(tempDir);
			let probeCalls = 0;
			const fingerprint = "fp:multi-surface";

			const tool = new ElfInspectTool(session, {
				computeFingerprint: () => fingerprint,
				resolveLiefDetailed: async () => {
					probeCalls += 1;
					return {
						status: "missing_module",
						available: false,
						deterministic: true,
						pythonBin: "/usr/bin/python3",
						version: null,
						modulePath: null,
						error: "No module named 'lief'",
						readinessFingerprint: fingerprint,
						checkedCandidates: ["/usr/bin/python3"],
					};
				},
			});
			const registeredTool: Tool = tool;
			session.toolRegistry?.set("elf_inspect", registeredTool);

			const xdevState: XdevState = {
				tools: session.toolRegistry!,
				mountedNames: new Set(["elf_inspect"]),
				builtInNames: new Set(["elf_inspect"]),
				isActive: () => true,
			};
			session.xdev = xdevState;

			// 1. Direct execution arms the gate
			const directRes = await tool.execute("direct-call-1", { action: "query", path: elfPath });
			expect(directRes.isError).toBe(true);
			expect(probeCalls).toBe(1);
			expect(isBlockedDetails(directRes.details)).toBe(true);
			if (isBlockedDetails(directRes.details)) {
				expect(directRes.details.blockedByGate).toBe(false);
			}

			// 2. xd:// dispatch hits the same session gate without re-probing
			const xdRes = await dispatchXdevTool(
				xdevState,
				"elf_inspect",
				JSON.stringify({ action: "query", path: elfPath }),
				"xd-call-2",
			);
			expect(xdRes.result.isError).toBe(true);
			expect(probeCalls).toBe(1);
			expect(isBlockedDetails(xdRes.xdev.inner)).toBe(true);
			if (isBlockedDetails(xdRes.xdev.inner)) {
				expect(xdRes.xdev.inner.blockedByGate).toBe(true);
				expect(xdRes.xdev.inner.sourceToolCallId).toBe("direct-call-1");
				expect(xdRes.xdev.inner.attemptCount).toBe(2);
			}

			// 3. eval JS bridge hits the same session gate without re-probing
			const bridgeRes = await callSessionTool("elf_inspect", { action: "query", path: elfPath }, { session });
			expect(
				typeof bridgeRes === "object" && bridgeRes !== null && "details" in bridgeRes && "hasError" in bridgeRes,
			).toBe(true);
			if (typeof bridgeRes === "object" && bridgeRes !== null && "details" in bridgeRes && "hasError" in bridgeRes) {
				expect(bridgeRes.hasError).toBe(true);
				expect(probeCalls).toBe(1);
				expect(isBlockedDetails(bridgeRes.details)).toBe(true);
				if (isBlockedDetails(bridgeRes.details)) {
					expect(bridgeRes.details.blockedByGate).toBe(true);
					expect(bridgeRes.details.sourceToolCallId).toBe("direct-call-1");
					expect(bridgeRes.details.attemptCount).toBe(3);
				}
			}
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("controlled Python subprocess smoke: verifies real venv missing_module, broken-runner probe_failed, and site-packages readiness invalidation", async () => {
		const hostPython = Bun.which("python3") ?? Bun.which("python");
		if (!hostPython) return;

		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "elf-real-py-smoke-"));
		const venvDir = path.join(tempDir, "tools", "lief-venv");
		const elfPath = path.join(tempDir, "libsmoke.so");
		await fs.writeFile(elfPath, createMinimalElf64FileBuffer());

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

			const isolatedEnv: Record<string, string | undefined> = {
				PATH: "",
				LIEF_PYTHON: venvPython,
				HOME: tempDir,
			};

			// 1. Real Python subprocess probe against empty venv confirms ModuleNotFoundError -> missing_module
			const initialProbe = probePythonForLiefDetailed(venvPython, isolatedEnv, { isolatedOnly: true });
			expect(initialProbe.status).toBe("missing_module");

			// 2. Real broken interpreter wrapper triggers probe_failed (never conflated into missing_module)
			if (process.platform !== "win32") {
				const brokenBin = path.join(tempDir, "broken-python");
				await fs.writeFile(brokenBin, "#!/bin/sh\necho 'Runtime loader crash' >&2\nexit 17\n", { mode: 0o755 });
				const brokenProbe = probePythonForLiefDetailed(brokenBin, isolatedEnv, { isolatedOnly: true });
				expect(brokenProbe.status).toBe("probe_failed");
				expect(brokenProbe.error).toContain("Runtime loader crash");
			}

			const fpBefore = computeLiefReadinessFingerprint({
				env: isolatedEnv,
				agentDir: tempDir,
				which: () => null,
			});

			const session = createHarnessSession(tempDir);
			const gate = getSessionDependencyGate(session);
			const tool = new ElfInspectTool(session, {
				gate,
				liefOptions: {
					env: isolatedEnv,
					agentDir: tempDir,
					which: () => null,
				},
			});

			// First query executes real Python subprocess probe and records deterministic block
			const fail1 = await tool.execute("smoke-call-1", { action: "query", path: elfPath });
			expect(fail1.isError).toBe(true);
			expect(isBlockedDetails(fail1.details)).toBe(true);
			if (isBlockedDetails(fail1.details)) {
				expect(fail1.details.failureKind).toBe("missing_module");
				expect(fail1.details.blockedByGate).toBe(false);
			}

			// Second query is blocked by session gate without spawning Python again
			const fail2 = await tool.execute("smoke-call-2", { action: "query", path: elfPath });
			expect(fail2.isError).toBe(true);
			expect(isBlockedDetails(fail2.details)).toBe(true);
			if (isBlockedDetails(fail2.details)) {
				expect(fail2.details.blockedByGate).toBe(true);
				expect(fail2.details.attemptCount).toBe(2);
			}

			// 3. Mutating real site-packages in the SAME venv updates readiness fingerprint automatically
			const spOut = child_process.spawnSync(venvPython, ["-c", "import site; print(site.getsitepackages()[0])"], {
				encoding: "utf8",
				timeout: 5000,
			});
			expect(spOut.status).toBe(0);
			const sitePackagesDir = spOut.stdout.trim();
			await fs.mkdir(path.join(sitePackagesDir, "lief-1.0.0.dist-info"), { recursive: true });

			const fpAfter = computeLiefReadinessFingerprint({
				env: isolatedEnv,
				agentDir: tempDir,
				which: () => null,
			});
			expect(fpAfter).not.toBe(fpBefore);

			// Because fpAfter !== fpBefore, next query invalidates the old gate record and re-probes fresh
			const reprobed = await tool.execute("smoke-call-3", { action: "query", path: elfPath });
			expect(reprobed.isError).toBe(true);
			expect(isBlockedDetails(reprobed.details)).toBe(true);
			if (isBlockedDetails(reprobed.details)) {
				expect(reprobed.details.blockedByGate).toBe(false);
				expect(reprobed.details.attemptCount).toBe(1);
				expect(reprobed.details.sourceToolCallId).toBe("smoke-call-3");
			}

			// 4. If host environment already has a real LIEF installation, verify real end-to-end recovery
			const hostLief = resolveLiefPythonDetailed();
			if (hostLief.available && hostLief.pythonBin) {
				isolatedEnv.LIEF_PYTHON = hostLief.pythonBin;
				const okRes = await tool.execute("smoke-call-4", {
					action: "query",
					path: elfPath,
					query_type: "info",
				});
				expect(okRes.isError).toBeUndefined();
				expect(isQueryDetails(okRes.details)).toBe(true);
			}
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	// 受控 SoFixer 替身为 POSIX shell 脚本；Windows 主机需真实 SoFixer 二进制才能覆盖该路径
	it.skipIf(process.platform === "win32")(
		"propagates blocked LIEF prerequisite through repair with the unvalidated SoFixer candidate preserved",
		async () => {
			const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "elf-repair-blocked-"));
			const dumpPath = path.join(tempDir, "libdump.so");
			const binDir = path.join(tempDir, "bin");
			const sofixerPath = path.join(binDir, "sofixer");
			await fs.mkdir(binDir, { recursive: true });
			await fs.writeFile(dumpPath, createMinimalElf64FileBuffer());
			// 受控 SoFixer 替身：仅复制输入到 -o 目标，使候选保留路径可被真实校验
			await fs.writeFile(
				sofixerPath,
				[
					"#!/bin/sh",
					'while [ "$#" -gt 0 ]; do',
					'  case "$1" in',
					'    -s) src="$2"; shift 2 ;;',
					'    -o) out="$2"; shift 2 ;;',
					"    *) shift ;;",
					"  esac",
					"done",
					'cp "$src" "$out"',
				].join("\n"),
				{ mode: 0o755 },
			);

			const previousSofixerPath = process.env.SOFIXER_PATH;
			process.env.SOFIXER_PATH = sofixerPath;
			try {
				const session = createHarnessSession(tempDir);
				const fingerprint = "fp:repair-missing-lief";
				const tool = new ElfInspectTool(session, {
					computeFingerprint: () => fingerprint,
					resolveLiefDetailed: async () => ({
						status: "missing_module",
						available: false,
						deterministic: true,
						pythonBin: "/usr/bin/python3",
						version: null,
						modulePath: null,
						error: "No module named 'lief'",
						readinessFingerprint: fingerprint,
						checkedCandidates: ["/usr/bin/python3"],
					}),
				});

				const repairRes = await tool.execute("repair-call-1", {
					action: "repair",
					dump_path: dumpPath,
					base_address: "0x1000",
				});

				// 未验证候选绝不能以 success:true 返回
				expect(repairRes.isError).toBe(true);
				expect(isBlockedDetails(repairRes.details)).toBe(true);
				if (!isBlockedDetails(repairRes.details)) throw new Error("expected blocked repair details");
				expect(repairRes.details.action).toBe("repair");
				expect("success" in repairRes.details).toBe(false);

				const preserved = repairRes.details.candidate;
				expect(preserved).toBeDefined();
				if (!preserved) throw new Error("expected preserved candidate");
				expect(preserved.dumpPath).toBe(dumpPath);
				expect(preserved.baseAddress).toBe("0x1000");
				expect(preserved.candidateBytes).toBeGreaterThan(0);
				// 候选文件真实存在且内容可读，供依赖安装后重新验证
				const preservedBytes = await fs.readFile(preserved.candidatePath);
				expect(preservedBytes.length).toBe(preserved.candidateBytes);

				// 第二次 repair 被同一门禁拦截，仍保留候选
				const secondRes = await tool.execute("repair-call-2", {
					action: "repair",
					dump_path: dumpPath,
					base_address: "0x1000",
				});
				expect(secondRes.isError).toBe(true);
				expect(isBlockedDetails(secondRes.details)).toBe(true);
				if (isBlockedDetails(secondRes.details)) {
					expect(secondRes.details.blockedByGate).toBe(true);
					expect(secondRes.details.sourceToolCallId).toBe("repair-call-1");
				}
			} finally {
				if (previousSofixerPath === undefined) delete process.env.SOFIXER_PATH;
				else process.env.SOFIXER_PATH = previousSofixerPath;
				await fs.rm(tempDir, { recursive: true, force: true });
			}
		},
	);

	it("readiness fingerprint tracks user-site package dirs so a pip --user install invalidates cached failures", async () => {
		const homeDir = await fs.mkdtemp(path.join(os.tmpdir(), "lief-user-site-"));
		const sitePackages = path.join(homeDir, ".local", "lib", "python3.11", "site-packages");
		const env: Record<string, string | undefined> = { HOME: homeDir, PATH: "" };
		const liefOptions = { env, agentDir: homeDir, which: () => null };

		try {
			await fs.mkdir(sitePackages, { recursive: true });

			const fpBefore = computeLiefReadinessFingerprint(liefOptions);

			const session = createHarnessSession(homeDir);
			const elfPath = path.join(homeDir, "libuser.so");
			await fs.writeFile(elfPath, createMinimalElf64FileBuffer());
			let probeCalls = 0;
			const tool = new ElfInspectTool(session, {
				liefOptions,
				computeFingerprint: () => computeLiefReadinessFingerprint(liefOptions),
				resolveLiefDetailed: async () => {
					probeCalls += 1;
					return {
						status: "missing_module",
						available: false,
						deterministic: true,
						pythonBin: "/usr/bin/python3",
						version: null,
						modulePath: null,
						error: "No module named 'lief'",
						readinessFingerprint: fpBefore,
						checkedCandidates: ["/usr/bin/python3"],
					};
				},
			});

			const first = await tool.execute("user-site-call-1", { action: "query", path: elfPath });
			expect(isBlockedDetails(first.details)).toBe(true);
			expect(probeCalls).toBe(1);

			const cached = await tool.execute("user-site-call-2", { action: "query", path: elfPath });
			expect(isBlockedDetails(cached.details)).toBe(true);
			if (isBlockedDetails(cached.details)) expect(cached.details.blockedByGate).toBe(true);
			expect(probeCalls).toBe(1);

			// pip --user 只写入用户 site-packages：前缀缓存与解释器 stat 均不变
			await fs.mkdir(path.join(sitePackages, "lief"), { recursive: true });
			const fpAfter = computeLiefReadinessFingerprint(liefOptions);
			expect(fpAfter).not.toBe(fpBefore);

			const reprobed = await tool.execute("user-site-call-3", { action: "query", path: elfPath });
			expect(isBlockedDetails(reprobed.details)).toBe(true);
			if (isBlockedDetails(reprobed.details)) {
				expect(reprobed.details.blockedByGate).toBe(false);
				expect(reprobed.details.sourceToolCallId).toBe("user-site-call-3");
			}
			expect(probeCalls).toBe(2);
		} finally {
			await fs.rm(homeDir, { recursive: true, force: true });
		}
	});
});
