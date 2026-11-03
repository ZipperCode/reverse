import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "../../src/config/settings";
import { ReverseWorkflowStore } from "../../src/reverse-workflow";
import { beginAnalysisRun } from "../../src/reverse-workspace";
import { AlgorithmVerifyTool, type AlgorithmVerifyParams } from "../../src/tools/algorithm-verify";
import type { ToolSession } from "../../src/tools";
import { resolveApproval } from "../../src/tools/approval";

function session(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: false,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
	};
}
async function fixture(run: (tool: AlgorithmVerifyTool, dir: string, base: AlgorithmVerifyParams) => Promise<void>) {
	const dir = await fs.mkdtemp(path.join(os.tmpdir(), "algorithm-verify-"));
	try {
		const prefix = `import { readFileSync } from 'node:fs'; const input = readFileSync(0); `;
		await fs.writeFile(path.join(dir, "oracle.js"), `${prefix}process.stdout.write(input);`);
		await fs.writeFile(path.join(dir, "candidate.js"), `${prefix}process.stdout.write(Buffer.from(input));`);
		const base: AlgorithmVerifyParams = {
			oracle: { argv: [process.execPath, "oracle.js"] },
			candidate: { argv: [process.execPath, "candidate.js"] },
			vectors: [
				{ id: "development", split: "exploration", input_hex: "0001ff" },
				{ id: "unseen", split: "holdout", input_hex: "e4b8ad00f09f9880" },
			],
			context: { seed: "42", clock: "2026-01-01T00:00:00Z", session: "fixture" },
			env: { BUN_BE_BUN: "1" },
			timeout_ms: 2000,
		};
		// 固定种子语料可复现；holdout 只是测试分组，不意味着对 agent 隐藏。
		let seed = 42;
		for (let i = 0; i < 4; i++) {
			const bytes = Buffer.alloc(8);
			for (let j = 0; j < bytes.length; j++) {
				seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
				bytes[j] = seed >>> 24;
			}
			base.vectors.push({ id: `seeded-${i}`, split: "holdout", input_hex: bytes.toString("hex") });
		}
		await run(new AlgorithmVerifyTool(session(dir)), dir, base);
	} finally {
		await fs.rm(dir, { recursive: true, force: true });
	}
}

describe("algorithm_verify local executable boundary", () => {
	it("runs separate processes on binary exploration and holdout vectors with reproducible context and private report", async () => {
		await fixture(async (_tool, dir, base) => {
			const reportPath = path.join(dir, "session-report.json");
			const tool = new AlgorithmVerifyTool({
				...session(dir),
				allocateOutputArtifact: async () => ({ id: "verify-report", path: reportPath }),
			});
			const script = `import { readFileSync } from 'node:fs'; const b=readFileSync(0); process.stdout.write(b); process.stderr.write(process.env.REVERSE_VERIFY_CONTEXT); if (process.env.CANARY_SECRET || process.env.TMPDIR !== 'explicit-temp') process.exit(99);`;
			await fs.writeFile(path.join(dir, "oracle.js"), script);
			await fs.writeFile(path.join(dir, "candidate.js"), script);
			const old = process.env.CANARY_SECRET;
			process.env.CANARY_SECRET = "not-forwarded";
			try {
				const { details } = await tool.execute("same", {
					...base,
					env: { ...base.env, TMPDIR: "explicit-temp" },
					vectors: [...base.vectors, { id: "empty", split: "holdout", input_hex: "", context: { seed: "99" } }],
				});
				expect(details.all_vectors_matched).toBe(true);
				expect(details.successful_output_matches).toBe(7);
				expect(details.matching_error_cases).toBe(0);
				expect(details.splits.holdout).toEqual({ total: 6, matched: 6, mismatch: 0, incomplete: 0 });
				expect(details.cases[1]!.oracle.stdout.size_bytes).toBe(8);
				expect(details.cases[1]!.oracle.stdout.preview_hex).toBe("e4b8ad00f09f9880");
				expect(details.cases[0]!.context_sha256).not.toBe(details.cases.at(-1)!.context_sha256);
				expect(details.provenance.oracle.artifacts[0]!.path).toBe("oracle.js");
				expect(details.provenance.shared_artifact_sha256).toHaveLength(1);
				expect(details.formal_equivalence_certified).toBe(false);
				expect(details.independent_reproduction_certified).toBe(false);
				expect(details.artifact_id).toBe("verify-report");
				const report = JSON.parse(await fs.readFile(reportPath, "utf8"));
				expect(report.vectors[1].input_hex).toBe(base.vectors[1]!.input_hex);
				expect(report.context.seed).toBe("42");
				if (process.platform !== "win32") expect((await fs.stat(reportPath)).mode & 0o777).toBe(0o600);
			} finally {
				if (old === undefined) delete process.env.CANARY_SECRET;
				else process.env.CANARY_SECRET = old;
			}
		});
	});

	it("catches memorization on caller-labelled holdout rather than claiming hidden secrecy", async () => {
		await fixture(async (tool, dir, base) => {
			await fs.writeFile(
				path.join(dir, "candidate.js"),
				`import {readFileSync} from 'node:fs'; const b=readFileSync(0); process.stdout.write(b.toString('hex')==='0001ff'?b:Buffer.from('wrong'));`,
			);
			const { details } = await tool.execute("holdout", base);
			expect(details.cases[0]!.status).toBe("matched");
			expect(details.cases.slice(1).every(c => c.status === "mismatch")).toBe(true);
			expect(details.cases[1]!.first_mismatch).toMatchObject({
				stream: "stdout",
				offset: 0,
				oracle_byte: 228,
				candidate_byte: 119,
			});
		});
	});

	it("detects wrong endianness, UTF-8 byte counts and 32-bit overflow with exact mismatch locations", async () => {
		await fixture(async (tool, dir, base) => {
			const cases = [
				{ input: "01020304", oracle: "String(b.readUInt32LE())", candidate: "String(b.readUInt32BE())" },
				{ input: "e4b8ad", oracle: "String(b.length)", candidate: "String(b.toString('utf8').length)" },
				{
					input: Buffer.from("4294967295").toString("hex"),
					oracle: "String((BigInt(b.toString())+1n)&0xffffffffn)",
					candidate: "String(Number(b.toString())+1)",
				},
			];
			for (const [index, c] of cases.entries()) {
				await fs.writeFile(
					path.join(dir, "oracle.js"),
					`import {readFileSync} from 'node:fs'; const b=readFileSync(0); process.stdout.write(${c.oracle});`,
				);
				await fs.writeFile(
					path.join(dir, "candidate.js"),
					`import {readFileSync} from 'node:fs'; const b=readFileSync(0); process.stdout.write(${c.candidate});`,
				);
				const { details } = await tool.execute(`fault-${index}`, {
					...base,
					vectors: [{ id: `boundary-${index}`, split: "holdout", input_hex: c.input }],
				});
				expect(details.all_vectors_matched).toBe(false);
				expect(details.cases[0]!.status).toBe("mismatch");
				expect(details.cases[0]!.first_mismatch!.offset).toBe(0);
				expect(details.cases[0]!.oracle.stdout.sha256).not.toBe(details.cases[0]!.candidate.stdout.sha256);
			}
		});
	});

	it("compares EOF, invalid UTF-8 bytes, stderr and nonzero exit behavior without normalization", async () => {
		await fixture(async (tool, dir, base) => {
			await fs.writeFile(
				path.join(dir, "oracle.js"),
				`process.stdout.write(Buffer.from([0xff,0x00]));process.stderr.write('bad');process.exit(7);`,
			);
			await fs.writeFile(
				path.join(dir, "candidate.js"),
				`process.stdout.write(Buffer.from([0xfe,0x00]));process.stderr.write('bad');process.exit(7);`,
			);
			let result = await tool.execute("raw", { ...base, vectors: [base.vectors[0]!] });
			expect(result.details.cases[0]!.first_mismatch).toMatchObject({
				offset: 0,
				oracle_byte: 255,
				candidate_byte: 254,
			});
			await fs.writeFile(
				path.join(dir, "candidate.js"),
				`process.stdout.write(Buffer.from([0xff,0x00]));process.stderr.write('bad');process.exit(7);`,
			);
			result = await tool.execute("nonzero-equal", { ...base, vectors: [base.vectors[0]!] });
			expect(result.details.cases[0]!.status).toBe("matched");
			expect(result.details.cases[0]!.candidate.exit_code).toBe(7);
			expect(result.details.successful_output_matches).toBe(0);
			expect(result.details.matching_error_cases).toBe(1);
			expect(result.content[0]).toMatchObject({
				type: "text",
				text: expect.stringContaining("1 matching error cases"),
			});
			await fs.writeFile(
				path.join(dir, "candidate.js"),
				`process.stdout.write(Buffer.from([0xff,0x00]));process.stderr.write('bad!');process.exit(8);`,
			);
			result = await tool.execute("nonzero-diff", { ...base, vectors: [base.vectors[0]!] });
			expect(result.details.cases[0]!.exit_equal).toBe(false);
			expect(result.details.cases[0]!.first_mismatch).toEqual({
				stream: "stderr",
				offset: 3,
				oracle_byte: null,
				candidate_byte: 33,
			});
		});
	});

	it("reports timeout, stderr/stdout overflow, spawn failure and cancellation as incomplete", async () => {
		await fixture(async (tool, dir, base) => {
			const one = { ...base, vectors: [base.vectors[0]!] };
			// 本集成用例验证真实子进程 deadline/AbortSignal；fake timer 无法驱动 OS 进程终止。
			await fs.writeFile(path.join(dir, "candidate.js"), "setInterval(()=>{},1000);");
			let result = await tool.execute("timeout", { ...one, timeout_ms: 100 });
			expect(result.details.cases[0]!.candidate.status).toBe("timeout");
			expect(result.details.cases[0]!.status).toBe("incomplete");
			result = await tool.execute("overall-timeout", { ...one, total_timeout_ms: 100 });
			expect(result.details.all_vectors_matched).toBe(false);
			expect(result.details.cases[0]!.status).toBe("incomplete");
			for (const stream of ["stdout", "stderr"] as const) {
				await fs.writeFile(path.join(dir, "candidate.js"), `process.${stream}.write(Buffer.alloc(262144,65));`);
				result = await tool.execute(`overflow-${stream}`, { ...one, max_output_bytes: 16 });
				expect(result.details.cases[0]!.candidate.status).toBe("output_limit");
				expect(result.details.cases[0]!.candidate[stream].size_bytes).toBe(16);
				expect(result.details.cases[0]!.candidate[stream].hash_scope).toBe("captured_prefix");
				expect(result.details.cases[0]!.stdout_equal).toBe(null);
			}
			const badExecutable = path.join(dir, "not-executable");
			await fs.writeFile(badExecutable, "invalid executable");
			result = await tool.execute("spawn-error", { ...one, candidate: { argv: [badExecutable] } });
			expect(result.details.cases[0]!.candidate.status).toBe("error");
			await fs.writeFile(path.join(dir, "candidate.js"), "setInterval(()=>{},1000);");
			const controller = new AbortController();
			const timer = setTimeout(() => controller.abort(), 100);
			try {
				result = await tool.execute("cancel", { ...one, timeout_ms: 2000 }, controller.signal);
				expect(["cancelled", "not_run"]).toContain(result.details.cases[0]!.candidate.status);
				expect(result.details.all_vectors_matched).toBe(false);
			} finally {
				clearTimeout(timer);
			}
		});
	});

	it("binds scripts to active run inputs, confines the private report and detects script drift", async () => {
		await fixture(async (tool, dir, base) => {
			const store = new ReverseWorkflowStore({ repositoryRoot: dir });
			const workflow = await store.create({
				target: path.join(dir, "oracle.js"),
				format: "unknown",
				goal: "Finite differential recovery",
			});
			const run = await beginAnalysisRun({
				projectDir: dir,
				workflowId: workflow.id,
				stepId: workflow.steps[0]!.id,
				purpose: "Compare exact bytes",
				command: "algorithm_verify",
				inputs: ["oracle.js", "candidate.js"],
				workflowStore: store,
			});
			const bound = {
				...base,
				vectors: [base.vectors[0]!],
				workflow_id: workflow.id,
				step_id: workflow.steps[0]!.id,
				run_id: run.run_id,
			};
			await expect(
				tool.execute("escape-output", { ...bound, output_path: path.join(dir, "outside-report.json") }),
			).rejects.toThrow(/output path/i);
			const result = await tool.execute("bound", bound);
			expect(result.details.all_vectors_matched).toBe(true);
			expect(result.details.report_path).toContain(run.paths.relative.reports_dir);
			const output = path.resolve(dir, result.details.report_path!);
			expect(JSON.parse(await fs.readFile(output, "utf8")).run_id).toBe(run.run_id);
			if (process.platform !== "win32") expect((await fs.stat(output)).mode & 0o777).toBe(0o600);
			await fs.writeFile(
				path.join(dir, "candidate.js"),
				`import {readFileSync,appendFileSync} from 'node:fs'; const b=readFileSync(0); process.stdout.write(b); appendFileSync('candidate.js','\\n// changed');`,
			);
			const drift = await tool.execute("drift", { ...base, vectors: [base.vectors[0]!] });
			expect(drift.details.cases[0]!.status).toBe("matched");
			expect(drift.details.provenance.drifted_paths).toContain("candidate.js");
			expect(drift.details.all_vectors_matched).toBe(false);
		});
	});

	it("requires per-call central approval for restricted cwd, executable, artifact and file argv paths even in yolo", async () => {
		await fixture(async (tool, dir, base) => {
			const restricted = path.join(dir, "restricted");
			await fs.mkdir(restricted);
			await fs.writeFile(path.join(restricted, "script.js"), "process.exit(0)");
			await fs.symlink(restricted, path.join(dir, "restricted-link"));
			const calls = [
				{ ...base, cwd: "restricted" },
				{ ...base, candidate: { argv: ["restricted/script.js"] } },
				{ ...base, candidate: { argv: [process.execPath, "restricted/script.js"] } },
				{ ...base, candidate: { argv: [process.execPath, "restricted-link/script.js"] } },
				{ ...base, candidate: { ...base.candidate, artifact_paths: ["restricted/script.js"] } },
			];
			for (const args of calls)
				expect(
					resolveApproval(tool, args, "yolo", {}, undefined, { restrictedFolders: [restricted], cwd: dir }),
				).toMatchObject({ policy: "prompt", source: "restriction" });
			expect(
				resolveApproval(tool, base, "yolo", {}, undefined, { restrictedFolders: [restricted], cwd: dir }).policy,
			).toBe("allow");
		});
	});

	it("requires exec approval, blocks plan mode and rejects malformed vectors/shell/cwd escapes before execution", async () => {
		await fixture(async (tool, dir, base) => {
			expect(tool.approval(base)).toBe("exec");
			const planTool = new AlgorithmVerifyTool({
				...session(dir),
				getPlanModeState: () => ({ enabled: true, planFilePath: "local://plan.md" }),
			});
			await expect(planTool.execute("plan", base)).rejects.toThrow(/Plan mode/);
			await expect(
				tool.execute("odd", { ...base, vectors: [{ id: "odd", split: "exploration", input_hex: "f" }] }),
			).rejects.toThrow(/even-length/);
			await expect(tool.execute("cwd", { ...base, cwd: "../" })).rejects.toThrow(/traversal/i);
			if (process.platform !== "win32")
				await expect(
					tool.execute("shell", { ...base, candidate: { argv: ["/bin/sh", "-c", "echo bad"] } }),
				).rejects.toThrow(/shell executable/);
			await expect(
				tool.execute("outside-artifact", {
					...base,
					candidate: { argv: [process.execPath, "candidate.js"], artifact_paths: ["../elsewhere"] },
				}),
			).rejects.toThrow(/traversal/i);
		});
	});
});
