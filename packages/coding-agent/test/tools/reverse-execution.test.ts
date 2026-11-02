import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "@reverse/coding-agent/config/settings";
import { ReverseWorkflowStore } from "@reverse/coding-agent/reverse-workflow";
import {
	hashFile,
	loadAnalysisExecution,
	resolveAnalysisOutputPath,
	type AnalysisRunRecord,
} from "@reverse/coding-agent/reverse-workspace";
import { ReverseWorkflowTool, ReverseWorkspaceTool, type ToolSession } from "@reverse/coding-agent/tools";
import { removeWithRetries } from "@reverse/utils";

function createTestSession(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
	};
}

async function createTargetFixture(dir: string, name = "sample.elf"): Promise<string> {
	const filePath = path.join(dir, name);
	const buf = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, 0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0]);
	await fs.writeFile(filePath, buf);
	return filePath;
}

describe("Reverse Analysis Execution Binding & Output Confinement (Step 1)", () => {
	it("loads a running execution, validates declared inputs, and allows readonly consumption of run-local intermediate files without mutating run.json", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-exec-valid-"));

		try {
			const targetFile = await createTargetFixture(tempDir, "protocol_client.elf");
			const declaredCapture = path.join(tempDir, "traffic.har");
			await fs.writeFile(declaredCapture, '{"log":{"version":"1.2","entries":[]}}\n', "utf8");

			const helperScript = path.join(tempDir, "helper.py");
			await fs.writeFile(helperScript, "print('helper v1')\n", "utf8");

			const session = createTestSession(tempDir);
			const workflowTool = new ReverseWorkflowTool(session);
			const workspaceTool = new ReverseWorkspaceTool(session);

			const createRes = await workflowTool.execute("wf-create", {
				action: "create",
				target: targetFile,
				format: "ELF",
				goal: "Validate active run execution binding and intermediate consumption",
			});
			const workflowId = createRes.details.workflow!.id;

			const beginRes = await workspaceTool.execute("ws-begin", {
				action: "begin",
				workflow_id: workflowId,
				step_id: "elf_step_1",
				purpose: "Import capture and parse extracted payload",
				command: "reverse protocol pipeline",
				inputs: [declaredCapture],
				script_paths: [helperScript],
			});
			const runId = beginRes.details.run_id!;
			const paths = beginRes.details.paths!;

			// 在同次 run 的受管子目录内生成中间产物与解析脚本
			const intermediatePayload = path.join(paths.dumps_dir, "request_0_body.bin");
			const payloadBytes = Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0x00, 0x04, 0x11, 0x22]);
			await fs.writeFile(intermediatePayload, payloadBytes);

			const generatedParser = path.join(paths.scripts_dir, "packet_parser.py");
			await fs.writeFile(generatedParser, "# auto-generated parser\n", "utf8");

			const runJsonBefore = await fs.readFile(paths.run_json, "utf8");
			const wfStore = new ReverseWorkflowStore({ repositoryRoot: tempDir });
			const wfBefore = await wfStore.get(workflowId);

			const targetHash = (await hashFile(targetFile))!;
			const captureHash = (await hashFile(declaredCapture))!;
			const intermediateHash = (await hashFile(intermediatePayload))!;
			const parserHash = (await hashFile(generatedParser))!;

			const candidateReportOut = path.join(paths.reports_dir, "nested", "parse_summary.json");
			const execution = await loadAnalysisExecution({
				projectDir: tempDir,
				workflowId,
				stepId: "elf_step_1",
				runId,
				inputPaths: [targetFile, declaredCapture, intermediatePayload, generatedParser],
				outputPaths: [candidateReportOut],
			});

			expect(execution.run.id).toBe(runId);
			expect(execution.run.workflow_id).toBe(workflowId);
			expect(execution.run.step_id).toBe("elf_step_1");
			expect(execution.run.status).toBe("running");
			expect(execution.paths.run_dir).toBe(paths.run_dir);

			// 返回的 inputRefs 同时包含 begin 声明输入与同次 run 中间产物的哈希绑定
			expect(execution.inputRefs).toEqual([
				{
					path: "protocol_client.elf",
					sha256: targetHash.sha256,
					size_bytes: targetHash.size,
				},
				{
					path: "traffic.har",
					sha256: captureHash.sha256,
					size_bytes: captureHash.size,
				},
				{
					path: `${paths.relative.dumps_dir}/request_0_body.bin`,
					sha256: intermediateHash.sha256,
					size_bytes: intermediateHash.size,
				},
				{
					path: `${paths.relative.scripts_dir}/packet_parser.py`,
					sha256: parserHash.sha256,
					size_bytes: parserHash.size,
				},
			]);

			expect(execution.outputPaths).toHaveLength(1);
			expect(execution.outputPaths[0]).toMatchObject({
				resolvedPath: candidateReportOut,
				relativePath: `${paths.relative.reports_dir}/nested/parse_summary.json`,
				runRelativePath: "reports/nested/parse_summary.json",
				subdir: "reports",
			});

			// 严禁把同次 run 中间文件追加进 run.inputs 或改动磁盘上的 run.json / workflow 记录
			expect(execution.run.inputs.map(i => i.path)).toEqual(["protocol_client.elf", "traffic.har"]);
			const runJsonAfter = await fs.readFile(paths.run_json, "utf8");
			expect(runJsonAfter).toBe(runJsonBefore);
			const wfAfter = await wfStore.get(workflowId);
			expect(wfAfter).toEqual(wfBefore);

			// 自定义非严格标识符格式的 step_id（含点号/冒号等）同样正常支持，仅需非空并匹配 workflow 步骤
			const customWf = await wfStore.create({
				target: targetFile,
				format: "ELF",
				goal: "Custom step label support",
				steps: [
					{
						...wfBefore!.steps[0],
						id: "phase.1:custom/parse",
						title: "Custom step",
						status: "pending",
					},
				],
			});
			const customBegin = await workspaceTool.execute("ws-begin-custom-step", {
				action: "begin",
				workflow_id: customWf.id,
				step_id: "phase.1:custom/parse",
				purpose: "Run under custom step label",
				command: "echo custom",
			});
			const customExec = await loadAnalysisExecution({
				projectDir: tempDir,
				workflowId: customWf.id,
				stepId: "phase.1:custom/parse",
				runId: customBegin.details.run_id!,
				inputPaths: [targetFile],
			});
			expect(customExec.run.step_id).toBe("phase.1:custom/parse");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects workflow, step, run, ownership, and non-running status errors without mutating state", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-exec-errors-"));

		try {
			const targetFile = await createTargetFixture(tempDir, "target.elf");
			const session = createTestSession(tempDir);
			const workflowTool = new ReverseWorkflowTool(session);
			const workspaceTool = new ReverseWorkspaceTool(session);
			const wfStore = new ReverseWorkflowStore({ repositoryRoot: tempDir });

			const createRes = await workflowTool.execute("wf-create", {
				action: "create",
				target: targetFile,
				format: "ELF",
				goal: "Test workflow/step/run/status validation",
			});
			const workflowId = createRes.details.workflow!.id;

			// 1. 非法标识符与空 step_id
			await expect(
				loadAnalysisExecution({
					projectDir: tempDir,
					workflowId: "../bad_wf",
					stepId: "elf_step_1",
					runId: "run_1",
					inputPaths: [],
				}),
			).rejects.toThrow(/Invalid workflow_id/);

			await expect(
				loadAnalysisExecution({
					projectDir: tempDir,
					workflowId,
					stepId: "   ",
					runId: "run_1",
					inputPaths: [],
				}),
			).rejects.toThrow(/step_id/);

			await expect(
				loadAnalysisExecution({
					projectDir: tempDir,
					workflowId,
					stepId: "elf_step_1",
					runId: "../bad_run",
					inputPaths: [],
				}),
			).rejects.toThrow(/Invalid run_id/);

			// 2. 不存在的 workflowId / stepId / runId（拒绝时不得在磁盘创建目录或锁文件）
			await expect(
				loadAnalysisExecution({
					projectDir: tempDir,
					workflowId: "wf_missing_999",
					stepId: "elf_step_1",
					runId: "run_missing",
					inputPaths: [],
				}),
			).rejects.toThrow(/Workflow 'wf_missing_999' not found/);

			await expect(
				loadAnalysisExecution({
					projectDir: tempDir,
					workflowId,
					stepId: "step_does_not_exist",
					runId: "run_missing",
					inputPaths: [],
				}),
			).rejects.toThrow(/Step 'step_does_not_exist' not found/);

			await expect(
				loadAnalysisExecution({
					projectDir: tempDir,
					workflowId,
					stepId: "elf_step_1",
					runId: "run_does_not_exist",
					inputPaths: [],
				}),
			).rejects.toThrow(/Analysis run 'run_does_not_exist' not found.*begin/);

			const missingRunDir = path.join(tempDir, ".reverse", "analysis", workflowId, "runs", "run_does_not_exist");
			await expect(fs.stat(missingRunDir)).rejects.toThrow();

			// 3. Step 归属不匹配
			const beginRes = await workspaceTool.execute("ws-begin", {
				action: "begin",
				workflow_id: workflowId,
				step_id: "elf_step_1",
				purpose: "Step 1 active run",
				command: "echo step1",
			});
			const runId = beginRes.details.run_id!;
			const paths = beginRes.details.paths!;
			const runJsonBeforeMismatch = await fs.readFile(paths.run_json, "utf8");

			await expect(
				loadAnalysisExecution({
					projectDir: tempDir,
					workflowId,
					stepId: "elf_step_2",
					runId,
					inputPaths: [],
				}),
			).rejects.toThrow(/Step ID mismatch/);
			expect(await fs.readFile(paths.run_json, "utf8")).toBe(runJsonBeforeMismatch);

			// 4. 已结束的 succeeded / failed 实验不可继续用于新执行
			const outFile = path.join(paths.dumps_dir, "done.txt");
			await fs.writeFile(outFile, "done\n", "utf8");
			await workspaceTool.execute("ws-record-ok", {
				action: "record",
				workflow_id: workflowId,
				run_id: runId,
				exit_code: 0,
				summary: "Completed run",
				output_paths: [outFile],
			});
			const succeededRunJson = await fs.readFile(paths.run_json, "utf8");

			await expect(
				loadAnalysisExecution({
					projectDir: tempDir,
					workflowId,
					stepId: "elf_step_1",
					runId,
					inputPaths: [targetFile],
				}),
			).rejects.toThrow(/status 'succeeded'.*begin/);
			expect(await fs.readFile(paths.run_json, "utf8")).toBe(succeededRunJson);

			const failBegin = await workspaceTool.execute("ws-begin-fail", {
				action: "begin",
				workflow_id: workflowId,
				step_id: "elf_step_1",
				purpose: "Failed run",
				command: "exit 1",
			});
			const failRunId = failBegin.details.run_id!;
			await workspaceTool.execute("ws-record-fail", {
				action: "record",
				workflow_id: workflowId,
				run_id: failRunId,
				exit_code: 1,
				summary: "Failed execution",
			});
			const failedRunJson = await fs.readFile(failBegin.details.paths!.run_json, "utf8");

			await expect(
				loadAnalysisExecution({
					projectDir: tempDir,
					workflowId,
					stepId: "elf_step_1",
					runId: failRunId,
					inputPaths: [],
				}),
			).rejects.toThrow(/status 'failed'.*begin/);
			expect(await fs.readFile(failBegin.details.paths!.run_json, "utf8")).toBe(failedRunJson);

			// 5. 损坏或 workflow_id 被篡改的 run.json
			const corruptBegin = await workspaceTool.execute("ws-begin-corrupt", {
				action: "begin",
				workflow_id: workflowId,
				step_id: "elf_step_1",
				purpose: "Corrupt run check",
				command: "echo corrupt",
			});
			const corruptRunId = corruptBegin.details.run_id!;
			const corruptRunJsonPath = corruptBegin.details.paths!.run_json;
			const parsed = JSON.parse(await fs.readFile(corruptRunJsonPath, "utf8")) as AnalysisRunRecord;
			await fs.writeFile(corruptRunJsonPath, JSON.stringify({ ...parsed, workflow_id: "wf_other_owner" }), "utf8");

			await expect(
				loadAnalysisExecution({
					projectDir: tempDir,
					workflowId,
					stepId: "elf_step_1",
					runId: corruptRunId,
					inputPaths: [],
					workflowStore: wfStore,
				}),
			).rejects.toThrow(/Workflow ID mismatch|Corrupt or mismatched/);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects undeclared external inputs and cross-run artifacts with clear instruction to start a new run via begin", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-exec-undeclared-"));

		try {
			const targetFile = await createTargetFixture(tempDir, "app.elf");
			const declaredInput = path.join(tempDir, "declared.ksy");
			const undeclaredExternal = path.join(tempDir, "undeclared_extra.ksy");
			await fs.writeFile(declaredInput, "meta:\n  id: declared\n", "utf8");
			await fs.writeFile(undeclaredExternal, "meta:\n  id: undeclared\n", "utf8");

			const session = createTestSession(tempDir);
			const workflowTool = new ReverseWorkflowTool(session);
			const workspaceTool = new ReverseWorkspaceTool(session);

			const createRes = await workflowTool.execute("wf-create", {
				action: "create",
				target: targetFile,
				format: "ELF",
				goal: "Reject undeclared external inputs",
			});
			const workflowId = createRes.details.workflow!.id;

			const beginA = await workspaceTool.execute("ws-begin-a", {
				action: "begin",
				workflow_id: workflowId,
				step_id: "elf_step_1",
				purpose: "Run A with declared.ksy only",
				command: "ksc declared.ksy",
				inputs: [declaredInput],
			});
			const runIdA = beginA.details.run_id!;
			const pathsA = beginA.details.paths!;

			const beginB = await workspaceTool.execute("ws-begin-b", {
				action: "begin",
				workflow_id: workflowId,
				step_id: "elf_step_1",
				purpose: "Run B with its own intermediate dump",
				command: "dump b",
			});
			const otherRunIntermediate = path.join(beginB.details.paths!.dumps_dir, "other_run_payload.bin");
			await fs.writeFile(otherRunIntermediate, Buffer.from([1, 2, 3, 4]));

			const runJsonABefore = await fs.readFile(pathsA.run_json, "utf8");

			// 未在 begin 声明的项目内外部文件必须拒绝并提示重新 begin
			await expect(
				loadAnalysisExecution({
					projectDir: tempDir,
					workflowId,
					stepId: "elf_step_1",
					runId: runIdA,
					inputPaths: [declaredInput, undeclaredExternal],
				}),
			).rejects.toThrow(/not declared.*begin/i);

			// 另一个 run 目录下的产物若未在当前 run 的 begin inputs 中声明，也属于外部未声明输入，必须拒绝
			await expect(
				loadAnalysisExecution({
					projectDir: tempDir,
					workflowId,
					stepId: "elf_step_1",
					runId: runIdA,
					inputPaths: [otherRunIntermediate],
				}),
			).rejects.toThrow(/not declared.*begin/i);

			expect(await fs.readFile(pathsA.run_json, "utf8")).toBe(runJsonABefore);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("detects target sample drift, declared input drift, and existing script drift before tool execution", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-exec-drift-"));

		try {
			const targetFile = await createTargetFixture(tempDir, "firmware.elf");
			const extraInput = path.join(tempDir, "capture.har");
			const existingScript = path.join(tempDir, "replay_helper.py");
			await fs.writeFile(extraInput, '{"entries":[1]}\n', "utf8");
			await fs.writeFile(existingScript, "print('v1')\n", "utf8");

			const session = createTestSession(tempDir);
			const workflowTool = new ReverseWorkflowTool(session);
			const workspaceTool = new ReverseWorkspaceTool(session);

			const createRes = await workflowTool.execute("wf-create", {
				action: "create",
				target: targetFile,
				format: "ELF",
				goal: "Detect sample/input/script drift",
			});
			const workflowId = createRes.details.workflow!.id;

			const beginRes = await workspaceTool.execute("ws-begin", {
				action: "begin",
				workflow_id: workflowId,
				step_id: "elf_step_1",
				purpose: "Check drift detection",
				command: "python3 replay_helper.py",
				inputs: [extraInput],
				script_paths: [existingScript],
			});
			const runId = beginRes.details.run_id!;
			const paths = beginRes.details.paths!;
			const originalRunJson = await fs.readFile(paths.run_json, "utf8");

			// 1. 修改已声明的 extraInput（即使本次调用未将其列入 inputPaths，也必须在复核全部 begin inputs 时拦截）
			await fs.writeFile(extraInput, '{"entries":[1,2]}\n', "utf8");
			await expect(
				loadAnalysisExecution({
					projectDir: tempDir,
					workflowId,
					stepId: "elf_step_1",
					runId,
					inputPaths: [targetFile],
				}),
			).rejects.toThrow(/Recorded input 'capture\.har' changed since run began/);
			expect(await fs.readFile(paths.run_json, "utf8")).toBe(originalRunJson);

			// 恢复 extraInput，验证恢复后可正常通过
			await fs.writeFile(extraInput, '{"entries":[1]}\n', "utf8");
			await expect(
				loadAnalysisExecution({
					projectDir: tempDir,
					workflowId,
					stepId: "elf_step_1",
					runId,
					inputPaths: [targetFile],
				}),
			).resolves.toBeDefined();

			// 2. 修改 begin 阶段已登记的既有脚本 existingScript -> 拦截
			await fs.writeFile(existingScript, "print('mutated v2')\n", "utf8");
			await expect(
				loadAnalysisExecution({
					projectDir: tempDir,
					workflowId,
					stepId: "elf_step_1",
					runId,
					inputPaths: [targetFile],
				}),
			).rejects.toThrow(/Recorded script 'replay_helper\.py' changed since run began/);
			expect(await fs.readFile(paths.run_json, "utf8")).toBe(originalRunJson);

			// 恢复 existingScript
			await fs.writeFile(existingScript, "print('v1')\n", "utf8");

			// 3. 修改原始目标样本 targetFile -> 拦截
			await fs.writeFile(targetFile, Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0xff, 0xff]));
			await expect(
				loadAnalysisExecution({
					projectDir: tempDir,
					workflowId,
					stepId: "elf_step_1",
					runId,
					inputPaths: [],
				}),
			).rejects.toThrow(/Target file .* changed since run began/);
			expect(await fs.readFile(paths.run_json, "utf8")).toBe(originalRunJson);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects path traversal, symlinks, directories as files, and metadata overwrites while preserving state", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-exec-sec-"));
		const outsideDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-exec-outside-"));

		try {
			const targetFile = await createTargetFixture(tempDir, "binary.elf");
			const undeclaredFile = path.join(tempDir, "secret_project_file.bin");
			await fs.writeFile(undeclaredFile, Buffer.from([0x10, 0x20, 0x30]));

			const outsideFile = path.join(outsideDir, "outside.bin");
			await fs.writeFile(outsideFile, Buffer.from([0x99, 0x88]));

			const session = createTestSession(tempDir);
			const workflowTool = new ReverseWorkflowTool(session);
			const workspaceTool = new ReverseWorkspaceTool(session);

			const createRes = await workflowTool.execute("wf-create", {
				action: "create",
				target: targetFile,
				format: "ELF",
				goal: "Verify path traversal, symlink, directory, and metadata protections",
			});
			const workflowId = createRes.details.workflow!.id;

			const beginRes = await workspaceTool.execute("ws-begin", {
				action: "begin",
				workflow_id: workflowId,
				step_id: "elf_step_1",
				purpose: "Security boundary verification",
				command: "echo sec",
			});
			const runId = beginRes.details.run_id!;
			const paths = beginRes.details.paths!;
			const runJsonBefore = await fs.readFile(paths.run_json, "utf8");

			// 1. inputPaths 含 .. 路径穿越 -> 拒绝
			await expect(
				loadAnalysisExecution({
					projectDir: tempDir,
					workflowId,
					stepId: "elf_step_1",
					runId,
					inputPaths: ["../outside.bin"],
				}),
			).rejects.toThrow(/traversal/i);

			// 2. inputPaths 指向目录 -> 拒绝
			await expect(
				loadAnalysisExecution({
					projectDir: tempDir,
					workflowId,
					stepId: "elf_step_1",
					runId,
					inputPaths: [paths.dumps_dir],
				}),
			).rejects.toThrow(/not a regular file/i);

			// 3. inputPaths 尝试将 run.json 元数据文件作为同次 run 中间输入消费 -> 拒绝
			await expect(
				loadAnalysisExecution({
					projectDir: tempDir,
					workflowId,
					stepId: "elf_step_1",
					runId,
					inputPaths: [paths.run_json],
				}),
			).rejects.toThrow(/Cannot overwrite internal run metadata|metadata/i);

			// 4. 在当前 run 的 dumps 目录内创建指向未声明项目文件或外部文件的符号链接 -> 拒绝通过中间产物通道偷渡
			const smuggledProjectSymlink = path.join(paths.dumps_dir, "smuggled_project.bin");
			const smuggledOutsideSymlink = path.join(paths.dumps_dir, "smuggled_outside.bin");
			await fs.symlink(undeclaredFile, smuggledProjectSymlink);
			await fs.symlink(outsideFile, smuggledOutsideSymlink);

			await expect(
				loadAnalysisExecution({
					projectDir: tempDir,
					workflowId,
					stepId: "elf_step_1",
					runId,
					inputPaths: [smuggledProjectSymlink],
				}),
			).rejects.toThrow(/Symlink escape/i);

			await expect(
				loadAnalysisExecution({
					projectDir: tempDir,
					workflowId,
					stepId: "elf_step_1",
					runId,
					inputPaths: [smuggledOutsideSymlink],
				}),
			).rejects.toThrow(/Symlink escape/i);

			// 5. resolveAnalysisOutputPath 输出边界校验：
			// 5a. 禁止输出到项目根或 run 目录之外
			await expect(
				resolveAnalysisOutputPath({
					projectDir: tempDir,
					paths,
					outputPath: path.join(tempDir, "scattered_report.json"),
				}),
			).rejects.toThrow(/escapes allowed directory/i);

			await expect(
				resolveAnalysisOutputPath({
					projectDir: tempDir,
					paths,
					outputPath: "../escaped.json",
				}),
			).rejects.toThrow(/traversal/i);

			// 5b. 禁止覆盖 run.json 或 run.lock，或直接写在 run 根目录（未进入受管子目录）
			await expect(
				resolveAnalysisOutputPath({
					projectDir: tempDir,
					paths,
					outputPath: paths.run_json,
				}),
			).rejects.toThrow(/Cannot overwrite internal run metadata/i);

			await expect(
				resolveAnalysisOutputPath({
					projectDir: tempDir,
					paths,
					outputPath: path.join(paths.run_dir, "run.lock"),
				}),
			).rejects.toThrow(/Cannot overwrite internal run metadata/i);

			await expect(
				resolveAnalysisOutputPath({
					projectDir: tempDir,
					paths,
					outputPath: path.join(paths.run_dir, "root_file.txt"),
				}),
			).rejects.toThrow(/confined within run subdirectories/i);

			// 5c. 禁止将目录本身（run_dir、dumps_dir 或已存在子目录）作为输出文件路径
			await expect(
				resolveAnalysisOutputPath({
					projectDir: tempDir,
					paths,
					outputPath: paths.dumps_dir,
				}),
			).rejects.toThrow(/not a regular file/i);

			const existingNestedDir = path.join(paths.reports_dir, "existing_dir");
			await fs.mkdir(existingNestedDir, { recursive: true });
			await expect(
				resolveAnalysisOutputPath({
					projectDir: tempDir,
					paths,
					outputPath: existingNestedDir,
				}),
			).rejects.toThrow(/not a regular file/i);

			// 5d. 禁止通过符号链接（含指向 ../run.json 的 run 内符号链接或符号链接父目录）写入输出
			const symlinkToRunJson = path.join(paths.dumps_dir, "alias_run_json.json");
			await fs.symlink(paths.run_json, symlinkToRunJson);
			await expect(
				resolveAnalysisOutputPath({
					projectDir: tempDir,
					paths,
					outputPath: symlinkToRunJson,
				}),
			).rejects.toThrow(/internal run metadata/i);

			const symlinkParentDir = path.join(paths.reports_dir, "linked_dir");
			await fs.symlink(outsideDir, symlinkParentDir);
			await expect(
				resolveAnalysisOutputPath({
					projectDir: tempDir,
					paths,
					outputPath: path.join(symlinkParentDir, "out.json"),
				}),
			).rejects.toThrow(/Symlink escape/i);

			// 验证所有拒绝均未改动 run.json
			expect(await fs.readFile(paths.run_json, "utf8")).toBe(runJsonBefore);
		} finally {
			await removeWithRetries(outsideDir);
			await removeWithRetries(tempDir);
		}
	});
});
