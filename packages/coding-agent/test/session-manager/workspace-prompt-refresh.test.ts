import { describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as path from "node:path";
import { createMockModel, registerMockApi } from "@reverse/ai/providers/mock";
import { ModelRegistry } from "@reverse/coding-agent/config/model-registry";
import { Settings } from "@reverse/coding-agent/config/settings";
import { createAgentSession } from "@reverse/coding-agent/sdk";
import { AuthStorage } from "@reverse/coding-agent/session/auth-storage";
import { SessionManager } from "@reverse/coding-agent/session/session-manager";
import { TempDir } from "@reverse/utils";
import { ReverseWorkflowTool, ReverseWorkspaceTool, type ToolSession } from "@reverse/coding-agent/tools";
import { ReverseWorkflowStore } from "@reverse/coding-agent/reverse-workflow";

import { cfgWorkspaceAdditionalDirectories } from "@reverse/coding-agent/session/context-settings";

registerMockApi();

/**
 * Contract: when `/add-dir` (or `addWorkspaceDirectory` + `refreshBaseSystemPrompt`)
 * runs mid-session, the rebuilt system prompt MUST list the newly-added directory
 * in its <workspace-roots> block. The sessionManager state updates immediately
 * (so `/dirs` reflects the add), but the system prompt is only re-read on the next
 * `refreshBaseSystemPrompt`; this test guards that refresh path end-to-end.
 */
describe("workspace directories in the system prompt", () => {
	it("adds a directory to the <workspace-roots> block after addWorkspaceDirectory + refreshBaseSystemPrompt", async () => {
		const dir = TempDir.createSync("@ws-prompt-add-");
		const auth = await AuthStorage.create(path.join(dir.path(), "auth.db"));
		try {
			auth.keys.setRuntime("mock", "test-key");
			const extraDir = path.join(dir.path(), "extra-root");
			fs.mkdirSync(extraDir, { recursive: true });
			const laterDir = path.join(dir.path(), "later-root");
			fs.mkdirSync(laterDir, { recursive: true });

			const mockModel = createMockModel({ id: "text", handler: () => ({ content: ["ok"] }) });
			const settings = Settings.isolated({
				"compaction.enabled": false,
				"todo.enabled": false,
				"retry.enabled": false,
			});
			const sessionManager = SessionManager.inMemory(dir.path());
			const { session } = await createAgentSession({
				cwd: dir.path(),
				agentDir: dir.path(),
				additionalDirectories: [extraDir],
				authStorage: auth,
				modelRegistry: new ModelRegistry(auth, path.join(dir.path(), "models.yml")),
				model: mockModel,
				settings,
				sessionManager,
				disableExtensionDiscovery: true,
				enableMCP: false,
				enableLsp: false,
				skills: [],
				rules: [],
				contextFiles: [],
			});
			try {
				// Sanity: the seed dir is present in the sessionManager state.
				expect(sessionManager.getAdditionalDirectories()).toEqual([extraDir]);

				// Add a second directory live (as /add-dir does) and refresh the prompt.
				await sessionManager.addWorkspaceDirectory(laterDir);
				await session.refreshBaseSystemPrompt();

				// sessionManager state now has both.
				expect(sessionManager.getAdditionalDirectories()).toEqual([extraDir, laterDir]);

				// Send a prompt so we can inspect the system prompt the provider received.
				await session.prompt("noop");

				const calls = mockModel.calls ?? [];
				const lastCall = calls.at(-1);
				const systemPrompt = (lastCall?.context?.systemPrompt as string[] | undefined)?.join("\n") ?? "";

				// Both directories must appear in the <workspace-roots> block.
				expect(systemPrompt).toContain("<workspace-roots>");
				expect(systemPrompt).toContain(extraDir);
				expect(systemPrompt).toContain(laterDir);
			} finally {
				await session.dispose();
			}
		} finally {
			auth.close();
			dir.removeSync();
		}
	});

	it("follows live workspace.additionalDirectories edits without touching other roots", async () => {
		const dir = TempDir.createSync("@ws-setting-live-");
		const auth = await AuthStorage.create(path.join(dir.path(), "auth.db"));
		try {
			auth.keys.setRuntime("mock", "test-key");
			const cliDir = path.join(dir.path(), "cli-root");
			const settingDir = path.join(dir.path(), "setting-root");
			fs.mkdirSync(cliDir, { recursive: true });
			fs.mkdirSync(settingDir, { recursive: true });

			const mockModel = createMockModel({ id: "text", handler: () => ({ content: ["ok"] }) });
			const settings = Settings.isolated({
				"compaction.enabled": false,
				"todo.enabled": false,
				"retry.enabled": false,
			});
			const sessionManager = SessionManager.inMemory(dir.path());
			const { session } = await createAgentSession({
				cwd: dir.path(),
				agentDir: dir.path(),
				additionalDirectories: [cliDir],
				authStorage: auth,
				modelRegistry: new ModelRegistry(auth, path.join(dir.path(), "models.yml")),
				model: mockModel,
				settings,
				sessionManager,
				disableExtensionDiscovery: true,
				enableMCP: false,
				enableLsp: false,
				skills: [],
				rules: [],
				contextFiles: [],
			});
			const lastSystemPrompt = async (): Promise<string> => {
				await session.prompt("noop");
				return (mockModel.calls?.at(-1)?.context?.systemPrompt as string[] | undefined)?.join("\n") ?? "";
			};
			// Let the coalesced watch run, then drain the prompt rebuild it queued.
			const settle = async (): Promise<void> => {
				await Bun.sleep(0);
				await session.runToolRegistryMutation(async () => {});
			};
			try {
				cfgWorkspaceAdditionalDirectories.set(settings, [settingDir]);
				await settle();
				expect(sessionManager.getAdditionalDirectories()).toEqual([cliDir, settingDir]);
				expect(await lastSystemPrompt()).toContain(settingDir);

				cfgWorkspaceAdditionalDirectories.set(settings, []);
				await settle();
				expect(sessionManager.getAdditionalDirectories()).toEqual([cliDir]);
				const systemPrompt = await lastSystemPrompt();
				expect(systemPrompt).not.toContain(settingDir);
				expect(systemPrompt).toContain(cliDir);
			} finally {
				await session.dispose();
			}
		} finally {
			auth.close();
			dir.removeSync();
		}
	});

	it("loads historical experiments into new sessions and refreshes only dynamic project context", async () => {
		const dir = TempDir.createSync("@investigation-prompt-");
		const auth = await AuthStorage.create(path.join(dir.path(), "auth.db"));
		const model = createMockModel({ id: "text", handler: () => ({ content: ["ok"] }) });
		const settings = Settings.isolated({
			"compaction.enabled": false,
			"todo.enabled": false,
			"retry.enabled": false,
			"tools.xdev": false,
		});
		const openSession = async () =>
			(
				await createAgentSession({
					cwd: dir.path(),
					agentDir: dir.path(),
					authStorage: auth,
					modelRegistry: new ModelRegistry(auth, path.join(dir.path(), "models.yml")),
					model,
					settings,
					sessionManager: SessionManager.inMemory(dir.path()),
					disableExtensionDiscovery: true,
					enableMCP: false,
					enableLsp: false,
					skills: [],
					rules: [],
					contextFiles: [],
				})
			).session;
		try {
			auth.keys.setRuntime("mock", "test-key");
			const initial = await openSession();
			let initialPrompt: string[];
			try {
				await initial.prompt("noop");
				initialPrompt = model.calls?.at(-1)?.context?.systemPrompt as string[];
				expect(initialPrompt.join("\n")).not.toContain("<investigation-brief>");
				expect(fs.existsSync(path.join(dir.path(), ".reverse"))).toBe(false);
			} finally {
				await initial.dispose();
			}

			const target = path.join(dir.path(), "sample.js");
			fs.writeFileSync(target, "function observedCall() { return 1; }\n");
			const toolSession: ToolSession = {
				cwd: dir.path(),
				hasUI: true,
				settings,
				getSessionFile: () => null,
				getSessionSpawns: () => "*",
			};
			const created = await new ReverseWorkflowTool(toolSession).execute("create", {
				action: "create",
				target,
				format: "JS",
				goal: "Inspect historical caller",
			});
			const workflow = created.details.workflow!;
			const workspace = new ReverseWorkspaceTool(toolSession);
			const begun = await workspace.execute("begin", {
				action: "begin",
				workflow_id: workflow.id,
				step_id: workflow.steps[0].id,
				purpose: "Compare prior caller observation",
				command: "bun caller.js",
			});
			await workspace.execute("record", {
				action: "record",
				workflow_id: workflow.id,
				run_id: begun.details.run_id!,
				exit_code: 1,
				summary: "Missing triggering input; next inspect event parameters",
			});

			const resumed = await openSession();
			try {
				await resumed.prompt("noop");
				const historical = model.calls?.at(-1)?.context?.systemPrompt as string[];
				expect(historical[0]).toBe(initialPrompt![0]);
				expect(historical.join("\n")).toContain("<investigation-brief>");
				expect(historical.join("\n")).toContain("Compare prior caller observation");
				expect(historical.join("\n")).toContain("Missing triggering input");
				expect(historical.join("\n")).toContain(workflow.target_sha256!);

				fs.writeFileSync(begun.details.paths!.run_json, "{broken json");
				await resumed.refreshBaseSystemPrompt();
				await resumed.prompt("noop");
				const refreshed = model.calls?.at(-1)?.context?.systemPrompt as string[];
				expect(refreshed[0]).toBe(initialPrompt![0]);
				expect(refreshed.join("\n")).not.toContain("Missing triggering input");
				expect(refreshed.join("\n")).toContain("<investigation-brief>");
			} finally {
				await resumed.dispose();
			}
		} finally {
			fs.rmSync(new ReverseWorkflowStore({ repositoryRoot: dir.path() }).projectDirectory, {
				recursive: true,
				force: true,
			});
			auth.close();
			dir.removeSync();
		}
	});
});
