import { afterAll, afterEach, beforeAll, describe, expect, it } from "bun:test";
import * as path from "node:path";
import type { Model } from "@rva/ai";
import { getBundledModel } from "@rva/catalog/models";
import { ModelRegistry } from "@rva/coding-agent/config/model-registry";
import { Settings } from "@rva/coding-agent/config/settings";
import { getMemoryRoot } from "@rva/coding-agent/memories";
import { AgentRegistry } from "@rva/coding-agent/registry/agent-registry";
import { createAgentSession } from "@rva/coding-agent/sdk";
import type { AgentSession } from "@rva/coding-agent/session/agent-session";
import type { AuthStorage } from "@rva/coding-agent/session/auth-storage";
import { SessionManager } from "@rva/coding-agent/session/session-manager";
import { TempDir } from "@rva/utils";
import { createInMemoryAuthStorage } from "../helpers/agent-session-setup";

// Embedded hosts share one Settings (pinned to a host directory) across sessions
// for several projects; memory injection must follow the session's project.
describe("local memory injection scope", () => {
	let authStorage: AuthStorage;
	let modelRegistry: ModelRegistry;
	let model: Model;
	let tempDir: TempDir;
	let session: AgentSession | undefined;

	beforeAll(() => {
		authStorage = createInMemoryAuthStorage();
		authStorage.keys.setRuntime("anthropic", "test-key");
		modelRegistry = new ModelRegistry(authStorage);
		const bundled = getBundledModel("anthropic", "claude-sonnet-4-5");
		if (!bundled) throw new Error("Expected built-in anthropic model to exist");
		model = bundled;
	});

	afterAll(() => {
		authStorage.close();
	});

	afterEach(async () => {
		await session?.dispose();
		session = undefined;
		await tempDir.remove();
	});

	it("injects the session project's memory when Settings is scoped to another directory", async () => {
		tempDir = TempDir.createSync("@pi-memory-session-scope-");
		const agentDir = tempDir.join("agent");
		const hostCwd = tempDir.join("host");
		const projectCwd = tempDir.join("project");
		await Bun.write(path.join(getMemoryRoot(agentDir, projectCwd), "memory_summary.md"), "PROJECT_SCOPE_SUMMARY\n");
		await Bun.write(path.join(getMemoryRoot(agentDir, hostCwd), "learned.md"), "- HOST_SCOPE_LESSON\n");

		const settings = Settings.isolated({ "async.enabled": false, "memory.backend": "local" });
		await settings.reloadForCwd(hostCwd);
		const result = await createAgentSession({
			cwd: projectCwd,
			agentDir,
			sessionManager: SessionManager.inMemory(projectCwd),
			agentRegistry: new AgentRegistry(),
			authStorage,
			modelRegistry,
			settings,
			model,
			disableExtensionDiscovery: true,
			skills: [],
			contextFiles: [],
			workspaceTree: { rootPath: projectCwd, rendered: "", truncated: false, totalLines: 0, agentsMdFiles: [] },
			promptTemplates: [],
			slashCommands: [],
			enableMCP: false,
			enableLsp: false,
		});
		session = result.session;

		const systemPrompt = session.agent.state.systemPrompt.join("\n");
		expect(systemPrompt).toContain("PROJECT_SCOPE_SUMMARY");
		expect(systemPrompt).not.toContain("HOST_SCOPE_LESSON");
	});
});
