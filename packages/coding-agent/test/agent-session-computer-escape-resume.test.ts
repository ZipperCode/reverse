import { afterAll, afterEach, beforeAll, describe, expect, it } from "bun:test";
import * as path from "node:path";
import { Agent } from "@reverse/agent";
import { createMockModel } from "@reverse/ai/providers/mock";
import { getBundledModel } from "@reverse/catalog/models";
import { ModelRegistry } from "@reverse/coding-agent/config/model-registry";
import { Settings } from "@reverse/coding-agent/config/settings";
import { AgentSession } from "@reverse/coding-agent/session/agent-session";
import { AuthStorage } from "@reverse/coding-agent/session/auth-storage";
import { convertToLlm, SKILL_PROMPT_MESSAGE_TYPE } from "@reverse/coding-agent/session/messages";
import { SessionManager } from "@reverse/coding-agent/session/session-manager";
import { registerComputerController } from "@reverse/coding-agent/tools/computer/supervisor";
import { TempDir } from "@reverse/utils";

describe("AgentSession computer use after the user's Escape", () => {
	let tempDir: TempDir;
	let authStorage: AuthStorage;
	let modelRegistry: ModelRegistry;
	let session: AgentSession | undefined;

	beforeAll(async () => {
		tempDir = TempDir.createSync("@pi-computer-escape-");
		authStorage = await AuthStorage.create(path.join(tempDir.path(), "auth.db"));
		authStorage.keys.setRuntime("anthropic", "test-key");
		modelRegistry = new ModelRegistry(authStorage, path.join(tempDir.path(), "models.yml"));
	});

	afterEach(async () => {
		await session?.dispose();
		session = undefined;
	});

	afterAll(() => {
		authStorage.close();
		tempDir.removeSync();
	});

	it("resumes on the user's prompt, steer, follow-up and skill prompt, never on agent-sent or synthetic ones", async () => {
		const model = getBundledModel("anthropic", "claude-sonnet-4-5")!;
		const mock = createMockModel({
			responses: ["stopped", "budget", "steered", "followed", "skill", "continued"].map(text => ({
				content: [text],
			})),
		});
		const agent = new Agent({
			getApiKey: () => "test-key",
			initialState: { model, systemPrompt: ["Test"], tools: [] },
			convertToLlm,
			streamFn: mock.stream,
		});
		const current = new AgentSession({
			agent,
			sessionManager: SessionManager.inMemory(),
			settings: Settings.isolated({ "compaction.enabled": false }),
			modelRegistry,
		});
		session = current;
		let resumes = 0;
		const unregister = registerComputerController(current.getEvalKernelOwnerId(), {
			run: async () => ({ displays: [], returnValue: undefined, screenshots: [] }),
			capabilities: async () => undefined,
			close: async () => {},
			resumeAfterEscape: () => {
				resumes += 1;
			},
		});
		try {
			const atYield: number[] = [];
			const inject = [
				// A subagent's request-budget notice is a user-role steer the agent sends.
				() => current.sendUserMessage("request budget low", { deliverAs: "steer", attribution: "agent" }),
				() => current.steer("keep going"),
				() => current.followUp("then save"),
			];
			current.agent.setOnBeforeYield(async () => {
				atYield.push(resumes);
				await inject.shift()?.();
			});
			await current.prompt("click the button");
			await current.waitForIdle();
			expect(atYield).toEqual([1, 1, 2, 3]);

			await current.promptCustomMessage({
				customType: SKILL_PROMPT_MESSAGE_TYPE,
				content: "run skill",
				display: true,
				details: { name: "test", path: "/tmp/SKILL.md", lineCount: 1 },
				attribution: "user",
			});
			await current.waitForIdle();
			expect(resumes).toBe(4);

			await current.prompt("Continue.", { synthetic: true });
			await current.waitForIdle();
			expect(mock.calls.length).toBe(6);
			expect(resumes).toBe(4);
		} finally {
			unregister();
		}
	});
});
