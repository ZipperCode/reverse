import * as path from "node:path";
import { Agent } from "@reverse/agent";
import { createMockModel } from "@reverse/ai/providers/mock";
import { getBundledModel } from "@reverse/catalog/models";
import { ModelRegistry } from "@reverse/coding-agent/config/model-registry";
import { Settings } from "@reverse/coding-agent/config/settings";
import { runRpcMode } from "@reverse/coding-agent/modes/rpc/rpc-mode";
import { AgentSession } from "@reverse/coding-agent/session/agent-session";
import { AuthStorage } from "@reverse/coding-agent/session/auth-storage";
import { convertToLlm } from "@reverse/coding-agent/session/messages";
import { SessionManager } from "@reverse/coding-agent/session/session-manager";
import { VISION_DESCRIPTION_SSE, waitForFile } from "../helpers/skill-image-vision";

// Real RPC dispatch with a `/skill:look` command on a text-only main model, so an image
// attached to the skill is described by the vision role first. The vision request creates
// `vision-started` in the cwd and holds until the test creates `vision-release` there.
const cwd = process.cwd();
const skillPath = path.join(cwd, "look", "SKILL.md");
await Bun.write(skillPath, "---\nname: look\ndescription: Look at an image\n---\n\nDescribe the attached image.\n");

const realFetch = globalThis.fetch;
globalThis.fetch = Object.assign(
	async (input: string | URL | Request, init?: RequestInit) => {
		const url = input instanceof Request ? input.url : String(input);
		if (!url.endsWith("/chat/completions")) return realFetch(input, init);
		await Bun.write(path.join(cwd, "vision-started"), "");
		await waitForFile(path.join(cwd, "vision-release"));
		return new Response(VISION_DESCRIPTION_SSE, { status: 200, headers: { "content-type": "text/event-stream" } });
	},
	{ preconnect: realFetch.preconnect },
);

const authStorage = await AuthStorage.create(path.join(cwd, "auth.db"));
authStorage.keys.setRuntime("zai", "test-key");
const modelRegistry = new ModelRegistry(authStorage, path.join(cwd, "models.yml"));
const mock = createMockModel({ handler: { content: ["ok"] } });
const agent = new Agent({
	getApiKey: () => "test-key",
	initialState: { model: getBundledModel("zai", "glm-5.3"), systemPrompt: ["Test"], tools: [], messages: [] },
	convertToLlm,
	streamFn: mock.stream,
});
const session = new AgentSession({
	agent,
	sessionManager: SessionManager.inMemory(cwd),
	settings: Settings.isolated({
		"compaction.enabled": false,
		modelRoles: { vision: "zai/glm-5.3-flash:max", default: "zai/glm-5.3:max" },
	}),
	modelRegistry,
	toolRegistry: new Map(),
	skills: [
		{
			name: "look",
			description: "Look at an image",
			filePath: skillPath,
			baseDir: path.dirname(skillPath),
			source: "project",
		},
	],
	skillsSettings: { enableSkillCommands: true },
});
await runRpcMode(session);
