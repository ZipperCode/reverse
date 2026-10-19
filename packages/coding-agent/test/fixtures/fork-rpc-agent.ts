import * as path from "node:path";
import { Agent } from "@reverse/agent";
import { createMockModel } from "@reverse/ai/providers/mock";
import { getBundledModel } from "@reverse/catalog/models";
import { ModelRegistry } from "@reverse/coding-agent/config/model-registry";
import { Settings } from "@reverse/coding-agent/config/settings";
import { runRpcMode } from "@reverse/coding-agent/modes/rpc/rpc-mode";
import { AgentSession } from "@reverse/coding-agent/session/agent-session";
import { AuthStorage } from "@reverse/coding-agent/session/auth-storage";
import { SessionManager } from "@reverse/coding-agent/session/session-manager";

// Real RPC dispatch over a session persisted under the test's temp root; only model replies are scripted.
// The root arrives as argv so storage can never land in an inherited cwd such as the repo checkout.
const root = process.argv[2];
if (!root || root.startsWith("-")) throw new Error("fork-rpc-agent: expected the temp root as the first argument");
process.chdir(root);
const cwd = process.cwd();
const authStorage = await AuthStorage.create(path.join(cwd, "auth.db"));
authStorage.keys.setRuntime("anthropic", "test-key");
const modelRegistry = new ModelRegistry(authStorage, path.join(cwd, "models.yml"));
const mock = createMockModel({
	// A prompt mentioning "slow" stays in flight long enough for the test to act mid-stream.
	handler: context => ({
		content: ["Done"],
		delayMs: JSON.stringify(context.messages.at(-1)?.content).includes("slow") ? 1500 : 0,
	}),
});
const agent = new Agent({
	getApiKey: () => "test-key",
	initialState: { model: getBundledModel("anthropic", "claude-sonnet-4-5")!, systemPrompt: ["Test"], tools: [] },
	streamFn: mock.stream,
});
const session = new AgentSession({
	agent,
	sessionManager: SessionManager.create(cwd, path.join(cwd, "sessions")),
	settings: Settings.isolated({ "compaction.enabled": false }),
	modelRegistry,
});
await runRpcMode(session);
