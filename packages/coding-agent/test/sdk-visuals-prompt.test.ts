import { describe, expect, it } from "bun:test";
import * as path from "node:path";
import { getBundledModel } from "@reverse/catalog/models";
import { ModelRegistry } from "@reverse/coding-agent/config/model-registry";
import { Settings } from "@reverse/coding-agent/config/settings";
import { type CreateAgentSessionOptions, createAgentSession } from "@reverse/coding-agent/sdk";
import { AuthStorage } from "@reverse/coding-agent/session/auth-storage";
import { SessionManager } from "@reverse/coding-agent/session/session-manager";
import { TempDir } from "@reverse/utils";

/** The default system prompt of a session created with `options`. */
async function promptFor(options: CreateAgentSessionOptions): Promise<string> {
	using tempDir = TempDir.createSync("@reverse-sdk-visuals-prompt-");
	const cwd = tempDir.join("project");
	const authStorage = await AuthStorage.create(":memory:");
	const modelRegistry = new ModelRegistry(authStorage, path.join(tempDir.path(), "models.yml"));
	const { session } = await createAgentSession({
		cwd,
		agentDir: tempDir.join("agent"),
		authStorage,
		modelRegistry,
		settings: Settings.isolated(),
		sessionManager: SessionManager.inMemory(cwd),
		model: getBundledModel("openai", "gpt-4o-mini"),
		disableExtensionDiscovery: true,
		skills: [],
		contextFiles: [],
		promptTemplates: [],
		slashCommands: [],
		enableMCP: false,
		enableLsp: false,
		skipPythonPreflight: true,
		...options,
	});
	try {
		return session.systemPrompt.join("\n");
	} finally {
		await session.dispose();
		authStorage.close();
	}
}

describe("visuals guidance in the system prompt", () => {
	it("is offered to the top-level TUI session only, not to RPC or subagent sessions", async () => {
		const tui = await promptFor({ hasUI: true, tuiTranscript: true });
		expect(tui).toContain("```mermaid");
		expect(tui).toContain("```svg");
		expect(tui).toContain("charts it underneath");

		// rpc-ui: a UI for dialogs, but replies are read by the client as text.
		const rpc = await promptFor({ hasUI: true });
		const subagent = await promptFor({ hasUI: true, tuiTranscript: true, taskDepth: 1 });
		for (const prompt of [rpc, subagent]) {
			expect(prompt).not.toContain("```mermaid");
			expect(prompt).not.toContain("```svg");
			expect(prompt).not.toContain("charts it underneath");
		}
	});
});
