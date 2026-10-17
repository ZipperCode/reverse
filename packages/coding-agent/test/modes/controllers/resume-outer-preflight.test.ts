import { afterEach, beforeAll, describe, expect, it, vi } from "bun:test";
import * as path from "node:path";
import * as core from "@rva/agent";
import { ModelRegistry } from "@rva/coding-agent/config/model-registry";
import { resetSettingsForTest, Settings } from "@rva/coding-agent/config/settings";
import { InteractiveMode } from "@rva/coding-agent/modes/interactive-mode";
import { initTheme } from "@rva/tui/theme";
import { AgentSession } from "@rva/coding-agent/session/agent-session";
import { AuthStorage } from "@rva/coding-agent/session/auth-storage";
import { SessionManager } from "@rva/coding-agent/session/session-manager";
import { executeBuiltinSlashCommand } from "@rva/coding-agent/slash-commands/builtin-registry";
import { createTools, type Tool } from "@rva/coding-agent/tools";
import { TempDir } from "@rva/utils";

beforeAll(async () => {
	await initTheme();
});

afterEach(() => {
	vi.restoreAllMocks();
});

async function createMode(opts: { flushFails?: boolean } = {}): Promise<{
	mode: InteractiveMode;
	session: AgentSession;
	cleanup: () => Promise<void>;
}> {
	resetSettingsForTest();
	const tempDir = TempDir.createSync("@pi-resume-outer-");
	await Settings.init({ inMemory: true, cwd: tempDir.path() });
	const settings = Settings.isolated({ "compaction.enabled": false });

	const authStorage = await AuthStorage.create(path.join(tempDir.path(), "testauth.db"));
	const modelRegistry = new ModelRegistry(authStorage);
	const model = modelRegistry.find("anthropic", "claude-sonnet-4-5");
	if (!model) throw new Error("Expected claude-sonnet-4-5 to exist in registry");

	const initialTools = await createTools(
		{ cwd: tempDir.path(), hasUI: false, getSessionFile: () => null, getSessionSpawns: () => "*", settings },
		["read"],
	);
	const toolRegistry = new Map<string, Tool>(initialTools.map(tool => [tool.name, tool] as const));
	const session = new AgentSession({
		agent: new core.Agent({
			initialState: { model, systemPrompt: ["Test"], tools: initialTools, messages: [] },
		}),
		sessionManager: SessionManager.create(tempDir.path(), tempDir.path()),
		settings,
		modelRegistry,
		toolRegistry,
		rebuildSystemPrompt: async () => ({ systemPrompt: ["Test"] }),
	});
	const mode = new InteractiveMode(session, "test");
	vi.spyOn(mode, "addMessageToChat").mockReturnValue([]);
	vi.spyOn(mode, "ensureLoadingAnimation").mockImplementation(() => {});
	mode.ui.requestRender = vi.fn();

	// Make settings.flush fail or succeed as configured.
	vi.spyOn(mode.settings, "flush").mockImplementation(async () => {
		if (opts.flushFails) throw new Error("disk full");
	});

	return {
		mode,
		session,
		cleanup: async () => {
			resetSettingsForTest();
			authStorage.close();
			await tempDir.remove();
		},
	};
}

describe("InteractiveMode.handleResumeSession outer preflight flush", () => {
	it("aborts before disposing controllers or resetting observers when flush fails", async () => {
		const { mode, cleanup } = await createMode({ flushFails: true });
		try {
			const resetSpy = vi.spyOn(mode, "resetObserverRegistry");
			const switchSpy = vi.spyOn(mode.session, "switchSession").mockResolvedValue(true);
			const showErrorSpy = vi.spyOn(mode, "showError");

			await mode.handleResumeSession("/tmp/some-session.jsonl");

			expect(mode.settings.flush).toHaveBeenCalled();
			expect(showErrorSpy).toHaveBeenCalledWith(expect.stringContaining("disk full"));
			expect(resetSpy).not.toHaveBeenCalled();
			expect(switchSpy).not.toHaveBeenCalled();
		} finally {
			await cleanup();
		}
	});
});

describe("/resume <id> switch failures", () => {
	it("reports a session whose saved model cannot be restored and keeps the current one", async () => {
		const { mode, session, cleanup } = await createMode();
		try {
			const previousFile = session.sessionFile;
			const cwd = session.sessionManager.getCwd();
			const timestamp = "2026-06-01T00:00:00.000Z";
			await Bun.write(
				path.join(session.sessionManager.getSessionDir(), "unrestorable.jsonl"),
				`${[
					{ type: "session", version: 3, id: "unrestorable", timestamp, cwd },
					{
						type: "model_change",
						id: "model",
						parentId: null,
						timestamp,
						model: "missing-provider/missing-model",
						role: "default",
					},
					{
						type: "message",
						id: "user",
						parentId: "model",
						timestamp,
						message: { role: "user", content: "Hello", timestamp: Date.parse(timestamp) },
					},
				]
					.map(entry => JSON.stringify(entry))
					.join("\n")}\n`,
			);
			const showErrorSpy = vi.spyOn(mode, "showError");

			expect(await executeBuiltinSlashCommand("/resume unrestorable", { ctx: mode })).toBe(true);

			expect(showErrorSpy).toHaveBeenCalledWith("Could not restore model missing-provider/missing-model");
			expect(session.sessionFile).toBe(previousFile);
		} finally {
			await cleanup();
		}
	});
});
