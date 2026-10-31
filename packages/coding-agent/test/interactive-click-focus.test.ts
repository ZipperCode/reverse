import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "bun:test";
import * as path from "node:path";
import { Agent } from "@reverse/agent";
import { ModelRegistry } from "@reverse/coding-agent/config/model-registry";
import { resetSettingsForTest, Settings } from "@reverse/coding-agent/config/settings";
import type { Extension } from "@reverse/coding-agent/extensibility/extensions";
import { ExtensionRuntime } from "@reverse/coding-agent/extensibility/extensions/loader";
import { ExtensionRunner } from "@reverse/coding-agent/extensibility/extensions/runner";
import { cfgExtensionAssistantTextRenderers } from "@reverse/coding-agent/extensibility/settings";
import { ToolExecutionComponent } from "@reverse/tui/chat/tool-execution";
import { AssistantMessageComponent } from "@reverse/tui/chat/assistant-message";
import { ReadToolGroupComponent } from "@reverse/tui/chat/read-tool-group";
import { SkillMessageComponent } from "@reverse/tui/chat/skill-message";
import { Text } from "@reverse/tui/components/text";
import type { AssistantMessage } from "@reverse/ai";
import { Composer } from "@reverse/tui/prompt/composer";
import { InteractiveMode } from "@reverse/coding-agent/modes/interactive-mode";
import { initTheme } from "@reverse/tui/theme";
import { AgentSession } from "@reverse/coding-agent/session/agent-session";
import { AuthStorage } from "@reverse/coding-agent/session/auth-storage";
import { SessionManager } from "@reverse/coding-agent/session/session-manager";
import type { AgentProgress } from "@reverse/tui/tools/task";
import { TASK_SUBAGENT_LIFECYCLE_CHANNEL } from "@reverse/coding-agent/task";
import { EventBus } from "@reverse/coding-agent/utils/event-bus";
import { TempDir } from "@reverse/utils";
import { VirtualTerminal } from "../../tui/test/virtual-terminal";

import { cfgTuiMouse } from "@reverse/coding-agent/modes/settings";
import { setNativeRendering } from "@reverse/tui/native/state";

function plainRows(rows: readonly string[]): string[] {
	return rows.map(row => Bun.stripANSI(row).trimEnd());
}

describe("inline click-to-focus geometry", () => {
	let tempDir: TempDir;
	let authStorage: AuthStorage;
	let session: AgentSession;
	let mode: InteractiveMode;
	let term: VirtualTerminal;
	let eventBus: EventBus;
	let modelRegistry: ModelRegistry;

	beforeAll(() => {
		initTheme();
	});

	beforeEach(async () => {
		resetSettingsForTest();
		tempDir = TempDir.createSync("@pi-click-focus-e2e-");
		await Settings.init({ inMemory: true, cwd: tempDir.path() });
		authStorage = await AuthStorage.create(path.join(tempDir.path(), "testauth.db"));
		modelRegistry = new ModelRegistry(authStorage);
		const model = modelRegistry.find("anthropic", "claude-sonnet-4-5");
		if (!model) throw new Error("Expected claude-sonnet-4-5 to exist in registry");
		session = new AgentSession({
			agent: new Agent({ initialState: { model, systemPrompt: ["Test"], tools: [], messages: [] } }),
			sessionManager: SessionManager.create(tempDir.path(), tempDir.path()),
			settings: Settings.isolated(),
			modelRegistry,
		});
		term = new VirtualTerminal(120, 32);
		eventBus = new EventBus();
		const composer = new Composer({ terminal: term });
		mode = new InteractiveMode(session, "test", undefined, () => {}, undefined, undefined, eventBus, composer);
	});
	afterEach(async () => {
		vi.restoreAllMocks();
		mode?.stop();
		await session?.dispose();
		authStorage?.close();
		tempDir?.removeSync();
		resetSettingsForTest();
	});

	it("maps a painted live task row back to its agent id", async () => {
		await mode.init({ suppressWelcomeIntro: true });
		void mode.getUserInput();
		await term.waitForRender();

		const card = new ToolExecutionComponent(
			"task",
			{},
			{},
			undefined,
			{
				requestRender: () => mode.ui.requestRender(),
				requestComponentRender: () => {},
				resetDisplay: () => {},
			},
			tempDir.path(),
		);
		mode.chatContainer.addChild(card);
		const progress: AgentProgress = {
			index: 0,
			id: "ClickWorker",
			agent: "task",
			agentSource: "bundled",
			status: "running",
			task: "do clickable work",
			recentTools: [],
			recentOutput: [],
			toolCount: 1,
			requests: 1,
			tokens: 0,
			cost: 0,
			durationMs: 0,
		};
		card.updateResult(
			{
				content: [{ type: "text", text: "Running 1 agent..." }],
				details: { projectAgentsDir: null, results: [], totalDurationMs: 1, progress: [progress] },
			},
			true,
		);
		mode.ui.requestRender();
		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes("ClickWorker")));

		// Screen row (0-based from the top) into mutable-viewport coordinates,
		// exactly as the SGR click router computes it.
		const viewport = plainRows(term.getViewport());
		const screenRow = viewport.findIndex(row => row.includes("ClickWorker"));
		expect(screenRow).toBeGreaterThanOrEqual(0);
		const top = mode.ui.getMutableViewport().top;
		expect(mode.resolveViewportClickCandidates(screenRow - top)).toEqual(["ClickWorker"]);

		// Chrome rows (the status line at the bottom) name no agent.
		expect(mode.resolveViewportClickCandidates(viewport.length - 1 - top)).toEqual([]);
	});

	it("bands the hovered live card and clears it off-target", async () => {
		cfgTuiMouse.set(mode.settings, true);
		await mode.init({ suppressWelcomeIntro: true });
		void mode.getUserInput();
		await term.waitForRender();

		const card = new ToolExecutionComponent(
			"task",
			{},
			{},
			undefined,
			{
				requestRender: () => mode.ui.requestRender(),
				requestComponentRender: () => {},
				resetDisplay: () => {},
			},
			tempDir.path(),
		);
		mode.chatContainer.addChild(card);
		card.updateResult(
			{
				content: [{ type: "text", text: "Running 1 agent..." }],
				details: {
					projectAgentsDir: null,
					results: [],
					totalDurationMs: 1,
					progress: [
						{
							index: 0,
							id: "HoverWorker",
							agent: "task",
							agentSource: "bundled",
							status: "running",
							task: "hoverable work",
							recentTools: [],
							recentOutput: [],
							toolCount: 1,
							requests: 1,
							tokens: 0,
							cost: 0,
							durationMs: 0,
						},
					],
				},
			},
			true,
		);
		mode.ui.requestRender();
		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes("HoverWorker")));

		const workerBg = (): number[] | undefined => {
			const rows = plainRows(term.getViewport());
			const row = rows.findIndex(line => line.includes("HoverWorker"));
			return row < 0 ? undefined : term.getViewportRowBackgroundValues(row);
		};
		const changed = (snapshot: number[] | undefined): boolean => {
			const now = workerBg();
			return now !== undefined && JSON.stringify(now) !== JSON.stringify(snapshot);
		};
		// Settle on a fresh frame so spans match the painted rows, then snapshot.
		mode.ui.requestRender();
		await term.waitForRender();
		const before = workerBg();
		expect(before).toBeDefined();
		// Motion is single-shot against the last painted spans, which can lag
		// one frame behind a just-mounted card: force a fresh frame, re-locate
		// by content, and retry until the band lands. The final expect still
		// fails loudly when nothing ever paints.
		for (let attempt = 0; attempt < 20; attempt++) {
			mode.ui.requestRender();
			await term.waitForRender();
			const rows = plainRows(term.getViewport());
			const row = rows.findIndex(line => line.includes("HoverWorker"));
			expect(row).toBeGreaterThanOrEqual(0);
			term.sendInput(`\x1b[<32;5;${row + 1}M`);
			await term.waitForRender(() => changed(before));
			if (changed(before)) break;
			if (attempt === 19) expect(changed(before)).toBe(true);
		}

		// Motion over the card bands its row.
		expect(changed(before)).toBe(true);

		// The live composer frame itself carries the band while hovered.
		const frame = mode.composer.renderFrame({ columns: 120, rows: 32 });
		expect(frame.viewport.filter(line => line.includes("\x1b[48")).length).toBeGreaterThan(0);

		// Disabling capture mid-hover clears the controller cache too: after
		// re-enabling, motion over the same card must restore the band instead
		// of looking unchanged and skipping the repaint.
		cfgTuiMouse.set(mode.settings, false);
		mode.ui.requestRender();
		await term.waitForRender(() => !changed(before));
		expect(workerBg()).toEqual(before);

		cfgTuiMouse.set(mode.settings, true);
		mode.ui.requestRender();
		await term.waitForRender();
		const cardRow = plainRows(term.getViewport()).findIndex(line => line.includes("HoverWorker"));
		expect(cardRow).toBeGreaterThanOrEqual(0);
		term.sendInput(`\x1b[<32;5;${cardRow + 1}M`);
		await term.waitForRender(() => changed(before));
		expect(changed(before)).toBe(true);

		// Moving onto the status line restores the exact prior colors.
		const bottomRow = term.getViewport().length - 1;
		term.sendInput(`\x1b[<32;5;${bottomRow + 1}M`);
		await term.waitForRender(() => !changed(before));
		expect(workerBg()).toEqual(before);
	});

	it("expands and collapses the pinned jump list through SGR clicks", async () => {
		cfgTuiMouse.set(mode.settings, true);
		await mode.init({ suppressWelcomeIntro: true });
		void mode.getUserInput();
		await term.waitForRender();

		for (let index = 0; index < 5; index++) {
			eventBus.emit(TASK_SUBAGENT_LIFECYCLE_CHANNEL, {
				id: `ToggleAgent${index}`,
				index,
				agent: "task",
				agentSource: "bundled",
				description: `toggle job ${index}`,
				status: "started",
				parentToolCallId: "tool-call",
				detached: true,
			});
		}
		const clickRow = async (marker: string): Promise<void> => {
			await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes(marker)));
			const viewport = plainRows(term.getViewport());
			const screenRow = viewport.findIndex(row => row.includes(marker));
			expect(screenRow).toBeGreaterThanOrEqual(0);
			term.sendInput(`\x1b[<0;5;${screenRow + 1}M`);
		};

		// Collapsed by default: three rows plus the expander.
		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes("more — expand")));
		expect(plainRows(term.getViewport()).some(row => row.includes("ToggleAgent3"))).toBe(false);

		// Clicking the expander paints the slotted window with a collapse row.
		await clickRow("more — expand");
		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes("show less")));
		expect(plainRows(term.getViewport()).some(row => row.includes("ToggleAgent4"))).toBe(true);
		// Clicking it again collapses back to a few rows.
		await clickRow("show less");
		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes("more — expand")));
		expect(plainRows(term.getViewport()).some(row => row.includes("ToggleAgent3"))).toBe(false);
	});

	it("expands and collapses tool execution through SGR clicks on header, body clicks no-op", async () => {
		cfgTuiMouse.set(mode.settings, true);
		await mode.init({ suppressWelcomeIntro: true });
		void mode.getUserInput();
		await term.waitForRender();

		const tool = new ToolExecutionComponent(
			"bash",
			{ command: "run_test_cmd" },
			{},
			undefined,
			{
				requestRender: () => mode.ui.requestRender(),
				requestComponentRender: () => {},
				resetDisplay: () => {},
			},
			tempDir.path(),
		);
		const outputLines = Array.from({ length: 15 }, (_, i) => `Bash output line ${i}`).join("\n");
		tool.updateResult({ content: [{ type: "text", text: outputLines }] }, false);
		mode.chatContainer.addChild(tool);
		mode.ui.requestRender();

		const clickRow = async (marker: string): Promise<void> => {
			await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes(marker)));
			const viewport = plainRows(term.getViewport());
			const screenRow = viewport.findIndex(row => row.includes(marker));
			expect(screenRow).toBeGreaterThanOrEqual(0);
			term.sendInput(`\x1b[<0;5;${screenRow + 1}M`);
		};

		// By default collapsed: tool header (Bash) is visible
		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes("Bash")));
		expect(tool.expanded).toBe(false);

		// Click on body command line -> must be NO-OP (does not expand)
		await clickRow("run_test_cmd");
		await term.waitForRender();
		expect(tool.expanded).toBe(false);

		await clickRow("Bash");
		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes("Bash output line 14")));
		expect(tool.expanded).toBe(true);

		// Click on header again -> collapses
		await clickRow("Bash");
		await term.waitForRender(() => tool.expanded === false);
		expect(tool.expanded).toBe(false);
	});

	it("expands and collapses thinking blocks through SGR clicks on header, body clicks no-op, preserves across streaming", async () => {
		cfgTuiMouse.set(mode.settings, true);
		await mode.init({ suppressWelcomeIntro: true });
		void mode.getUserInput();
		await term.waitForRender();

		const asst = new AssistantMessageComponent();
		const msgData: AssistantMessage = {
			role: "assistant",
			content: [
				{ type: "thinking", thinking: "My deep thinking line 1\nMy deep thinking line 2" },
				{ type: "text", text: "Visible answer text" },
			],
			api: "anthropic-messages",
			provider: "anthropic",
			model: "m",
			usage: {
				input: 0,
				output: 0,
				cacheRead: 0,
				cacheWrite: 0,
				totalTokens: 0,
				cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
			},
			stopReason: "stop",
			timestamp: 0,
		};
		asst.updateContent(msgData);
		mode.chatContainer.addChild(asst);
		mode.ui.requestRender();

		const clickRow = async (marker: string): Promise<void> => {
			await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes(marker)));
			const viewport = plainRows(term.getViewport());
			const screenRow = viewport.findIndex(row => row.includes(marker));
			expect(screenRow).toBeGreaterThanOrEqual(0);
			term.sendInput(`\x1b[<0;5;${screenRow + 1}M`);
		};

		// Collapsed by default: summary is visible, thinking body is hidden
		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes("Thought")));
		expect(plainRows(term.getViewport()).some(row => row.includes("My deep thinking line 1"))).toBe(false);

		// Click on answer prose text -> NO-OP (does not toggle thinking)
		await clickRow("Visible answer text");
		await term.waitForRender();
		expect(plainRows(term.getViewport()).some(row => row.includes("My deep thinking line 1"))).toBe(false);

		// Click on thinking header -> expands!
		await clickRow("Thought");
		await term.waitForRender(() =>
			plainRows(term.getViewport()).some(row => row.includes("My deep thinking line 1")),
		);
		expect(plainRows(term.getViewport()).some(row => row.includes("My deep thinking line 1"))).toBe(true);

		// Streaming update while expanded preserves expanded state
		const updatedMsg: AssistantMessage = {
			...msgData,
			content: [
				{ type: "thinking", thinking: "My deep thinking line 1\nMy deep thinking line 2\nThinking line 3 added" },
				{ type: "text", text: "Visible answer text updated" },
			],
		};
		asst.updateContent(updatedMsg, { transient: true });
		mode.ui.requestRender();
		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes("Thinking line 3 added")));
		expect(plainRows(term.getViewport()).some(row => row.includes("Thinking line 3 added"))).toBe(true);

		// Click on thinking header again -> collapses
		await clickRow("Thought");
		await term.waitForRender(
			() => !plainRows(term.getViewport()).some(row => row.includes("My deep thinking line 1")),
		);
		expect(plainRows(term.getViewport()).some(row => row.includes("My deep thinking line 1"))).toBe(false);
	});

	it("expands and collapses actively streaming thinking mid-stream BEFORE text delta arrives", async () => {
		cfgTuiMouse.set(mode.settings, true);
		await mode.init({ suppressWelcomeIntro: true });
		void mode.getUserInput();
		await term.waitForRender();

		const asst = new AssistantMessageComponent();
		const streamingReasoning: AssistantMessage = {
			role: "assistant",
			content: [{ type: "thinking", thinking: "Active reasoning line 1\nActive reasoning line 2" }],
			api: "anthropic-messages",
			provider: "anthropic",
			model: "m",
			usage: {
				input: 0,
				output: 0,
				cacheRead: 0,
				cacheWrite: 0,
				totalTokens: 0,
				cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
			},
			stopReason: "stop",
			timestamp: 0,
		};
		asst.updateContent(streamingReasoning, { transient: true });
		mode.chatContainer.addChild(asst);
		mode.ui.requestRender();

		const clickRow = async (marker: string): Promise<void> => {
			await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes(marker)));
			const viewport = plainRows(term.getViewport());
			const screenRow = viewport.findIndex(row => row.includes(marker));
			expect(screenRow).toBeGreaterThanOrEqual(0);
			term.sendInput(`\x1b[<0;5;${screenRow + 1}M`);
		};

		// 1. By default collapsed while streaming: shows live pulse "Thinking…"
		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes("Thinking")));
		expect(plainRows(term.getViewport()).some(row => row.includes("Active reasoning line 1"))).toBe(false);

		// 2. Click on the active streaming Thinking pulse -> opens thinking text!
		await clickRow("Thinking");
		await term.waitForRender(() =>
			plainRows(term.getViewport()).some(row => row.includes("Active reasoning line 1")),
		);
		expect(plainRows(term.getViewport()).some(row => row.includes("Active reasoning line 1"))).toBe(true);

		// 3. Click on the concise header "Thought" while STILL streaming -> collapses back to pulse BEFORE text arrives!
		await clickRow("Thought");
		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes("Thinking")));
		expect(plainRows(term.getViewport()).some(row => row.includes("Active reasoning line 1"))).toBe(false);

		// 4. Now text arrives (delta transition from thinking to text)
		const withText: AssistantMessage = {
			...streamingReasoning,
			content: [
				{ type: "thinking", thinking: "Active reasoning line 1\nActive reasoning line 2" },
				{ type: "text", text: "Answer after thinking" },
			],
		};
		asst.updateContent(withText, { transient: true });
		mode.ui.requestRender();
		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes("Answer after thinking")));
		expect(plainRows(term.getViewport()).some(row => row.includes("Answer after thinking"))).toBe(true);
		expect(plainRows(term.getViewport()).some(row => row.includes("Active reasoning line 1"))).toBe(false);
	});

	it("expands and collapses read tool group through SGR clicks on header", async () => {
		cfgTuiMouse.set(mode.settings, true);
		await mode.init({ suppressWelcomeIntro: true });
		void mode.getUserInput();
		await term.waitForRender();

		const readGroup = new ReadToolGroupComponent({ showContentPreview: false });
		readGroup.updateArgs({ path: "src/sample-file.ts" }, "read_1");
		readGroup.updateResult(
			{ content: [{ type: "text", text: "line 1 content\nline 2 content\nline 3 content\n" }] },
			false,
			"read_1",
		);
		readGroup.finalize();
		mode.chatContainer.addChild(readGroup);
		mode.ui.requestRender();

		const clickRow = async (marker: string): Promise<void> => {
			await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes(marker)));
			const viewport = plainRows(term.getViewport());
			const screenRow = viewport.findIndex(row => row.includes(marker));
			expect(screenRow).toBeGreaterThanOrEqual(0);
			term.sendInput(`\x1b[<0;5;${screenRow + 1}M`);
		};

		// Collapsed by default: header shows Read src/sample-file.ts
		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes("sample-file.ts")));
		expect(readGroup.expanded).toBe(false);

		// Click header -> expands preview
		await clickRow("sample-file.ts");
		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes("line 1 content")));
		expect(readGroup.expanded).toBe(true);

		// Click preview content body -> NO-OP
		await clickRow("line 1 content");
		await term.waitForRender();
		expect(readGroup.expanded).toBe(true);

		// Click header again -> collapses
		await clickRow("sample-file.ts");
		await term.waitForRender(() => readGroup.expanded === false);
		expect(readGroup.expanded).toBe(false);
	});

	it("expands and collapses skill prompt disclosure through SGR clicks on header", async () => {
		cfgTuiMouse.set(mode.settings, true);
		await mode.init({ suppressWelcomeIntro: true });
		void mode.getUserInput();
		await term.waitForRender();

		const skillCard = new SkillMessageComponent({
			role: "custom",
			customType: "skill-prompt",
			content: "stage all tracked files",
			display: true,
			details: {
				name: "atomic-commit",
				path: path.join(tempDir.path(), "SKILL.md"),
				lineCount: 1,
			},
			timestamp: Date.now(),
		});
		mode.chatContainer.addChild(skillCard);
		mode.ui.requestRender();

		const clickRow = async (marker: string): Promise<void> => {
			await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes(marker)));
			const viewport = plainRows(term.getViewport());
			const screenRow = viewport.findIndex(row => row.includes(marker));
			expect(screenRow).toBeGreaterThanOrEqual(0);
			term.sendInput(`\x1b[<0;5;${screenRow + 1}M`);
		};

		// Collapsed by default: header shows test-skill chip
		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes("atomic-commit")));
		expect(skillCard.expanded).toBe(false);
		expect(plainRows(term.getViewport()).some(row => row.includes("stage all tracked files"))).toBe(false);

		// Click header -> expands prompt
		await clickRow("atomic-commit");
		await term.waitForRender(() =>
			plainRows(term.getViewport()).some(row => row.includes("stage all tracked files")),
		);
		expect(skillCard.expanded).toBe(true);

		// Click prompt content body -> NO-OP
		await clickRow("stage all tracked files");
		await term.waitForRender();
		expect(skillCard.expanded).toBe(true);

		// Click header again -> collapses
		await clickRow("atomic-commit");
		await term.waitForRender(() => skillCard.expanded === false);
		expect(skillCard.expanded).toBe(false);

		// Click top rail padding row0 -> must be NO-OP (does not toggle)
		const chipRow = plainRows(term.getViewport()).findIndex(row => row.includes("atomic-commit"));
		expect(chipRow).toBeGreaterThan(0);
		term.sendInput(`\x1b[<0;5;${chipRow}M`);
		await term.waitForRender();
		expect(skillCard.expanded).toBe(false);

		// Click visible chip header -> expands
		await clickRow("atomic-commit");
		await term.waitForRender(() =>
			plainRows(term.getViewport()).some(row => row.includes("stage all tracked files")),
		);
		expect(skillCard.expanded).toBe(true);
	});

	it("bypasses detail clicks when tui.mouse is disabled", async () => {
		cfgTuiMouse.set(mode.settings, false);
		await mode.init({ suppressWelcomeIntro: true });
		void mode.getUserInput();
		await term.waitForRender();

		const tool = new ToolExecutionComponent(
			"bash",
			{ command: "bypass_test_cmd" },
			{},
			undefined,
			{
				requestRender: () => mode.ui.requestRender(),
				requestComponentRender: () => {},
				resetDisplay: () => {},
			},
			tempDir.path(),
		);
		tool.updateResult({ content: [{ type: "text", text: "bypass output" }] }, false);
		mode.chatContainer.addChild(tool);
		mode.ui.requestRender();

		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes("Bash")));
		const viewport = plainRows(term.getViewport());
		const screenRow = viewport.findIndex(row => row.includes("Bash"));
		expect(screenRow).toBeGreaterThanOrEqual(0);

		// Send SGR click with mouse disabled
		term.sendInput(`\x1b[<0;5;${screenRow + 1}M`);
		await term.waitForRender();
		expect(tool.expanded).toBe(false);
	});

	it("headerless think tool body clicks are no-op and never expand", async () => {
		cfgTuiMouse.set(mode.settings, true);
		await mode.init({ suppressWelcomeIntro: true });
		void mode.getUserInput();
		await term.waitForRender();

		const tool = new ToolExecutionComponent(
			"think",
			{ thoughts: "Reflecting on test cases\nConsidering boundary conditions" },
			{},
			undefined,
			{
				requestRender: () => mode.ui.requestRender(),
				requestComponentRender: () => {},
				resetDisplay: () => {},
			},
			tempDir.path(),
		);
		mode.chatContainer.addChild(tool);
		mode.ui.requestRender();

		const clickRow = async (marker: string): Promise<void> => {
			await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes(marker)));
			const viewport = plainRows(term.getViewport());
			const screenRow = viewport.findIndex(row => row.includes(marker));
			expect(screenRow).toBeGreaterThanOrEqual(0);
			term.sendInput(`\x1b[<0;5;${screenRow + 1}M`);
		};

		await term.waitForRender(() =>
			plainRows(term.getViewport()).some(row => row.includes("Reflecting on test cases")),
		);
		expect(tool.expanded).toBe(false);

		// Clicking any row of headerless think tool must be a NO-OP
		await clickRow("Reflecting on test cases");
		await term.waitForRender();
		expect(tool.expanded).toBe(false);

		await clickRow("Considering boundary conditions");
		await term.waitForRender();
		expect(tool.expanded).toBe(false);
	});

	it("multi-file edit toggles expanded on file header click, diff body clicks are no-op", async () => {
		cfgTuiMouse.set(mode.settings, true);
		await mode.init({ suppressWelcomeIntro: true });
		void mode.getUserInput();
		await term.waitForRender();

		const tool = new ToolExecutionComponent(
			"edit",
			{
				file_path: "multi.ts",
				edits: [
					{ path: "alpha.ts", oldText: "oldAlpha", newText: "newAlpha" },
					{ path: "beta.ts", oldText: "oldBeta", newText: "newBeta" },
				],
			},
			{},
			undefined,
			{
				requestRender: () => mode.ui.requestRender(),
				requestComponentRender: () => {},
				resetDisplay: () => {},
			},
			tempDir.path(),
		);
		tool.updateResult(
			{
				content: [],
				details: {
					perFileResults: [
						{
							path: path.join(tempDir.path(), "alpha.ts"),
							diff: " 1|keep\n-2|oldA\n+2|newA\n+3|moreA\n+4|extraA",
							firstChangedLine: 2,
							op: "update",
						},
						{
							path: path.join(tempDir.path(), "beta.ts"),
							diff: " 1|keep\n-2|oldB\n+2|newB",
							firstChangedLine: 2,
							op: "update",
						},
					],
				},
			},
			false,
		);
		mode.chatContainer.addChild(tool);
		mode.ui.requestRender();

		const clickRow = async (marker: string): Promise<void> => {
			await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes(marker)));
			const viewport = plainRows(term.getViewport());
			const screenRow = viewport.findIndex(row => row.includes(marker));
			expect(screenRow).toBeGreaterThanOrEqual(0);
			term.sendInput(`\x1b[<0;5;${screenRow + 1}M`);
		};

		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes("alpha.ts")));
		expect(tool.expanded).toBe(false);

		// Click diff body row inside alpha.ts -> must be NO-OP
		if (plainRows(term.getViewport()).some(row => row.includes("oldA"))) {
			await clickRow("oldA");
			await term.waitForRender();
			expect(tool.expanded).toBe(false);
		}

		// Click file header (alpha.ts) -> toggles expanded
		await clickRow("alpha.ts");
		await term.waitForRender(() => tool.expanded === true);
		expect(tool.expanded).toBe(true);

		// Click file header (beta.ts) -> toggles collapsed
		await clickRow("beta.ts");
		await term.waitForRender(() => tool.expanded === false);
		expect(tool.expanded).toBe(false);
	});

	it("multi-file read tool group toggles expanded on header, tree summary rows are no-op", async () => {
		cfgTuiMouse.set(mode.settings, true);
		await mode.init({ suppressWelcomeIntro: true });
		void mode.getUserInput();
		await term.waitForRender();

		const readGroup = new ReadToolGroupComponent({ showContentPreview: false });
		readGroup.updateArgs({ path: "src/first.ts" }, "read_1");
		readGroup.updateResult(
			{
				content: [{ type: "text", text: "first file content line 1\nfirst file content line 2\n" }],
				details: { displayContent: { text: "first file content line 1\nfirst file content line 2\n" } },
			},
			false,
			"read_1",
		);
		readGroup.updateArgs({ path: "src/second.ts" }, "read_2");
		readGroup.updateResult(
			{
				content: [{ type: "text", text: "second file content\n" }],
				details: { displayContent: { text: "second file content\n" } },
			},
			false,
			"read_2",
		);
		readGroup.finalize();
		mode.chatContainer.addChild(readGroup);
		mode.ui.requestRender();

		const clickRow = async (marker: string): Promise<void> => {
			await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes(marker)));
			const viewport = plainRows(term.getViewport());
			const screenRow = viewport.findIndex(row => row.includes(marker));
			expect(screenRow).toBeGreaterThanOrEqual(0);
			term.sendInput(`\x1b[<0;5;${screenRow + 1}M`);
		};

		// Collapsed by default: header shows "Read (2)" and summary rows show "first.ts" and "second.ts"
		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes("Read (2)")));
		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes("first.ts")));
		expect(readGroup.expanded).toBe(false);

		// Click tree summary row ("first.ts") -> MUST NOT toggle expanded
		await clickRow("first.ts");
		await term.waitForRender();
		expect(readGroup.expanded).toBe(false);

		// Click header row ("Read (2)") -> toggles expanded
		await clickRow("Read (2)");
		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes("first file content")));
		expect(readGroup.expanded).toBe(true);

		// Click preview content body -> NO-OP
		await clickRow("first file content");
		await term.waitForRender();
		expect(readGroup.expanded).toBe(true);

		// Click header row again -> collapses
		await clickRow("Read (2)");
		await term.waitForRender(() => readGroup.expanded === false);
		expect(readGroup.expanded).toBe(false);
	});

	/**
	 * Install a runner whose one extension claims `schemes` (`demo:` by default) and records each
	 * `link_activate` URL.
	 */
	function installDemoLinkExtension(schemes: string[] = ["demo"]): {
		activated: string[];
		firstActivation: Promise<void>;
		extension: Extension;
		runner: ExtensionRunner;
	} {
		const activated: string[] = [];
		const first = Promise.withResolvers<void>();
		const handlers: Extension["handlers"] = new Map();
		handlers.set("link_activate", [
			async (...args: unknown[]) => {
				const [event] = args;
				if (event && typeof event === "object" && "url" in event && typeof event.url === "string") {
					activated.push(event.url);
				}
				first.resolve();
			},
		]);
		const extension: Extension = {
			path: "/test/links.ts",
			resolvedPath: "/test/links.ts",
			handlers,
			tools: new Map(),
			assistantThinkingRenderers: [],
			assistantTextRenderers: [],
			linkSchemes: schemes,
			fileWriteFallbackHandlers: [],
			fileDeleteFallbackHandlers: [],
			messageRenderers: new Map(),
			composerShapes: new Map(),
			commands: new Map(),
			flags: new Map(),
			shortcuts: new Map(),
		};
		const runner = new ExtensionRunner(
			[extension],
			new ExtensionRuntime(),
			tempDir.path(),
			session.sessionManager,
			modelRegistry,
			undefined,
			mode.settings,
		);
		Object.defineProperty(session, "extensionRunner", { configurable: true, get: () => runner });
		return { activated, firstActivation: first.promise, extension, runner };
	}

	function appendReply(text: string): void {
		session.sessionManager.appendMessage({
			role: "assistant",
			content: [{ type: "text", text }],
			api: "anthropic-messages",
			provider: "anthropic",
			model: "claude-sonnet-4-5",
			stopReason: "stop",
			usage: {
				input: 0,
				output: 0,
				cacheRead: 0,
				cacheWrite: 0,
				totalTokens: 0,
				cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
			},
			timestamp: 1,
		});
	}

	/** Draw one assistant reply with `text` and wait until `visible` shows on screen. */
	async function showReply(text: string, visible: string): Promise<void> {
		appendReply(text);
		await mode.renderInitialMessages();
		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes(visible)));
	}

	it("leaves a link change before the startup replay to that replay, drawing the transcript once", async () => {
		cfgExtensionAssistantTextRenderers.set(mode.settings, true);
		const { extension } = installDemoLinkExtension([]);
		appendReply("Open [the details](demo:open/7) now.");
		await mode.init({ suppressWelcomeIntro: true });
		void mode.getUserInput();
		await term.waitForRender();
		// A startup notice (MCP, LSP) lands in the chat before the replay; then a scheme is claimed.
		mode.showWarning("early notice");
		extension.linkSchemes.push("demo");
		mode.syncExtensionLinks();
		// Any rebuild the change queued runs as a microtask, before this continuation.
		await Promise.resolve();
		await mode.renderInitialMessages({ preserveExistingChat: true });
		const chat = plainRows(mode.chatContainer.render(120)).join("\n");
		expect(chat.split("Open the details now.").length - 1).toBe(1);
		expect(chat.split("early notice").length - 1).toBe(1);
	});

	it("hands a click on an extension-owned link to its extension with tui.mouse on, other links unchanged", async () => {
		cfgExtensionAssistantTextRenderers.set(mode.settings, true);
		cfgTuiMouse.set(mode.settings, true);
		const { activated, firstActivation } = installDemoLinkExtension();
		await mode.init({ suppressWelcomeIntro: true });
		void mode.getUserInput();
		await term.waitForRender();

		const written: string[] = [];
		const write = term.write.bind(term);
		vi.spyOn(term, "write").mockImplementation(data => {
			written.push(data);
			write(data);
		});
		await showReply("Open [the details](demo:open/7) or read [the docs](https://example.com/docs).", "the details");
		// The terminal never receives the extension URL, so it has no hyperlink of its own to open.
		expect(written.join("")).not.toContain("demo:open/7");
		expect(written.join("")).toContain("https://example.com/docs");
		const viewport = plainRows(term.getViewport());
		const screenRow = viewport.findIndex(row => row.includes("the details"));
		// The extension link draws without its URL; the web link keeps the suffix.
		expect(viewport[screenRow]).not.toContain("demo:open/7");
		expect(viewport[screenRow]).toContain("the docs (https://example.com/docs)");

		const click = (label: string) =>
			term.sendInput(`\x1b[<0;${viewport[screenRow]!.indexOf(label) + 2};${screenRow + 1}M`);
		// A click on the web link raises nothing; the extension link's click reaches its extension.
		click("the docs");
		click("the details");
		await firstActivation;
		expect(activated).toEqual(["demo:open/7"]);
	});

	it("picks an extension link by its hint tag with tui.mouse off; Esc cancels without picking", async () => {
		cfgExtensionAssistantTextRenderers.set(mode.settings, true);
		const { activated, firstActivation } = installDemoLinkExtension();
		await mode.init({ suppressWelcomeIntro: true });
		void mode.getUserInput();
		await term.waitForRender();
		// A user rebinding of the hint key is honored.
		mode.keybindings.setUserBindings({ "app.links.hint": "alt+k" });
		expect(cfgTuiMouse.get(mode.settings)).toBe(false);
		expect(session.extensionRunner?.getUIContext()?.getLinkClicksAvailable()).toBe(true);

		await showReply("Open [the details](demo:open/7) or read [the docs](https://example.com/docs).", "the details");
		const tagged = () => plainRows(term.getViewport()).some(row => row.includes("Open ahe details"));
		const hintKey = "\x1bk";

		// Esc leaves hint mode untouched by any pick, and the next letter types into the editor again.
		term.sendInput(hintKey);
		await term.waitForRender(tagged);
		term.sendInput("\x1b");
		await term.waitForRender(() => !tagged());
		term.sendInput("a");
		await term.waitForRender();
		expect(mode.editor.getText()).toBe("a");
		expect(activated).toEqual([]);

		// The tag drawn over the label picks it.
		term.sendInput(hintKey);
		await term.waitForRender(tagged);
		term.sendInput("a");
		await firstActivation;
		expect(activated).toEqual(["demo:open/7"]);
		await term.waitForRender(() => !tagged());
		expect(mode.editor.getText()).toBe("a");

		// An overlay opening mid-hint (e.g. an extension's custom UI) gets the keys; no link is picked.
		term.sendInput(hintKey);
		await term.waitForRender(tagged);
		const overlayInput: string[] = [];
		const overlay = mode.ui.showOverlay({
			render: () => ["overlay"],
			handleInput: (data: string) => overlayInput.push(data),
			invalidate: () => {},
		});
		term.sendInput("a");
		await term.waitForRender(() => !tagged());
		expect(overlayInput).toEqual(["a"]);
		expect(activated).toEqual(["demo:open/7"]);
		overlay.hide();

		// Same for a dialog that takes focus in the editor area (ask, selectors), which is no overlay.
		term.sendInput(hintKey);
		await term.waitForRender(tagged);
		const dialogInput: string[] = [];
		const dialog = {
			render: () => [],
			handleInput: (data: string) => dialogInput.push(data),
			invalidate: () => {},
		};
		mode.ui.setFocus(dialog);
		term.sendInput("a");
		await term.waitForRender(() => !tagged());
		expect(dialogInput).toEqual(["a"]);
		expect(activated).toEqual(["demo:open/7"]);
		// And the hint key does nothing while such a dialog has focus.
		term.sendInput(hintKey);
		await term.waitForRender();
		expect(mode.linkHintsActive).toBe(false);
		mode.ui.setFocus(mode.editor);

		// A paste ends hint mode and still lands in the editor.
		mode.editor.setText("");
		term.sendInput(hintKey);
		await term.waitForRender(tagged);
		term.sendInput("\x1b[200~pasted\x1b[201~");
		await term.waitForRender(() => !tagged());
		await term.waitForRender(() => mode.editor.getText() === "pasted");
		expect(mode.editor.getText()).toBe("pasted");
		expect(mode.linkHintsActive).toBe(false);
		expect(activated).toEqual(["demo:open/7"]);
	});

	it("reports links as unavailable with the hint key unbound until tui.mouse turns on", async () => {
		cfgExtensionAssistantTextRenderers.set(mode.settings, true);
		installDemoLinkExtension();
		await mode.init({ suppressWelcomeIntro: true });
		void mode.getUserInput();
		await term.waitForRender();
		const ui = session.extensionRunner?.getUIContext();
		expect(ui?.getLinkClicksAvailable()).toBe(true);
		mode.keybindings.setUserBindings({ "app.links.hint": [] });
		expect(ui?.getLinkClicksAvailable()).toBe(false);
		cfgTuiMouse.set(mode.settings, true);
		// The mode picks the change up from its settings listener, after `set` returns.
		await term.waitForRender(() => ui?.getLinkClicksAvailable() === true);
		expect(ui?.getLinkClicksAvailable()).toBe(true);
	});

	it("redraws a focused subagent's reply when its extension handles a click on its link", async () => {
		cfgExtensionAssistantTextRenderers.set(mode.settings, true);
		cfgTuiMouse.set(mode.settings, true);
		const extension = (handlers: Extension["handlers"], renderers: Extension["assistantTextRenderers"]) => ({
			path: "/test/links.ts",
			resolvedPath: "/test/links.ts",
			handlers,
			tools: new Map(),
			assistantThinkingRenderers: [],
			assistantTextRenderers: renderers,
			linkSchemes: ["demo"],
			fileWriteFallbackHandlers: [],
			fileDeleteFallbackHandlers: [],
			messageRenderers: new Map(),
			composerShapes: new Map(),
			commands: new Map(),
			flags: new Map(),
			shortcuts: new Map(),
		});
		const runner = (ext: Extension) =>
			new ExtensionRunner(
				[ext],
				new ExtensionRuntime(),
				tempDir.path(),
				session.sessionManager,
				modelRegistry,
				undefined,
				mode.settings,
			);
		// The main session's copy of the extension: interactive UI, never sees the click.
		const mainRunner = runner(extension(new Map(), []));
		// The subagent's own copy: a headless runner, as the task executor builds it.
		let opened = false;
		const handled = Promise.withResolvers<void>();
		const childHandlers: Extension["handlers"] = new Map();
		childHandlers.set("link_activate", [
			async (...args: unknown[]) => {
				opened = true;
				const ctx = args[1] as { ui: { rerenderMessage(timestamp: number): void } };
				ctx.ui.rerenderMessage(1);
				handled.resolve();
			},
		]);
		const childRunner = runner(
			extension(childHandlers, [
				({ text }) => (opened ? text.replace("[the details](demo:toggle)", "OPENED") : undefined),
			]),
		);
		Object.defineProperty(session, "extensionRunner", { configurable: true, get: () => mainRunner });
		await mode.init({ suppressWelcomeIntro: true });
		void mode.getUserInput();
		await term.waitForRender();
		// Focus the subagent: its transcript, renderers and link schemes come from its runner.
		const focused = new Proxy(session, {
			get: (target, property) => {
				if (property === "extensionRunner") return childRunner;
				const value = Reflect.get(target, property, target);
				return typeof value === "function" ? value.bind(target) : value;
			},
		});
		Object.defineProperty(mode, "viewSession", { configurable: true, get: () => focused });
		session.sessionManager.appendMessage({
			role: "assistant",
			content: [{ type: "text", text: "Open [the details](demo:toggle) now." }],
			api: "anthropic-messages",
			provider: "anthropic",
			model: "claude-sonnet-4-5",
			stopReason: "stop",
			usage: {
				input: 0,
				output: 0,
				cacheRead: 0,
				cacheWrite: 0,
				totalTokens: 0,
				cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
			},
			timestamp: 1,
		});
		await mode.renderInitialMessages();
		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes("the details")));
		// The subagent's runner has no UI of its own, yet its links are picked here: it says so too.
		expect(mainRunner.getUIContext()?.getLinkClicksAvailable()).toBe(true);
		expect(childRunner.hasUI()).toBe(false);
		expect(childRunner.getUIContext()?.getLinkClicksAvailable()).toBe(true);
		const viewport = plainRows(term.getViewport());
		const screenRow = viewport.findIndex(row => row.includes("the details"));
		term.sendInput(`\x1b[<0;${viewport[screenRow]!.indexOf("the details") + 2};${screenRow + 1}M`);
		await handled.promise;
		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes("OPENED")));
		expect(plainRows(term.getViewport()).some(row => row.includes("Open OPENED now."))).toBe(true);

		// Disabling the extension live suspends only the main copy; the subagent's copy stops drawing too.
		mainRunner.setSuspendedExtensions(() => true);
		await Promise.resolve();
		const chat = plainRows(mode.chatContainer.render(120)).join("\n");
		expect(chat).toContain("Open the details (demo:toggle) now.");
		expect(await childRunner.emitLinkActivate("demo:toggle")).toBe(false);
	});

	it("re-runs assistant text renderers when Tern's native view takes the screen and hands it back", async () => {
		cfgExtensionAssistantTextRenderers.set(mode.settings, true);
		const { extension, runner } = installDemoLinkExtension();
		// Draws the link only while it can be picked here, its target inline otherwise.
		extension.assistantTextRenderers.push(({ text }) =>
			runner.getUIContext()?.getLinkClicksAvailable()
				? undefined
				: text.replace("[the details](demo:open/7)", "INLINE"),
		);
		await mode.init({ suppressWelcomeIntro: true });
		void mode.getUserInput();
		await term.waitForRender();
		await showReply("Open [the details](demo:open/7) now.", "the details");
		const chat = () => plainRows(mode.chatContainer.render(120)).join("\n");
		expect(chat()).toContain("Open the details now.");
		try {
			setNativeRendering(true);
			// The redraw's rebuild runs as a microtask, before this continuation.
			await Promise.resolve();
			expect(chat()).toContain("Open INLINE now.");
		} finally {
			setNativeRendering(false);
		}
		await Promise.resolve();
		expect(chat()).toContain("Open the details now.");
	});

	it("drops a suspended extension's link scheme and renderers from the transcript, and restores them on resume", async () => {
		cfgExtensionAssistantTextRenderers.set(mode.settings, true);
		const { extension, runner } = installDemoLinkExtension();
		extension.assistantTextRenderers.push(({ text }) => text.replace("now", "NOW"));
		await mode.init({ suppressWelcomeIntro: true });
		void mode.getUserInput();
		await term.waitForRender();
		await showReply("Open [the details](demo:open/7) now.", "the details");
		const chat = () => plainRows(mode.chatContainer.render(120)).join("\n");
		expect(chat()).toContain("Open the details NOW.");

		// A live `disabledExtensions` edit suspends it: its scheme is no longer claimed, its renderer gone.
		runner.setSuspendedExtensions(() => true);
		expect(runner.getLinkSchemes()).toEqual([]);
		await Promise.resolve();
		expect(chat()).toContain("Open the details (demo:open/7) now.");

		runner.setSuspendedExtensions(() => false);
		await Promise.resolve();
		expect(chat()).toContain("Open the details NOW.");
	});

	it("maps detail clicks, hover bands, and link hints to scrolled transcript rows without stale pre-scroll coordinates", async () => {
		cfgExtensionAssistantTextRenderers.set(mode.settings, true);
		const { activated, firstActivation } = installDemoLinkExtension();
		await mode.init({ suppressWelcomeIntro: true });
		void mode.getUserInput();
		await term.waitForRender();

		const tool = new ToolExecutionComponent(
			"bash",
			{ command: "scrolled_cmd" },
			{},
			undefined,
			{
				requestRender: () => mode.ui.requestRender(),
				requestComponentRender: () => {},
				resetDisplay: () => {},
			},
			tempDir.path(),
		);
		tool.updateResult(
			{ content: [{ type: "text", text: Array.from({ length: 12 }, (_, i) => `Scrolled bash ${i}`).join("\n") }] },
			false,
		);
		mode.chatContainer.addChild(tool);

		const asst = new AssistantMessageComponent();
		asst.updateContent({
			role: "assistant",
			content: [
				{ type: "thinking", thinking: "Scrolled thinking body 1\nScrolled thinking body 2" },
				{ type: "text", text: "Open [scrolled link](demo:scrolled/1) in answer" },
			],
			api: "anthropic-messages",
			provider: "anthropic",
			model: "m",
			usage: {
				input: 0,
				output: 0,
				cacheRead: 0,
				cacheWrite: 0,
				totalTokens: 0,
				cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
			},
			stopReason: "stop",
			timestamp: 1,
		});
		mode.chatContainer.addChild(asst);

		const card = new ToolExecutionComponent(
			"task",
			{},
			{},
			undefined,
			{
				requestRender: () => mode.ui.requestRender(),
				requestComponentRender: () => {},
				resetDisplay: () => {},
			},
			tempDir.path(),
		);
		card.updateResult(
			{
				content: [{ type: "text", text: "Running 1 agent..." }],
				details: {
					projectAgentsDir: null,
					results: [],
					totalDurationMs: 1,
					progress: [
						{
							index: 0,
							id: "ScrolledWorker",
							agent: "task",
							agentSource: "bundled",
							status: "running",
							task: "scrolled hover work",
							recentTools: [],
							recentOutput: [],
							toolCount: 1,
							requests: 1,
							tokens: 0,
							cost: 0,
							durationMs: 0,
						},
					],
				},
			},
			true,
		);
		mode.chatContainer.addChild(card);

		for (let i = 0; i < 40; i++) {
			mode.chatContainer.addChild(new Text(`FILLER-${String(i).padStart(2, "0")}`, 0, 0));
		}
		mode.ui.requestRender();
		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes("FILLER-39")));
		expect(plainRows(term.getViewport()).some(row => row.includes("ScrolledWorker"))).toBe(false);

		// Scroll up to bring tool, thinking/link, and task card into the viewport
		mode.composer.scrollTranscript(-90);
		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes("ScrolledWorker")));
		const anchorBefore = plainRows(term.getViewport())[0];

		// With default tui.mouse=false, clicking the scrolled tool header does not expand
		const toolRowDisabled = plainRows(term.getViewport()).findIndex(row => row.includes("Bash"));
		expect(toolRowDisabled).toBeGreaterThanOrEqual(0);
		term.sendInput(`\x1b[<0;5;${toolRowDisabled + 1}M`);
		await term.waitForRender();
		expect(tool.expanded).toBe(false);

		// Enable tui.mouse: scrolled tool and thinking headers expand and collapse while preserving top anchor
		cfgTuiMouse.set(mode.settings, true);
		mode.ui.requestRender();
		await term.waitForRender();

		const clickVisible = async (marker: string): Promise<void> => {
			const rows = plainRows(term.getViewport());
			const row = rows.findIndex(line => line.includes(marker));
			expect(row).toBeGreaterThanOrEqual(0);
			term.sendInput(`\x1b[<0;5;${row + 1}M`);
			mode.ui.renderNow();
		};

		await clickVisible("Bash");
		await term.waitForRender(() => tool.expanded === true);
		expect(plainRows(term.getViewport()).some(row => row.includes("Scrolled bash 11"))).toBe(true);
		expect(plainRows(term.getViewport())[0]).toBe(anchorBefore);

		await clickVisible("Bash");
		await term.waitForRender(() => tool.expanded === false);
		expect(plainRows(term.getViewport())[0]).toBe(anchorBefore);

		await clickVisible("Thought");
		await term.waitForRender(() =>
			plainRows(term.getViewport()).some(row => row.includes("Scrolled thinking body 1")),
		);
		await clickVisible("Thought");
		await term.waitForRender(
			() => !plainRows(term.getViewport()).some(row => row.includes("Scrolled thinking body 1")),
		);
		expect(plainRows(term.getViewport())[0]).toBe(anchorBefore);

		// Hovering ScrolledWorker bands its current row, and scrolling clears stale hover state
		mode.composer.scrollTranscript(12);
		mode.ui.renderNow();
		const workerRow = plainRows(term.getViewport()).findIndex(row => row.includes("ScrolledWorker"));
		expect(workerRow).toBeGreaterThanOrEqual(0);
		const bgBefore = term.getViewportRowBackgroundValues(workerRow);
		term.sendInput(`\x1b[<32;5;${workerRow + 1}M`);
		await term.waitForRender(
			() => JSON.stringify(term.getViewportRowBackgroundValues(workerRow)) !== JSON.stringify(bgBefore),
		);
		mode.composer.scrollTranscript(3);
		await term.waitForRender(
			() => plainRows(term.getViewport()).findIndex(row => row.includes("ScrolledWorker")) !== workerRow,
		);
		const movedWorkerRow = plainRows(term.getViewport()).findIndex(row => row.includes("ScrolledWorker"));
		expect(movedWorkerRow).toBeGreaterThanOrEqual(0);
		expect(term.getViewportRowBackgroundValues(movedWorkerRow)).toEqual(bgBefore);

		// Link hints and link clicks use post-scroll coordinates, and scrolling cancels active hints if targets change
		mode.keybindings.setUserBindings({ "app.links.hint": "alt+k" });
		term.sendInput("\x1bk");
		await term.waitForRender(() => mode.linkHintsActive);
		mode.composer.scrollTranscript(80);
		await term.waitForRender(() => !mode.linkHintsActive);
		expect(mode.linkHintsActive).toBe(false);

		mode.composer.scrollTranscript(-80);
		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes("scrolled link")));
		const linkViewport = plainRows(term.getViewport());
		const linkRow = linkViewport.findIndex(row => row.includes("scrolled link"));
		expect(linkRow).toBeGreaterThanOrEqual(0);
		term.sendInput(`\x1b[<0;${linkViewport[linkRow]!.indexOf("scrolled link") + 2};${linkRow + 1}M`);
		await firstActivation;
		expect(activated).toEqual(["demo:scrolled/1"]);
	});
});
