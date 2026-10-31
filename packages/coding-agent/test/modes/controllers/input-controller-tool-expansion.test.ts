import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "bun:test";
import type { AssistantMessage } from "@reverse/ai";
import { resetSettingsForTest, Settings } from "@reverse/coding-agent/config/settings";
import { InputController } from "@reverse/coding-agent/modes/controllers/input-controller";
import { cfgDisplayHideToolActivity } from "@reverse/coding-agent/modes/settings";
import type { InteractiveModeContext } from "@reverse/coding-agent/modes/types";
import { Container } from "@reverse/tui";
import { AssistantMessageComponent } from "@reverse/tui/chat/assistant-message";
import { ReadToolGroupComponent } from "@reverse/tui/chat/read-tool-group";
import { TranscriptContainer } from "@reverse/tui/chrome/transcript-container";
import { Composer } from "@reverse/tui/prompt/composer";
import { initTheme } from "@reverse/tui/theme";
import { withoutTerminalMultiplexer } from "../../../../tui/test/helpers/terminal-multiplexer";
import { VirtualRenderScheduler } from "../../../../tui/test/virtual-render-scheduler";
import { VirtualTerminal } from "../../../../tui/test/virtual-terminal";

const PENDING_USER_TEXT = "User: please inspect kernel-module.c";
const THINKING_SECRET = "REASONING_PROVABLY_SECRET_INTERNAL_STEPS";
const ANSWER_TEXT = "FINAL_ANSWER_SUMMARY_HEAD";
const READ_PATH = "/tmp/project/kernel-module.c";
const READ_BODY = "int main() { return 0; }";
const TAIL_FILLER = "Filler line 14 for viewport history pressure";

withoutTerminalMultiplexer();

describe("InputController transcript expansion and tool activity visibility", () => {
	beforeAll(async () => {
		await initTheme(false);
	});

	beforeEach(async () => {
		resetSettingsForTest();
		await Settings.init({ inMemory: true });
	});

	afterEach(() => {
		resetSettingsForTest();
		vi.restoreAllMocks();
	});

	it("drives expansion -> collapse -> hide -> show across full Composer-scrolled VT history without leaking or leaving stale state", async () => {
		const term = new VirtualTerminal(100, 10);
		const scheduler = new VirtualRenderScheduler();
		const composer = new Composer({
			terminal: term,
			tuiOptions: { renderScheduler: scheduler },
			preferences: { quiet: true },
		});
		const chatContainer = new TranscriptContainer();
		const editorContainer = new Container();
		editorContainer.addChild(composer.editor);
		composer.setRuntimeChildren([chatContainer, editorContainer]);
		composer.start({ playWelcomeIntro: false });

		try {
			const pendingUserMessage = {
				kind: "pending-user",
				render: () => [PENDING_USER_TEXT],
			};

			const assistantMsg: AssistantMessage = {
				role: "assistant",
				content: [
					{ type: "thinking", thinking: THINKING_SECRET },
					{ type: "text", text: ANSWER_TEXT },
				],
				api: "anthropic-messages",
				provider: "anthropic",
				model: "claude-sonnet-4-5",
				usage: {
					input: 0,
					output: 0,
					cacheRead: 0,
					cacheWrite: 0,
					totalTokens: 0,
					cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
				},
				stopReason: "stop",
				timestamp: 100,
			};
			const assistantComp = new AssistantMessageComponent();
			assistantComp.updateContent(assistantMsg);
			assistantComp.markTranscriptBlockFinalized();

			const readGroup = new ReadToolGroupComponent();
			readGroup.updateArgs({ path: READ_PATH }, "read-call-1");
			readGroup.updateResult({ content: [{ type: "text", text: READ_BODY }] }, false, "read-call-1");
			readGroup.finalize();

			chatContainer.addChild(pendingUserMessage);
			chatContainer.addChild(assistantComp);
			chatContainer.addChild(readGroup);

			for (let i = 0; i < 15; i++) {
				const filler = {
					render: () => [`Filler line ${i} for viewport history pressure`],
					isTranscriptBlockFinalized: () => true,
				};
				chatContainer.addChild(filler);
			}

			composer.ui.requestRender(true);
			await scheduler.settle(term);

			const viewportText = () =>
				term
					.getViewport()
					.map(row => Bun.stripANSI(row).trimEnd())
					.join("\n");

			const browseHistoryText = async (): Promise<string> => {
				composer.scrollTranscript(-10_000);
				await scheduler.settle(term);

				const pages: string[] = [viewportText()];
				for (let page = 0; page < 50; page++) {
					const step = Math.max(1, composer.transcriptViewportHeight);
					composer.scrollTranscript(step);
					await scheduler.settle(term);
					const next = viewportText();
					if (next === pages.at(-1)) break;
					pages.push(next);
				}

				expect(pages.length).toBeGreaterThan(1);
				expect(term.getBufferPosition().baseY).toBe(0);
				expect(pages.at(-1)).toContain(TAIL_FILLER);
				return pages.join("\n");
			};

			// Initial tail state: fullscreen Composer emits no native scrollback and early blocks sit above the tail window.
			expect(term.getBufferPosition().baseY).toBe(0);
			expect(viewportText()).toContain(TAIL_FILLER);
			expect(viewportText()).not.toContain(PENDING_USER_TEXT);
			expect(viewportText()).not.toContain(ANSWER_TEXT);
			expect(viewportText()).not.toContain(READ_PATH);
			expect(viewportText()).not.toContain(THINKING_SECRET);

			// Initial browsed history: assistant answer and read path reachable via Composer scrolling; thinking and read body collapsed.
			const initialHistory = await browseHistoryText();
			expect(initialHistory).toContain(PENDING_USER_TEXT);
			expect(initialHistory).toContain(ANSWER_TEXT);
			expect(initialHistory).toContain(READ_PATH);
			expect(initialHistory).not.toContain(READ_BODY);
			expect(initialHistory).not.toContain(THINKING_SECRET);

			const settings = Settings.isolated();
			const showStatus = vi.fn();
			const ctx = {
				settings,
				toolOutputExpanded: false,
				hideToolActivity: false,
				chatContainer,
				ui: composer.ui,
				showStatus,
			} as unknown as InteractiveModeContext;
			const controller = new InputController(ctx);

			// 1. Expansion while scrolled to top: repaints browsed VT viewport in place without jumping to tail, and expands across full history.
			composer.scrollTranscript(-10_000);
			await scheduler.settle(term);
			expect(viewportText()).toContain(PENDING_USER_TEXT);
			expect(viewportText()).not.toContain(THINKING_SECRET);

			controller.toggleToolOutputExpansion();
			await scheduler.settle(term);
			expect(ctx.toolOutputExpanded).toBe(true);
			expect(showStatus).toHaveBeenLastCalledWith("Transcript details: expanded");
			expect(viewportText()).toContain(PENDING_USER_TEXT);
			expect(viewportText()).toContain(THINKING_SECRET);
			expect(viewportText()).not.toContain(TAIL_FILLER);

			const expandedHistory = await browseHistoryText();
			expect(expandedHistory).toContain(THINKING_SECRET);
			expect(expandedHistory).toContain(ANSWER_TEXT);
			expect(expandedHistory).toContain(READ_PATH);
			expect(expandedHistory).toContain(READ_BODY);

			// 2. Collapse: hides thinking and read body details again across all browsed pages.
			controller.toggleToolOutputExpansion();
			await scheduler.settle(term);
			expect(ctx.toolOutputExpanded).toBe(false);
			expect(showStatus).toHaveBeenLastCalledWith("Transcript details: collapsed");
			const collapsedHistory = await browseHistoryText();
			expect(collapsedHistory).not.toContain(THINKING_SECRET);
			expect(collapsedHistory).toContain(ANSWER_TEXT);
			expect(collapsedHistory).toContain(READ_PATH);
			expect(collapsedHistory).not.toContain(READ_BODY);

			// 3. Hide tool activity: tool activity disappears across the entire browsed VT history without leaks.
			controller.toggleToolActivityVisibility();
			await scheduler.settle(term);
			expect(ctx.hideToolActivity).toBe(true);
			expect(cfgDisplayHideToolActivity.get(settings)).toBe(true);
			expect(showStatus).toHaveBeenLastCalledWith("Tool activity: hidden");
			const hiddenToolsHistory = await browseHistoryText();
			expect(hiddenToolsHistory).toContain(PENDING_USER_TEXT);
			expect(hiddenToolsHistory).toContain(ANSWER_TEXT);
			expect(hiddenToolsHistory).not.toContain(READ_PATH);
			expect(hiddenToolsHistory).not.toContain(READ_BODY);
			expect(hiddenToolsHistory).not.toContain(THINKING_SECRET);

			// 4. Expand while tools are hidden: hidden tools stay hidden while thinking expands.
			controller.toggleToolOutputExpansion();
			await scheduler.settle(term);
			expect(ctx.toolOutputExpanded).toBe(true);
			expect(showStatus).toHaveBeenLastCalledWith("Transcript details: expanded");
			const expandedWhileHiddenHistory = await browseHistoryText();
			expect(expandedWhileHiddenHistory).not.toContain(READ_PATH);
			expect(expandedWhileHiddenHistory).not.toContain(READ_BODY);
			expect(expandedWhileHiddenHistory).toContain(THINKING_SECRET);
			expect(expandedWhileHiddenHistory).toContain(ANSWER_TEXT);

			// 5. Show tool activity: tools restored, resetting expansion on ALL expandable children (no stale thinking or read expansion).
			controller.toggleToolActivityVisibility();
			await scheduler.settle(term);
			expect(ctx.hideToolActivity).toBe(false);
			expect(ctx.toolOutputExpanded).toBe(false);
			expect(cfgDisplayHideToolActivity.get(settings)).toBe(false);
			expect(showStatus).toHaveBeenLastCalledWith("Tool activity: visible");
			const restoredHistory = await browseHistoryText();
			expect(restoredHistory).toContain(PENDING_USER_TEXT);
			expect(restoredHistory).toContain(ANSWER_TEXT);
			expect(restoredHistory).toContain(READ_PATH);
			expect(restoredHistory).not.toContain(READ_BODY);
			expect(restoredHistory).not.toContain(THINKING_SECRET);

			composer.scrollTranscript(-10_000);
			await scheduler.settle(term);
			expect(viewportText()).toContain(PENDING_USER_TEXT);
			composer.scrollTranscriptToBottom();
			await scheduler.settle(term);
			expect(viewportText()).toContain(TAIL_FILLER);
			expect(viewportText()).not.toContain(PENDING_USER_TEXT);

			// 6. Live objects and pending messages preserved throughout.
			expect(chatContainer.children[0]).toBe(pendingUserMessage);
			expect(chatContainer.children[1]).toBe(assistantComp);
			expect(chatContainer.children[2]).toBe(readGroup);
		} finally {
			composer.stop();
		}
	});
});
