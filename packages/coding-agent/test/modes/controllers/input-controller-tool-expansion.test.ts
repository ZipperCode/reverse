import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "bun:test";
import type { AssistantMessage } from "@reverse/ai";
import { resetSettingsForTest, Settings } from "@reverse/coding-agent/config/settings";
import { InputController } from "@reverse/coding-agent/modes/controllers/input-controller";
import { cfgDisplayHideToolActivity } from "@reverse/coding-agent/modes/settings";
import type { InteractiveModeContext } from "@reverse/coding-agent/modes/types";
import { AssistantMessageComponent } from "@reverse/tui/chat/assistant-message";
import { ReadToolGroupComponent } from "@reverse/tui/chat/read-tool-group";
import { TranscriptContainer } from "@reverse/tui/chrome/transcript-container";
import { Composer } from "@reverse/tui/prompt/composer";
import { initTheme } from "@reverse/tui/theme";
import { VirtualTerminal } from "../../../../tui/test/virtual-terminal";

const THINKING_SECRET = "REASONING_PROVABLY_SECRET_INTERNAL_STEPS";
const ANSWER_TEXT = "FINAL_ANSWER_SUMMARY_HEAD";
const READ_PATH = "/tmp/project/kernel-module.c";

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

	it("drives expansion -> collapse -> hide -> show over genuine retired scrollback history without leaking or leaving stale state", async () => {
		const term = new VirtualTerminal(100, 10);
		const composer = new Composer({ terminal: term });
		const chatContainer = new TranscriptContainer();
		composer.setRuntimeChildren([chatContainer]);
		composer.start({ playWelcomeIntro: false });

		const pendingUserMessage = {
			kind: "pending-user",
			render: () => ["User: please inspect kernel-module.c"],
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
		readGroup.updateResult({ content: [{ type: "text", text: "int main() { return 0; }" }] }, false, "read-call-1");
		readGroup.finalize();

		chatContainer.addChild(pendingUserMessage);
		chatContainer.addChild(assistantComp);
		chatContainer.addChild(readGroup);

		for (let i = 0; i < 15; i++) {
			const filler = {
				render: () => [`Filler line ${i} for scrollback pressure`],
				isTranscriptBlockFinalized: () => true,
			};
			chatContainer.addChild(filler);
		}

		// Drive frames under row capacity pressure until the top blocks retire to scrollback.
		for (let i = 0; i < 20 && term.getBufferPosition().baseY === 0; i++) {
			composer.ui.requestRender(true);
			await term.waitForRender();
		}
		expect(term.getBufferPosition().baseY).toBeGreaterThan(0);

		const committedText = () =>
			term
				.getScrollBuffer()
				.slice(0, term.getBufferPosition().baseY)
				.map(row => Bun.stripANSI(row).trimEnd())
				.join("\n");
		const allBufferText = () =>
			term
				.getScrollBuffer()
				.map(row => Bun.stripANSI(row).trimEnd())
				.join("\n");

		// Initial state: assistant answer and read path retired; thinking is collapsed.
		expect(committedText()).toContain(ANSWER_TEXT);
		expect(allBufferText()).toContain(READ_PATH);
		expect(allBufferText()).not.toContain(THINKING_SECRET);

		const settings = Settings.isolated();
		const showStatus = vi.fn();
		const clearInlineImages = vi.fn();
		const ctx = {
			settings,
			toolOutputExpanded: false,
			hideToolActivity: false,
			chatContainer,
			ui: composer.ui,
			showStatus,
			clearInlineImages,
		} as unknown as InteractiveModeContext;
		const controller = new InputController(ctx);

		// 1. Expansion: reveals thinking details in retired history.
		controller.toggleToolOutputExpansion();
		await term.waitForRender();
		expect(ctx.toolOutputExpanded).toBe(true);
		expect(showStatus).toHaveBeenLastCalledWith("Transcript details: expanded");
		expect(allBufferText()).toContain(THINKING_SECRET);
		expect(allBufferText()).toContain(READ_PATH);

		// 2. Collapse: hides thinking details again.
		controller.toggleToolOutputExpansion();
		await term.waitForRender();
		expect(ctx.toolOutputExpanded).toBe(false);
		expect(showStatus).toHaveBeenLastCalledWith("Transcript details: collapsed");
		expect(allBufferText()).not.toContain(THINKING_SECRET);
		expect(allBufferText()).toContain(READ_PATH);

		// 3. Hide tool activity: tool activity disappears from scrollback and viewport without leaks.
		controller.toggleToolActivityVisibility();
		await term.waitForRender();
		expect(ctx.hideToolActivity).toBe(true);
		expect(cfgDisplayHideToolActivity.get(settings)).toBe(true);
		expect(showStatus).toHaveBeenLastCalledWith("Tool activity: hidden");
		expect(allBufferText()).not.toContain(READ_PATH);
		expect(allBufferText()).not.toContain(THINKING_SECRET);

		// 4. Expand while tools are hidden: hidden tools stay hidden, thinking expands.
		controller.toggleToolOutputExpansion();
		await term.waitForRender();
		expect(ctx.toolOutputExpanded).toBe(true);
		expect(showStatus).toHaveBeenLastCalledWith("Transcript details: expanded");
		expect(allBufferText()).not.toContain(READ_PATH);
		expect(allBufferText()).toContain(THINKING_SECRET);

		// 5. Show tool activity: tools restored, resetting expansion on ALL expandable children (no stale thinking expansion).
		controller.toggleToolActivityVisibility();
		await term.waitForRender();
		expect(ctx.hideToolActivity).toBe(false);
		expect(ctx.toolOutputExpanded).toBe(false);
		expect(cfgDisplayHideToolActivity.get(settings)).toBe(false);
		expect(showStatus).toHaveBeenLastCalledWith("Tool activity: visible");
		expect(allBufferText()).toContain(READ_PATH);
		expect(allBufferText()).not.toContain(THINKING_SECRET);

		// 6. Live objects and pending messages preserved throughout.
		expect(chatContainer.children[0]).toBe(pendingUserMessage);
		expect(chatContainer.children[1]).toBe(assistantComp);
		expect(chatContainer.children[2]).toBe(readGroup);

		composer.stop();
	});
});
