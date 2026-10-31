import { beforeAll, describe, expect, it } from "bun:test";
import type { AssistantMessage } from "@reverse/ai";
import { type Component, Container, Text } from "@reverse/tui";
import { AssistantMessageComponent } from "@reverse/tui/chat/assistant-message";
import { TranscriptContainer } from "@reverse/tui/chrome/transcript-container";
import { COMPOSER_DEFAULTS, Composer } from "@reverse/tui/prompt/composer";
import { initTheme } from "@reverse/tui/theme";
import { withoutTerminalMultiplexer } from "./helpers/terminal-multiplexer";
import { VirtualRenderScheduler } from "./virtual-render-scheduler";
import { VirtualTerminal } from "./virtual-terminal";

withoutTerminalMultiplexer();

const COLUMNS = 120;
const REPLY_LINES = 150;

/** Turn chrome (status, loader, HUD) that outlives the turn, taller than the idle chrome at startup. */
class TurnChrome implements Component {
	rows = 0;
	render(): readonly string[] {
		return Array.from({ length: this.rows }, (_, i) => `Turn chrome row ${i}`);
	}
}

function reply(text: string): AssistantMessage {
	return {
		role: "assistant",
		content: [{ type: "text", text }],
		api: "openai-codex-responses",
		provider: "openai-codex",
		model: "gpt-5.6-sol",
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
	};
}

beforeAll(async () => {
	await initTheme();
});

/** Read the full conversation through the actual bounded viewport, then restore follow-tail. */
async function browse(
	composer: Composer,
	scheduler: VirtualRenderScheduler,
	terminal: VirtualTerminal,
): Promise<string[]> {
	const seen = new Map<number, string>();
	for (let page = 0; page < REPLY_LINES * 2; page++) {
		for (const row of terminal.getViewport()) {
			const text = Bun.stripANSI(row).trim();
			const token = /QZ[ISC](\d{3})/.exec(text);
			if (token) seen.set(Number(token[1]), text);
		}
		if (seen.size === REPLY_LINES) break;
		composer.scrollTranscript(-Math.max(1, composer.transcriptViewportHeight - 1));
		await scheduler.settle(terminal);
	}
	composer.scrollTranscriptToBottom();
	await scheduler.settle(terminal);
	return [...seen].sort(([a], [b]) => a - b).map(([, text]) => text);
}

describe("transcript rows under chrome that outlives the turn", () => {
	for (const rows of [24, 45]) {
		it(`keeps every line of a long streamed answer at ${rows} rows`, async () => {
			const terminal = new VirtualTerminal(COLUMNS, rows);
			const scheduler = new VirtualRenderScheduler();
			const composer = new Composer({
				terminal,
				tuiOptions: { renderScheduler: scheduler },
				preferences: { ...COMPOSER_DEFAULTS, quiet: true },
			});
			const transcript = new TranscriptContainer();
			const chrome = new TurnChrome();
			const editor = new Container();
			editor.addChild(new Text("EDITOR", 0, 0));
			composer.setRuntimeChildren([transcript, chrome, editor]);
			composer.start({ playWelcomeIntro: false });
			await scheduler.settle(terminal);

			const message = new AssistantMessageComponent();
			transcript.addChild(message);
			chrome.rows = 7;
			const lines = Array.from(
				{ length: REPLY_LINES },
				(_, i) => `QZC${String(i + 1).padStart(3, "0")} alpha bravo`,
			);
			for (let n = 1; n <= lines.length; n++) {
				message.updateContent(reply(lines.slice(0, n).join("\n\n")), { transient: true });
				composer.ui.requestRender();
				await scheduler.settle(terminal);
			}
			message.updateContent(reply(lines.join("\n\n")));
			message.markTranscriptBlockFinalized();
			composer.ui.requestRender();
			await scheduler.settle(terminal);
			expect(await browse(composer, scheduler, terminal)).toEqual(lines);
			composer.stop();
		});
	}

	for (const mounting of ["initial mount", "runtime remount"] as const) {
		it(`keeps restored transcript and shell history reachable when idle chrome grows after ${mounting} without a new run`, async () => {
			const rows = 30;
			const shell = Array.from({ length: 12 }, (_, i) => `shell${i}`);
			const terminal = new VirtualTerminal(COLUMNS, rows);
			terminal.write(`${shell.join("\r\n")}${"\r\n".repeat(rows + 1)}`);
			const scheduler = new VirtualRenderScheduler();
			const composer = new Composer({
				terminal,
				tuiOptions: { renderScheduler: scheduler },
				preferences: { ...COMPOSER_DEFAULTS, quiet: true },
			});
			const transcript = new TranscriptContainer();
			const lines = Array.from(
				{ length: REPLY_LINES },
				(_, i) => `QZI${String(i + 1).padStart(3, "0")} alpha bravo`,
			);
			const message = new AssistantMessageComponent();
			message.updateContent(reply(lines.join("\n\n")));
			message.markTranscriptBlockFinalized();
			transcript.addChild(message);
			const chrome = new TurnChrome();
			const editor = new Container();
			editor.addChild(new Text("EDITOR", 0, 0));
			composer.setRuntimeChildren([transcript, chrome, editor]);
			composer.start({ playWelcomeIntro: false });
			try {
				await scheduler.advance(terminal, 300);
				if (mounting === "runtime remount") {
					// Remounting roots keeps the same conversation and browsing state.
					composer.setRuntimeChildren([transcript, chrome, editor]);
					await scheduler.advance(terminal, 300);
				}
				expect(await browse(composer, scheduler, terminal)).toEqual(lines);
				chrome.rows = 7;
				composer.ui.requestRender();
				await scheduler.advance(terminal, 300);
				expect(await browse(composer, scheduler, terminal)).toEqual(lines);
				expect(
					terminal
						.getViewport()
						.map(row => Bun.stripANSI(row).trim())
						.filter(row => row.startsWith("Turn chrome row ")),
				).toEqual(Array.from({ length: 7 }, (_, i) => `Turn chrome row ${i}`));

				chrome.rows = 0;
				composer.ui.requestRender();
				await scheduler.advance(terminal, 300);
				const editorRow = terminal.getViewport().findIndex(row => row.includes("EDITOR"));
				expect(editorRow).toBe(rows - 1);
				expect(await browse(composer, scheduler, terminal)).toEqual(lines);
			} finally {
				composer.stop();
				await terminal.flush();
				expect(
					terminal
						.getScrollBuffer()
						.map(row => Bun.stripANSI(row).trim())
						.filter(row => /^shell\d+$/.test(row)),
				).toEqual(shell);
			}
		});
	}

	/** Stream {@link REPLY_LINES} lines under 7 rows of persistent chrome, then let the idle chrome settle. */
	async function streamUnderChrome(composer: Composer, scheduler: VirtualRenderScheduler, terminal: VirtualTerminal) {
		const transcript = new TranscriptContainer();
		const chrome = new TurnChrome();
		const editorRoot = new Container();
		editorRoot.addChild(composer.editor);
		composer.setRuntimeChildren([transcript, chrome, editorRoot]);
		await scheduler.settle(terminal);
		return async (beforeStream?: () => Promise<void>): Promise<string[]> => {
			await beforeStream?.();
			const message = new AssistantMessageComponent();
			transcript.addChild(message);
			chrome.rows = 7;
			const lines = Array.from({ length: REPLY_LINES }, (_, i) => `QZS${String(i + 1).padStart(3, "0")}`);
			for (let n = 1; n <= lines.length; n++) {
				message.updateContent(reply(lines.slice(0, n).join("\n\n")), { transient: true });
				composer.ui.requestRender();
				await scheduler.settle(terminal);
			}
			message.updateContent(reply(lines.join("\n\n")));
			message.markTranscriptBlockFinalized();
			composer.ui.requestRender();
			await scheduler.settle(terminal);
			const seen = new Set((await browse(composer, scheduler, terminal)).map(row => /QZS\d{3}/.exec(row)?.[0]));
			return lines.filter(line => !seen.has(line));
		};
	}

	it("keeps every line when the runtime composer shape is taller than the prepaint shape", async () => {
		const terminal = new VirtualTerminal(COLUMNS, 24);
		const scheduler = new VirtualRenderScheduler();
		const composer = new Composer({
			terminal,
			tuiOptions: { renderScheduler: scheduler },
			preferences: { ...COMPOSER_DEFAULTS, quiet: true, composerShape: "band" },
		});
		composer.start({ playWelcomeIntro: false });
		try {
			// The bootstrap frame paints the cached 2-row band; settings then resolve to the 3-row pi shape.
			await scheduler.settle(terminal);
			composer.editor.setBorderStyle("pi");
			const run = await streamUnderChrome(composer, scheduler, terminal);
			expect(await run()).toEqual([]);
		} finally {
			composer.stop();
		}
	});

	it("keeps every line after the composer shape grows mid-session", async () => {
		const terminal = new VirtualTerminal(COLUMNS, 24);
		const scheduler = new VirtualRenderScheduler();
		const composer = new Composer({
			terminal,
			tuiOptions: { renderScheduler: scheduler },
			preferences: { ...COMPOSER_DEFAULTS, quiet: true, composerShape: "band" },
		});
		composer.start({ playWelcomeIntro: false });
		try {
			await scheduler.settle(terminal);
			const run = await streamUnderChrome(composer, scheduler, terminal);
			const missing = await run(async () => {
				composer.setPreferences({ composerShape: "pi" });
				composer.ui.requestRender();
				await scheduler.settle(terminal);
			});
			expect(missing).toEqual([]);
		} finally {
			composer.stop();
		}
	});
});
