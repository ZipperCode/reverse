import { afterEach, beforeAll, expect, it, vi } from "bun:test";
import { Composer } from "@reverse/tui/prompt/composer";
import { TranscriptContainer } from "@reverse/tui/chrome/transcript-container";
import { initTheme } from "@reverse/tui/theme";
import { Text } from "@reverse/tui";
import { VirtualRenderScheduler } from "./virtual-render-scheduler";
import { VirtualTerminal } from "./virtual-terminal";
import { withoutTerminalMultiplexer } from "./helpers/terminal-multiplexer";

withoutTerminalMultiplexer();
beforeAll(async () => {
	await initTheme();
});

afterEach(() => {
	vi.restoreAllMocks();
	vi.useRealTimers();
});
it("keeps an oversized startup changelog reachable above the fixed editor after the intro", async () => {
	const terminal = new VirtualTerminal(100, 30);
	vi.useFakeTimers();
	let now = 0;
	vi.spyOn(performance, "now").mockImplementation(() => now);
	const scheduler = new VirtualRenderScheduler();
	const composer = new Composer({
		terminal,
		tuiOptions: { renderScheduler: scheduler },
		preferences: { spellingTypoDetection: false, spellingAutocomplete: "off", spellingAutocorrect: false },
	});
	const entries = Array.from({ length: 60 }, (_, i) => `Changelog entry ${i}`);
	composer.setHeaderExtras([], [new Text(entries.join("\n"), 0, 0)]);
	composer.setRuntimeChildren([new TranscriptContainer(), new Text("EDITOR", 0, 0)]);
	composer.start();
	try {
		await scheduler.settle(terminal);
		// Complete the intro with no key or unrelated render to rescue its
		// completion frame.
		now = 3200;
		vi.advanceTimersByTime(33);
		await scheduler.settle(terminal);
		const seen = new Set<string>();
		for (let page = 0; page < 5; page++) {
			for (const row of terminal.getViewport()) {
				const text = Bun.stripANSI(row).trimEnd();
				if (text.startsWith("Changelog entry ")) seen.add(text);
			}
			composer.scrollTranscript(-25);
			await scheduler.settle(terminal);
		}
		expect([...seen].sort((a, b) => Number(a.slice(16)) - Number(b.slice(16)))).toEqual(entries);
		expect(terminal.getViewport().at(-1)?.trimEnd()).toBe("EDITOR");
	} finally {
		composer.stop();
	}
});
