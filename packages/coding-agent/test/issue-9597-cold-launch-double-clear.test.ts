import { afterEach, beforeEach, describe, expect, it, vi } from "bun:test";
import { resetSettingsForTest, Settings } from "@reverse/coding-agent/config/settings";
import type { ComposerPreferences } from "@reverse/tui/prompt/composer";
import { InteractiveMode } from "@reverse/coding-agent/modes/interactive-mode";
import {
	beginStartupComposer,
	stopPendingStartupComposer,
	takeStartupComposerLease,
} from "@reverse/coding-agent/modes/startup-composer";
import { initTheme } from "@reverse/tui/theme";
import { VirtualTerminal } from "../../tui/test/virtual-terminal";
import { assistantMsg, createTestSession, userMsg } from "./utilities";

import {
	cfgAutocompleteMaxVisible,
	cfgComposerShape,
	cfgShowHardwareCursor,
	cfgSpellingAutocomplete,
	cfgSpellingAutocorrect,
	cfgSpellingTypoDetection,
	cfgStartupQuiet,
	cfgTuiImeSafeCursor,
	cfgTuiMaxInlineImages,
} from "@reverse/coding-agent/modes/settings";

// Fullscreen startup/reset must leave shell scrollback untouched.
const ERASE_SCROLLBACK = "\x1b[3J";

/** VirtualTerminal that also records every raw byte the TUI writes. */
class CapturingTerminal extends VirtualTerminal {
	readonly raw: string[] = [];
	override write(data: string): void {
		this.raw.push(data);
		super.write(data);
	}
	countResets(): number {
		const all = this.raw.join("");
		let n = 0;
		for (let i = all.indexOf(ERASE_SCROLLBACK); i !== -1; i = all.indexOf(ERASE_SCROLLBACK, i + 1)) n++;
		return n;
	}
}

// Prepaint and session adoption share one owned screen without archiving welcome frames.
describe("issue #9597 — cold-launch welcome duplication", () => {
	let settings: Settings;
	let config: ComposerPreferences;

	beforeEach(async () => {
		resetSettingsForTest();
		await initTheme();
		settings = await Settings.init({ inMemory: true });
		config = {
			quiet: cfgStartupQuiet.get(settings),
			composerShape: cfgComposerShape.get(settings) ?? "box",
			showHardwareCursor: cfgShowHardwareCursor.get(settings),
			maxInlineImages: cfgTuiMaxInlineImages.get(settings),
			imeSafeCursor: cfgTuiImeSafeCursor.get(settings),
			autocompleteMaxVisible: cfgAutocompleteMaxVisible.get(settings),
			spellingTypoDetection: cfgSpellingTypoDetection.get(settings),
			spellingAutocomplete: cfgSpellingAutocomplete.get(settings),
			spellingAutocorrect: cfgSpellingAutocorrect.get(settings),
		};
	});

	afterEach(() => {
		stopPendingStartupComposer();
		resetSettingsForTest();
	});

	// `resuming` mirrors `main.ts` `runInteractiveMode`: `false` on a plain `reverse`
	// launch, `true` for --continue/--resume/--fork.
	async function coldLaunch(resuming: boolean): Promise<{
		resets: number;
		welcomeRows: number;
		scrollBuffer: string;
	}> {
		const terminal = new CapturingTerminal(100, 30);
		beginStartupComposer({
			preferences: config,
			terminal,
			version: "18.0.4",
			cache: false,
		});
		await terminal.waitForRender();
		const lease = takeStartupComposerLease();
		expect(lease).toBeDefined();
		const testSession = await createTestSession({ inMemory: true });
		if (resuming) {
			testSession.sessionManager.appendMessage(userMsg("resume marker question"));
			testSession.sessionManager.appendMessage(assistantMsg("resume marker answer"));
		}
		const mode = new InteractiveMode(
			testSession.session,
			"18.0.4",
			undefined,
			undefined,
			undefined,
			undefined,
			undefined,
			lease!.composer,
		);
		lease!.adopt();
		vi.spyOn(mode.statusLine, "watchBranch").mockImplementation(() => {});
		try {
			await mode.init({ suppressWelcomeIntro: resuming, clearInitialTerminalHistory: true });
			await terminal.waitForRender();
			await mode.renderInitialMessages({ preserveExistingChat: true });
			// Observe the actual adopted viewport, not normal-buffer history.
			await terminal.waitForRender(
				() =>
					!resuming || terminal.getViewport().some(line => Bun.stripANSI(line).includes("resume marker answer")),
			);
			const rows = terminal.getViewport().map(l => Bun.stripANSI(l));
			return {
				resets: terminal.countResets(),
				welcomeRows: rows.filter(l => l.includes("18.0.4")).length,
				scrollBuffer: rows.join("\n"),
			};
		} finally {
			mode.stop();
			await testSession.cleanup();
		}
	}

	it("preserves shell history on a fresh launch, leaving one welcome header", async () => {
		const { resets, welcomeRows } = await coldLaunch(false);
		expect(resets).toBe(0);
		expect(welcomeRows).toBe(1);
	});

	it("adopts a resumed transcript without clearing shell history", async () => {
		const { resets, scrollBuffer, welcomeRows } = await coldLaunch(true);
		expect(resets).toBe(0);
		expect(scrollBuffer).toContain("resume marker answer");
		expect(welcomeRows).toBe(1);
	});
});
