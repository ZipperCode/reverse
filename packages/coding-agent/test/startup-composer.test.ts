import { afterEach, beforeEach, describe, expect, it, vi } from "bun:test";
import * as path from "node:path";
import { parseArgs } from "@rva/coding-agent/cli/args";
import { KeybindingsManager } from "@rva/tui/app-keybindings";
import { ModelRegistry } from "@rva/coding-agent/config/model-registry";
import { getBundledModel } from "@rva/catalog/models";
import { resetSettingsForTest, Settings } from "@rva/coding-agent/config/settings";
import * as pluginHelpers from "@rva/coding-agent/discovery/helpers";
import { runRootCommand } from "@rva/coding-agent/main";
import { Composer, type ComposerPreferences } from "@rva/tui/prompt/composer";
import * as composerCache from "@rva/tui/prompt/composer-cache";
import { InteractiveMode } from "@rva/coding-agent/modes/interactive-mode";
import {
	applyStartupComposerPreferences,
	beginStartupComposer,
	ComposerLease,
	stopPendingStartupComposer,
	takeStartupComposerLease,
} from "@rva/coding-agent/modes/startup-composer";
import { initTheme } from "@rva/tui/theme";
import { AgentLifecycleManager } from "@rva/coding-agent/registry/agent-lifecycle";
import { AuthStorage } from "@rva/coding-agent/session/auth-storage";
import { getProjectDir, setProjectDir } from "@rva/utils";
import { VirtualTerminal } from "../../tui/test/virtual-terminal";
import { cfgTierOpenai } from "@rva/coding-agent/session/settings";
import { createTestSession } from "./utilities";

import {
	cfgAutocompleteMaxVisible,
	cfgComposerShape,
	cfgMarketplaceAutoUpdate,
	cfgShowHardwareCursor,
	cfgSpellingAutocomplete,
	cfgSpellingAutocorrect,
	cfgSpellingTypoDetection,
	cfgStartupChangelogMode,
	cfgStartupQuiet,
	cfgStartupSetupWizard,
	cfgStartupShowSplash,
	cfgTuiImeSafeCursor,
	cfgTuiMaxInlineImages,
	cfgTuiResizeScrollback,
} from "@rva/coding-agent/modes/settings";

class CountingTerminal extends VirtualTerminal {
	starts = 0;
	stops = 0;
	override start(onInput: (data: string) => void, onResize: () => void): void {
		this.starts += 1;
		super.start(onInput, onResize);
	}

	override stop(): void {
		this.stops += 1;
		super.stop();
	}
}

class WriteTrackingTerminal extends CountingTerminal {
	written = "";
	override write(data: string): void {
		this.written += data;
		super.write(data);
	}
}

class ThrowingStartTerminal extends CountingTerminal {
	override start(): void {
		this.starts += 1;
		throw new Error("terminal start failed");
	}
}
class InputTrackingTerminal extends CountingTerminal {
	startOptions: { deferInput?: boolean } | undefined;
	inputEnables = 0;
	override start(
		onInput: (data: string) => void,
		onResize: () => void,
		_onDisconnect?: () => void,
		options?: { deferInput?: boolean },
	): void {
		this.startOptions = options;
		super.start(onInput, onResize);
	}

	enableInput(): void {
		this.inputEnables += 1;
	}
}


describe("Composer prepaint", () => {
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
			resizeScrollback: cfgTuiResizeScrollback.get(settings),
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

	it.each([
		{ configured: "priority", sessionFast: false, cachedFast: true },
		{ configured: "none", sessionFast: true, cachedFast: false },
	] as const)(
		"prepaints fast mode from tier.openai=$configured, not a session-only /fast toggle",
		async ({ configured, sessionFast, cachedFast }) => {
			const testSession = await createTestSession();
			const cache = composerCache.ComposerCache.open(path.join(testSession.tempDir, "composer.db"));
			vi.spyOn(composerCache, "sharedComposerCache").mockReturnValue(cache);
			const anthropic = testSession.session.model;
			const openai = getBundledModel("openai", "gpt-5.2");
			if (!anthropic || !openai) throw new Error("Bundled test models missing");
			testSession.session.settings.setModelRole("default", `${openai.provider}/${openai.id}`);
			vi.spyOn(testSession.session.modelRegistry, "hasConfiguredAuth").mockReturnValue(true);
			vi.spyOn(testSession.session.modelRegistry, "getAvailable").mockReturnValue([openai, anthropic]);
			cfgTierOpenai.set(testSession.session.settings, configured);
			await testSession.session.setModel(openai);
			testSession.session.setFastMode(sessionFast);
			expect(testSession.session.isFastModeActive()).toBe(sessionFast);
			const composer = new Composer({ terminal: new VirtualTerminal() });
			composer.start();
			const mode = new InteractiveMode(
				testSession.session,
				"test",
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				composer,
			);
			vi.spyOn(mode.statusLine, "watchBranch").mockImplementation(() => {});
			try {
				await mode.init({ suppressWelcomeIntro: true });
				await testSession.session.setModel(anthropic);
				mode.stop();
				const status = cache.read(testSession.sessionManager.getCwd()).status?.statusLine;
				expect(status?.model?.id).toBe(openai.id);
				expect(status?.fastMode).toBe(cachedFast);
			} finally {
				mode.stop();
				cache.close();
				await testSession.cleanup();
				vi.restoreAllMocks();
			}
		},
	);

	it("keeps one live editor and terminal across handoff", () => {
		const terminal = new CountingTerminal();
		const composer = new Composer({ preferences: config, terminal });
		const submit = vi.fn();
		composer.editor.onSubmit = submit;

		composer.start();
		terminal.sendInput("alpha");
		terminal.sendInput("\r");

		expect(composer.editor.getExpandedText()).toBe("alpha");
		expect(submit).not.toHaveBeenCalled();
		expect(terminal.starts).toBe(1);

		composer.transfer();
		composer.stop();
		terminal.sendInput(" beta");

		expect(composer.editor.getExpandedText()).toBe("alpha beta");
		expect(terminal.starts).toBe(1);
		expect(terminal.stops).toBe(0);

		composer.ui.stop();
		expect(terminal.stops).toBe(1);
	});

	it("adopts the live draft with final theme, keybindings, and submit behavior", async () => {
		const terminal = new CountingTerminal();
		const composer = new Composer({ preferences: config, terminal });
		composer.start();
		terminal.sendInput("alpha ");
		terminal.sendInput("\x1b[200~one\ntwo\x1b[201~");
		terminal.sendInput(" omega");
		terminal.sendInput("\x1b[D");

		const expectedDraft = composer.editor.getExpandedText();
		const expectedCursor = composer.editor.getCursor();
		const lease = new ComposerLease(composer);
		const adoptedComposer = lease.composer;
		const testSession = await createTestSession({
			inMemory: true,
			settingsOverrides: { symbolPreset: "ascii" },
		});
		let mode: InteractiveMode | undefined;

		try {
			await initTheme(false, "ascii");
			cfgComposerShape.set(settings, "box");
			vi.spyOn(KeybindingsManager, "create").mockReturnValue(KeybindingsManager.inMemory({ "app.clear": "ctrl+x" }));
			mode = new InteractiveMode(
				testSession.session,
				"test",
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				adoptedComposer,
			);
			lease.adopt();
			vi.spyOn(mode.statusLine, "watchBranch").mockImplementation(() => {});

			expect(mode.ui).toBe(adoptedComposer.ui);
			expect(mode.editor).toBe(adoptedComposer.editor);
			await mode.init({ suppressWelcomeIntro: true });

			expect(mode.ui).toBe(adoptedComposer.ui);
			expect(mode.editor).toBe(adoptedComposer.editor);
			expect(mode.editor.getExpandedText()).toBe(expectedDraft);
			expect(mode.editor.getCursor()).toEqual(expectedCursor);
			expect(terminal.starts).toBe(1);
			const adoptedEditor = Bun.stripANSI(mode.editor.render(40).join("\n"));
			expect(adoptedEditor.startsWith("+")).toBe(true);
			expect(adoptedEditor).not.toContain("╭");

			terminal.sendInput("\x03");
			expect(mode.editor.getExpandedText()).toBe(expectedDraft);
			terminal.sendInput("\x18");
			expect(mode.editor.getExpandedText()).toBe("");
			expect(mode.editor.disableSubmit).toBe(false);
			terminal.sendInput("ready");
			expect(mode.editor.getExpandedText()).toBe("ready");

			const submitted = mode.getUserInput();
			expect(mode.editor.disableSubmit).toBe(false);
			terminal.sendInput("\r");
			expect(await submitted).toEqual(expect.objectContaining({ text: "ready" }));
			expect(mode.editor.getExpandedText()).toBe("");
			expect(terminal.starts).toBe(1);
		} finally {
			mode?.stop();
			await testSession.cleanup();
			vi.restoreAllMocks();
			await initTheme();
		}
	});

	it("keeps submit gated during initialization, then dispatches with steer", async () => {
		const terminal = new CountingTerminal();
		const composer = new Composer({ preferences: config, terminal });
		composer.start();
		const lease = new ComposerLease(composer);
		const testSession = await createTestSession({ inMemory: true });
		const mode = new InteractiveMode(
			testSession.session,
			"test",
			undefined,
			undefined,
			undefined,
			undefined,
			undefined,
			lease.composer,
		);
		lease.adopt();
		const enteredInit = Promise.withResolvers<void>();
		const releaseInit = Promise.withResolvers<void>();
		vi.spyOn(mode, "refreshSlashCommandState").mockImplementation(async () => {
			enteredInit.resolve();
			await releaseInit.promise;
		});
		vi.spyOn(mode.statusLine, "watchBranch").mockImplementation(() => {});
		const prompt = vi.spyOn(testSession.session, "prompt").mockResolvedValue(true);

		try {
			const initializing = mode.init({ suppressWelcomeIntro: true });
			await enteredInit.promise;
			terminal.sendInput("alpha");
			terminal.sendInput("\r");

			expect(prompt).not.toHaveBeenCalled();
			expect(mode.editor.getExpandedText()).toBe("alpha");
			expect(mode.editor.disableSubmit).toBe(true);

			releaseInit.resolve();
			await initializing;
			// Init wired the submit pipeline and lifted the gate: an Enter before
			// the input loop's first getUserInput dispatches directly with steer
			// instead of being silently dropped.
			expect(mode.editor.disableSubmit).toBe(false);
			terminal.sendInput("\r");
			for (let i = 0; i < 50 && prompt.mock.calls.length === 0; i++) await Promise.resolve();
			expect(prompt).toHaveBeenCalledWith("alpha", expect.objectContaining({ streamingBehavior: "steer" }));
			expect(mode.editor.getExpandedText()).toBe("");
		} finally {
			releaseInit.resolve();
			mode.stop();
			lease.dispose();
			await testSession.cleanup();
			vi.restoreAllMocks();
		}
	});

	it("turns kitty enhanced paste on when the interactive mode adopts an already started composer", async () => {
		// The prepaint composer starts the TUI before InteractiveMode wires the input
		// controller, so enhanced paste (ESC[?5522h) cannot wait for a start event.
		const terminal = new WriteTrackingTerminal();
		const composer = new Composer({ preferences: config, terminal });
		composer.start();
		const lease = new ComposerLease(composer);
		const testSession = await createTestSession({ inMemory: true });
		const mode = new InteractiveMode(
			testSession.session,
			"test",
			undefined,
			undefined,
			undefined,
			undefined,
			undefined,
			lease.composer,
		);
		lease.adopt();
		vi.spyOn(mode.statusLine, "watchBranch").mockImplementation(() => {});

		try {
			expect(terminal.written).not.toContain("\x1b[?5522h");
			await mode.init({ suppressWelcomeIntro: true });
			expect(terminal.written.split("\x1b[?5522h")).toHaveLength(2);
			expect(terminal.starts).toBe(1);
		} finally {
			mode.stop();
			lease.dispose();
			await testSession.cleanup();
			vi.restoreAllMocks();
		}
	});

	it("accepts input while the initial CLI prompt's first turn is still running", async () => {
		const terminal = new CountingTerminal();
		const composer = new Composer({ preferences: config, terminal });
		composer.start();
		const lease = new ComposerLease(composer);
		const testSession = await createTestSession({ inMemory: true });
		const mode = new InteractiveMode(
			testSession.session,
			"test",
			undefined,
			undefined,
			undefined,
			undefined,
			undefined,
			lease.composer,
		);
		lease.adopt();
		vi.spyOn(mode.statusLine, "watchBranch").mockImplementation(() => {});
		const turn = Promise.withResolvers<boolean>();
		const prompt = vi.spyOn(testSession.session, "prompt").mockResolvedValue(true);

		try {
			await mode.init({ suppressWelcomeIntro: true });

			// The `omp "prompt"` launch shape: the CLI message is dispatched after
			// init and its first turn is still in flight when the user types. The
			// input loop has not reached getUserInput yet.
			prompt.mockReturnValueOnce(turn.promise);
			const initialTurn = testSession.session.prompt("count to 25", { streamingBehavior: "steer" });

			terminal.sendInput("also add tests");
			terminal.sendInput("\r");
			for (let i = 0; i < 50 && prompt.mock.calls.length < 2; i++) await Promise.resolve();
			expect(prompt).toHaveBeenCalledWith("also add tests", expect.objectContaining({ streamingBehavior: "steer" }));
			expect(mode.editor.getExpandedText()).toBe("");

			turn.resolve(true);
			await initialTurn;
		} finally {
			mode.stop();
			lease.dispose();
			await testSession.cleanup();
			vi.restoreAllMocks();
		}
	});

	it("tracks terminal ownership until a lease is adopted", () => {
		const abandonedTerminal = new CountingTerminal();
		const abandonedComposer = new Composer({ preferences: config, terminal: abandonedTerminal });
		abandonedComposer.start();
		const abandonedLease = new ComposerLease(abandonedComposer);
		abandonedLease.dispose();
		abandonedLease.dispose();
		expect(abandonedTerminal.stops).toBe(1);

		const adoptedTerminal = new CountingTerminal();
		const adoptedComposer = new Composer({ preferences: config, terminal: adoptedTerminal });
		adoptedComposer.start();
		const adoptedLease = new ComposerLease(adoptedComposer);
		adoptedLease.adopt();
		adoptedLease.dispose();
		expect(adoptedTerminal.stops).toBe(0);
		adoptedLease.composer.ui.stop();
		expect(adoptedTerminal.stops).toBe(1);
	});

	it("restores a partially started terminal and leaves no pending owner", () => {
		const terminal = new ThrowingStartTerminal();
		expect(() => beginStartupComposer({ preferences: config, terminal, cache: false })).toThrow(
			"terminal start failed",
		);
		expect(terminal.starts).toBe(1);
		expect(terminal.stops).toBe(1);
		expect(takeStartupComposerLease()).toBeUndefined();
	});

	it("bounds a tall startup draft after adoption in a short terminal", async () => {
		const terminal = new CountingTerminal(80, 8);
		const composer = new Composer({ preferences: config, terminal });
		composer.start();
		for (let index = 0; index < 18; index += 1) {
			terminal.sendInput(`line-${index}`);
			if (index < 17) terminal.sendInput("\n");
		}
		const draft = composer.editor.getExpandedText();
		const lease = new ComposerLease(composer);
		const testSession = await createTestSession({ inMemory: true });
		const mode = new InteractiveMode(
			testSession.session,
			"test",
			undefined,
			undefined,
			undefined,
			undefined,
			undefined,
			lease.composer,
		);
		lease.adopt();
		vi.spyOn(mode.statusLine, "watchBranch").mockImplementation(() => {});

		try {
			await mode.init({ suppressWelcomeIntro: true });
			await terminal.waitForRender();
			expect(mode.editor.getExpandedText()).toBe(draft);
			expect(draft.split("\n")).toHaveLength(18);
			expect(mode.editor.render(80).length).toBeLessThanOrEqual(4);
			expect(terminal.getViewport().join("\n")).not.toContain("Starting OMP");
		} finally {
			mode.stop();
			lease.dispose();
			await testSession.cleanup();
			vi.restoreAllMocks();
		}
	});

	it("restores the terminal before an early double interrupt exits", () => {
		const terminal = new CountingTerminal();
		const exit = vi.fn();
		let now = 1_000;
		const composer = new Composer({ preferences: config, terminal, exit, now: () => now });
		composer.start();

		terminal.sendInput("draft");
		terminal.sendInput("\x03");
		expect(composer.editor.getExpandedText()).toBe("");
		now += 100;
		terminal.sendInput("\x03");

		expect(terminal.stops).toBe(1);
		expect(exit).toHaveBeenCalledWith(130);
	});

	it("forward-deletes a startup draft before interactive keybindings load, exiting once it is empty", () => {
		const terminal = new CountingTerminal();
		const exit = vi.fn();
		const composer = new Composer({ preferences: config, terminal, exit });
		composer.start();

		terminal.sendInput("draft");
		terminal.sendInput("\x1b[D"); // Left, so Ctrl+D has a character ahead of the cursor
		terminal.sendInput("\x04");
		expect(composer.editor.getExpandedText()).toBe("draf");
		expect(exit).not.toHaveBeenCalled();
		expect(terminal.stops).toBe(0);

		for (let i = 0; i < 4; i++) terminal.sendInput("\x7f"); // Backspace the rest of the draft
		expect(composer.editor.getExpandedText()).toBe("");
		terminal.sendInput("\x04");

		expect(exit).toHaveBeenCalledWith(0);
		expect(terminal.stops).toBe(1);
	});

	it("keeps emergency exit live after adoption until interactive handlers replace it", () => {
		const terminal = new CountingTerminal();
		const exit = vi.fn();
		const composer = new Composer({ preferences: config, terminal, exit });
		composer.start();
		const lease = new ComposerLease(composer);
		lease.adopt();

		// InputController.setupKeyHandlers() has not run yet; a stalled startup must
		// still honor Ctrl+D so a raw-mode user can abort.
		terminal.sendInput("\x04");

		expect(exit).toHaveBeenCalledWith(0);
		expect(terminal.stops).toBe(1);
	});

	it("renders the complete interactive welcome scene on the first frame", async () => {
		const terminal = new CountingTerminal(80, 32);
		const composer = new Composer({
			preferences: config,
			terminal,
			welcome: { version: "9.9.9" },
		});
		composer.start();
		await terminal.waitForRender(() => terminal.getViewport().some(row => Bun.stripANSI(row).includes("v9.9.9")));

		const output = terminal
			.getViewport()
			.map(r => Bun.stripANSI(r))
			.join("\n");
		expect(output).not.toContain("Starting OMP");
		expect(output).toContain("╰");
		const initialEditorRow = terminal
			.getViewport()
			.map(row => Bun.stripANSI(row))
			.findLastIndex(row => row.startsWith("╰"));
		composer.updateWelcome({ version: "10.0.0-authoritative" });
		await terminal.waitForRender(() =>
			terminal.getViewport().some(row => Bun.stripANSI(row).includes("v10.0.0-authoritative")),
		);
		const updatedEditorRow = terminal
			.getViewport()
			.map(row => Bun.stripANSI(row))
			.findLastIndex(row => row.startsWith("╰"));
		expect(updatedEditorRow).toBe(initialEditorRow);
		composer.stop();
	});

	it("adopted welcome survives handoff with authoritative data", async () => {
		const terminal = new CountingTerminal(80, 32);
		const composer = new Composer({
			preferences: config,
			terminal,
			// The prepaint's speculative version; InteractiveMode's is authoritative.
			welcome: { version: "9.9.8" },
		});
		composer.start();
		await terminal.waitForRender(() => terminal.getViewport().some(row => Bun.stripANSI(row).includes("v9.9.8")));
		const prepaintRows = terminal.getViewport().map(row => Bun.stripANSI(row));
		expect(prepaintRows.join("\n")).toContain("v9.9.8");
		const prepaintEditorRow = prepaintRows.findLastIndex(row => row.startsWith("╰"));

		terminal.sendInput("draft message");
		const lease = new ComposerLease(composer);
		const testSession = await createTestSession({ inMemory: true });
		let mode: InteractiveMode | undefined;

		try {
			mode = new InteractiveMode(
				testSession.session,
				"9.9.9",
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				lease.composer,
			);
			lease.adopt();
			vi.spyOn(mode.statusLine, "watchBranch").mockImplementation(() => {});
			const realTopBorder = vi
				.spyOn(mode.statusLine, "getTopBorder")
				.mockReturnValue({ content: "real status bar", width: 15, revision: 1 });
			terminal.sendInput(" between");
			expect(mode.editor.getExpandedText()).toBe("draft message between");
			await terminal.waitForRender();
			await mode.init({ suppressWelcomeIntro: true });
			await terminal.waitForRender();

			expect(terminal.starts).toBe(1);
			expect(mode.editor.getExpandedText()).toBe("draft message between");
			const output = terminal
				.getViewport()
				.map(r => Bun.stripANSI(r))
				.join("\n");
			expect(output).toContain("v9.9.9");
			expect(output).not.toContain("v9.9.8");
			realTopBorder.mockReturnValue({ content: "real status bar *18 ?5", width: 21, revision: 2 });
			mode.ui.requestRender();
			await terminal.waitForRender(() =>
				terminal.getViewport().some(row => Bun.stripANSI(row).includes("real status bar *18 ?5")),
			);
			const welcomeMatches = (output.match(/v9\.9\.9/g) || []).length;
			expect(welcomeMatches).toBe(1);
			const adoptedEditorRow = terminal
				.getViewport()
				.map(row => Bun.stripANSI(row))
				.findLastIndex(row => row.startsWith("╰"));
			expect(adoptedEditorRow).toBe(prepaintEditorRow);
		} finally {
			mode?.stop();
			lease.dispose();
			await testSession.cleanup();
			vi.restoreAllMocks();
		}
	});

	it("preferences feed applies quiet mode", async () => {
		const terminal = new CountingTerminal(80, 32);
		beginStartupComposer({
			preferences: config,
			terminal,
			version: "9.9.9",
			cache: false,
		});
		await terminal.waitForRender(() => terminal.getViewport().some(row => Bun.stripANSI(row).includes("v9.9.9")));

		applyStartupComposerPreferences({
			quiet: true,
			composerShape: "box",
			showHardwareCursor: config.showHardwareCursor,
			maxInlineImages: config.maxInlineImages,
			resizeScrollback: config.resizeScrollback,
			imeSafeCursor: config.imeSafeCursor,
			autocompleteMaxVisible: config.autocompleteMaxVisible,
			spellingTypoDetection: cfgSpellingTypoDetection.get(settings),
			spellingAutocomplete: cfgSpellingAutocomplete.get(settings),
			spellingAutocorrect: cfgSpellingAutocorrect.get(settings),
			theme: {},
		});
		await terminal.waitForRender();

		const output = terminal
			.getViewport()
			.map(r => Bun.stripANSI(r))
			.join("\n");
		expect(output).not.toContain("v9.9.9");

		terminal.sendInput("still editable");
		await terminal.waitForRender();
		expect(
			terminal
				.getViewport()
				.map(r => Bun.stripANSI(r))
				.join("\n"),
		).toContain("still editable");
	});

	it("defers raw input until resolved settings arrive, adoption as fallback", async () => {
		// Regression contract: losing the deferral re-blinds typing during the
		// startup module-load stall; losing the enable leaves the keyboard dead
		// for the whole session.
		const terminal = new InputTrackingTerminal(80, 32);
		beginStartupComposer({
			preferences: config,
			terminal,
			version: "9.9.9",
			cache: false,
		});
		// The prepaint must be physically written before any async runtime import
		// can monopolize the event loop; a merely queued render is still a blind gap.
		expect(terminal.getViewport().some(row => Bun.stripANSI(row).includes("9.9.9"))).toBeTrue();
		expect(terminal.startOptions?.deferInput).toBeTrue();
		expect(terminal.inputEnables).toBe(0);

		applyStartupComposerPreferences({ ...config, theme: {} });
		expect(terminal.inputEnables).toBe(1);

		// Adoption after preferences must not double-enable…
		const lease = takeStartupComposerLease();
		lease?.adopt();
		expect(terminal.inputEnables).toBe(1);
		lease?.composer.ui.stop();
	});

	it("adoption enables raw input when settings never resolved", () => {
		const terminal = new InputTrackingTerminal(80, 32);
		beginStartupComposer({
			preferences: config,
			terminal,
			version: "9.9.9",
			cache: false,
		});
		const lease = takeStartupComposerLease();
		lease?.adopt();
		expect(terminal.inputEnables).toBe(1);
		lease?.composer.ui.stop();
	});
});
