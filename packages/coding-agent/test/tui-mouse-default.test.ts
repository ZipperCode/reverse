import { afterEach, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import * as path from "node:path";
import { Agent } from "@reverse/agent";
import { ModelRegistry } from "@reverse/coding-agent/config/model-registry";
import { resetSettingsForTest, Settings } from "@reverse/coding-agent/config/settings";
import { cfgTuiMouse } from "@reverse/coding-agent/modes/settings";
import { InteractiveMode } from "@reverse/coding-agent/modes/interactive-mode";
import { AgentSession } from "@reverse/coding-agent/session/agent-session";
import { AuthStorage } from "@reverse/coding-agent/session/auth-storage";
import { SessionManager } from "@reverse/coding-agent/session/session-manager";
import type { Component } from "@reverse/tui";
import { ToolExecutionComponent } from "@reverse/tui/chat/tool-execution";
import { SelectList } from "@reverse/tui/components/select-list";
import { parseSgrMouse } from "@reverse/tui/mouse";
import { Composer } from "@reverse/tui/prompt/composer";
import { getSelectListTheme, initTheme } from "@reverse/tui/theme";
import { TempDir } from "@reverse/utils";
import { VirtualTerminal } from "../../tui/test/virtual-terminal";

const MOUSE_TRACKING_ON = "\x1b[?1000h\x1b[?1003h\x1b[?1006h";
const MOUSE_TRACKING_OFF = "\x1b[?1006l\x1b[?1003l\x1b[?1000l";

/** VirtualTerminal recording every raw sequence written to the terminal. */
class CapturingTerminal extends VirtualTerminal {
	readonly raw: string[] = [];

	override write(data: string): void {
		this.raw.push(data);
		super.write(data);
	}
}

/** Exercise a real scrollable selector rather than merely echoing mouse input. */
class FullscreenWheelModal implements Component {
	readonly list = new SelectList(
		Array.from({ length: 12 }, (_, index) => ({ value: `entry-${index}`, label: `entry-${index}` })),
		4,
		getSelectListTheme(),
	);

	render(width: number): readonly string[] {
		return this.list.render(width);
	}

	handleInput(data: string): void {
		const event = parseSgrMouse(data);
		if (event) this.list.routeMouse(event, event.row, event.col);
	}
}

describe("tui.mouse default off runtime behavior", () => {
	let tempDir: TempDir;
	let authStorage: AuthStorage;
	let session: AgentSession;
	let mode: InteractiveMode;
	let term: CapturingTerminal;

	beforeAll(() => {
		initTheme();
	});

	beforeEach(async () => {
		resetSettingsForTest();
		tempDir = TempDir.createSync("@pi-tui-mouse-default-");
		// Actual default settings wired without overriding cfgTuiMouse
		await Settings.init({ inMemory: true, cwd: tempDir.path() });
		authStorage = await AuthStorage.create(path.join(tempDir.path(), "testauth.db"));
		const modelRegistry = new ModelRegistry(authStorage);
		const model = modelRegistry.find("anthropic", "claude-sonnet-4-5");
		if (!model) throw new Error("Expected claude-sonnet-4-5 to exist in registry");
		session = new AgentSession({
			agent: new Agent({ initialState: { model, systemPrompt: ["Test"], tools: [], messages: [] } }),
			sessionManager: SessionManager.create(tempDir.path(), tempDir.path()),
			settings: Settings.isolated(),
			modelRegistry,
		});
		term = new CapturingTerminal(120, 32);
		const composer = new Composer({ terminal: term });
		mode = new InteractiveMode(session, "test", undefined, () => {}, undefined, undefined, undefined, composer);
	});

	afterEach(async () => {
		mode?.stop();
		await session?.dispose();
		authStorage?.close();
		tempDir?.removeSync();
		resetSettingsForTest();
	});

	it("never emits mouse capture to normal buffer under default settings", async () => {
		await mode.init({ suppressWelcomeIntro: true });
		void mode.getUserInput();
		await term.waitForRender();

		// Normal buffer rendering under default false must never send MOUSE_TRACKING_ON
		expect(term.raw.some(chunk => chunk.includes(MOUSE_TRACKING_ON))).toBe(false);

		// An SGR click input sent on normal buffer is bypassed and never triggers capture
		term.sendInput("\x1b[<0;10;10M");
		await term.waitForRender();
		expect(term.raw.some(chunk => chunk.includes(MOUSE_TRACKING_ON))).toBe(false);
	});

	it("enables capture and routes wheel in fullscreen overlay, then restores off when closed", async () => {
		await mode.init({ suppressWelcomeIntro: true });
		void mode.getUserInput();
		await term.waitForRender();

		term.raw.length = 0;
		const modal = new FullscreenWheelModal();
		const handle = mode.ui.showOverlay(modal, { fullscreen: true });
		mode.ui.renderNow();

		// Fullscreen overlay independently requests mouse reporting
		expect(term.raw.some(chunk => chunk.includes(MOUSE_TRACKING_ON))).toBe(true);

		term.sendInput("\x1b[<65;20;10M");
		mode.ui.renderNow();
		expect(modal.list.pickerView().selected).toBe("entry-1");
		term.sendInput("\x1b[<64;20;10M");
		mode.ui.renderNow();
		expect(modal.list.pickerView().selected).toBe("entry-0");

		term.raw.length = 0;
		handle.hide();
		mode.ui.renderNow();

		// Closing fullscreen overlay restores off on normal buffer
		expect(term.raw.some(chunk => chunk.includes(MOUSE_TRACKING_OFF))).toBe(true);
		expect(term.raw.some(chunk => chunk.includes(MOUSE_TRACKING_ON))).toBe(false);
	});

	it("restores inline click expand on explicit opt-in and restores off when disabled", async () => {
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
		await term.waitForRender(() => term.getViewport().some(row => row.includes("Bash")));

		const viewport = term.getViewport().map(row => Bun.stripANSI(row).trimEnd());
		const headerRow = viewport.findIndex(row => row.includes("Bash"));
		expect(headerRow).toBeGreaterThanOrEqual(0);

		// While default false: SGR click on header does NOT expand
		term.sendInput(`\x1b[<0;5;${headerRow + 1}M`);
		await term.waitForRender();
		expect(tool.expanded).toBe(false);

		// Explicitly opt in to mouse capture
		term.raw.length = 0;
		cfgTuiMouse.set(mode.settings, true);
		mode.ui.requestRender();
		await term.waitForRender();

		expect(term.raw.some(chunk => chunk.includes(MOUSE_TRACKING_ON))).toBe(true);

		// SGR click on header now expands detail
		term.sendInput(`\x1b[<0;5;${headerRow + 1}M`);
		await term.waitForRender();
		expect(tool.expanded).toBe(true);

		// Explicitly disable again
		term.raw.length = 0;
		cfgTuiMouse.set(mode.settings, false);
		mode.ui.requestRender();
		await term.waitForRender();

		expect(term.raw.some(chunk => chunk.includes(MOUSE_TRACKING_OFF))).toBe(true);
	});
});
