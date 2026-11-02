import { afterEach, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import * as path from "node:path";
import { Agent } from "@reverse/agent";
import { ModelRegistry } from "@reverse/coding-agent/config/model-registry";
import { resetSettingsForTest, Settings } from "@reverse/coding-agent/config/settings";
import { cfgComposerTokenRate, cfgComposerShape, cfgTuiMouse } from "@reverse/coding-agent/modes/settings";
import { InteractiveMode } from "@reverse/coding-agent/modes/interactive-mode";
import { AgentSession } from "@reverse/coding-agent/session/agent-session";
import { AuthStorage } from "@reverse/coding-agent/session/auth-storage";
import { SessionManager } from "@reverse/coding-agent/session/session-manager";
import type { Component } from "@reverse/tui";
import { ToolExecutionComponent } from "@reverse/tui/chat/tool-execution";
import { SelectList } from "@reverse/tui/components/select-list";
import { Text } from "@reverse/tui/components/text";
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

function plainRows(rows: readonly string[]): string[] {
	return rows.map(row =>
		Bun.stripANSI(row)
			.replace(/[│█]$/, "")
			.trimEnd(),
	);
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

	it("always enables mouse capture on fullscreen main surface under default settings and releases on stop", async () => {
		await mode.init({ suppressWelcomeIntro: true });
		void mode.getUserInput();
		await term.waitForRender();

		expect(cfgTuiMouse.get(mode.settings)).toBe(false);
		// Fullscreen main surface always enables SGR mouse reporting so wheel scrolling works by default
		expect(term.raw.some(chunk => chunk.includes(MOUSE_TRACKING_ON))).toBe(true);

		// An SGR click with tui.mouse=false is consumed without leaking into the editor draft
		term.sendInput("\x1b[<0;10;10M");
		await term.waitForRender();
		expect(mode.editor.getText()).toBe("");

		term.raw.length = 0;
		mode.stop();
		expect(term.raw.some(chunk => chunk.includes(MOUSE_TRACKING_OFF))).toBe(true);
	});

	it("routes wheel in fullscreen overlay and preserves mouse capture when returning to fullscreen main", async () => {
		await mode.init({ suppressWelcomeIntro: true });
		void mode.getUserInput();
		await term.waitForRender();

		const modal = new FullscreenWheelModal();
		const handle = mode.ui.showOverlay(modal, { fullscreen: true });
		mode.ui.renderNow();

		term.sendInput("\x1b[<65;20;10M");
		mode.ui.renderNow();
		expect(modal.list.pickerView().selected).toBe("entry-1");
		term.sendInput("\x1b[<64;20;10M");
		mode.ui.renderNow();
		expect(modal.list.pickerView().selected).toBe("entry-0");

		term.raw.length = 0;
		handle.hide();
		mode.ui.renderNow();

		// Returning from fullscreen overlay to fullscreen main keeps mouse reporting active
		expect(term.raw.some(chunk => chunk.includes(MOUSE_TRACKING_OFF))).toBe(false);
	});

	it("keeps detail click expand opt-in via tui.mouse while keeping mouse capture active for wheel", async () => {
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

		const viewport = plainRows(term.getViewport());
		const headerRow = viewport.findIndex(row => row.includes("Bash"));
		expect(headerRow).toBeGreaterThanOrEqual(0);

		// While default false: SGR click on header is consumed and does NOT expand
		term.sendInput(`\x1b[<0;5;${headerRow + 1}M`);
		await term.waitForRender();
		expect(tool.expanded).toBe(false);
		expect(mode.editor.getText()).toBe("");

		// Explicitly opt in to detail clicks
		cfgTuiMouse.set(mode.settings, true);
		mode.ui.requestRender();
		await term.waitForRender();

		// SGR click on header now expands detail
		term.sendInput(`\x1b[<0;5;${headerRow + 1}M`);
		await term.waitForRender(() => tool.expanded === true);
		expect(tool.expanded).toBe(true);

		// Explicitly disable again: clicks stop toggling while fullscreen wheel capture stays on
		term.raw.length = 0;
		cfgTuiMouse.set(mode.settings, false);
		mode.ui.requestRender();
		await term.waitForRender();

		expect(term.raw.some(chunk => chunk.includes(MOUSE_TRACKING_OFF))).toBe(false);
		const expandedHeaderRow = plainRows(term.getViewport()).findIndex(row => row.includes("Bash"));
		expect(expandedHeaderRow).toBeGreaterThanOrEqual(0);
		term.sendInput(`\x1b[<0;5;${expandedHeaderRow + 1}M`);
		await term.waitForRender();
		expect(tool.expanded).toBe(true);
	});

	it("scrolls transcript by 3 rows across history/editor/status and keeps browsing stable across appends", async () => {
		await mode.init({ suppressWelcomeIntro: true });
		void mode.getUserInput();
		await term.waitForRender();

		for (let i = 0; i < 100; i++) {
			mode.chatContainer.addChild(new Text(`ROW-${String(i).padStart(3, "0")}`, 0, 0));
		}
		mode.ui.requestRender();
		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes("ROW-099")));

		term.sendInput("draft");
		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes("draft")));

		const transcriptHeight = mode.composer.transcriptViewportHeight;
		expect(transcriptHeight).toBeGreaterThan(10);
		const initialAll = plainRows(term.getViewport());
		const initialTranscript = initialAll.slice(0, transcriptHeight);
		const editorRowIndex = initialAll.findIndex(row => row.includes("draft"));
		expect(editorRowIndex).toBeGreaterThanOrEqual(transcriptHeight);

		// Wheel up in transcript area (\x1b[<64;5;3M) scrolls up 3 physical rows
		term.sendInput("\x1b[<64;5;3M");
		await term.waitForRender(() => !plainRows(term.getViewport()).some(row => row.includes("ROW-099")));
		const afterUp1All = plainRows(term.getViewport());
		const afterUp1Transcript = afterUp1All.slice(0, transcriptHeight);
		expect(afterUp1Transcript.slice(3)).toEqual(initialTranscript.slice(0, transcriptHeight - 3));
		expect(afterUp1All.at(-1)).toBe(initialAll.at(-1));
		expect(afterUp1All.findIndex(row => row.includes("draft"))).toBe(editorRowIndex);
		expect(mode.editor.getText()).toBe("draft");

		// Second wheel up scrolls up another 3 rows; wheel down (\x1b[<65;5;3M) scrolls down 3 rows
		term.sendInput("\x1b[<64;5;3M");
		await term.waitForRender(() => plainRows(term.getViewport())[0] !== afterUp1Transcript[0]);
		const afterUp2Transcript = plainRows(term.getViewport()).slice(0, transcriptHeight);
		expect(afterUp2Transcript.slice(3)).toEqual(afterUp1Transcript.slice(0, transcriptHeight - 3));

		term.sendInput("\x1b[<65;5;3M");
		await term.waitForRender(() => plainRows(term.getViewport())[0] === afterUp1Transcript[0]);
		expect(plainRows(term.getViewport()).slice(0, transcriptHeight)).toEqual(afterUp1Transcript);

		// Appending block 101 while browsing history preserves the current top anchor and editor row
		mode.chatContainer.addChild(new Text("ROW-100", 0, 0));
		mode.ui.requestRender();
		await term.waitForRender();
		expect(plainRows(term.getViewport()).slice(0, transcriptHeight)).toEqual(afterUp1Transcript);
		expect(plainRows(term.getViewport()).some(row => row.includes("ROW-100"))).toBe(false);
		expect(plainRows(term.getViewport()).findIndex(row => row.includes("draft"))).toBe(editorRowIndex);

		// Each dock wheel independently moves history by three rows without moving the draft/status.
		let beforeDock = afterUp1Transcript;
		for (const row of [editorRowIndex, initialAll.length - 1]) {
			term.sendInput(`\x1b[<64;5;${row + 1}M`);
			mode.ui.renderNow();
			const afterDock = plainRows(term.getViewport()).slice(0, transcriptHeight);
			expect(afterDock.slice(3)).toEqual(beforeDock.slice(0, transcriptHeight - 3));
			expect(afterDock).not.toEqual(beforeDock);
			expect(plainRows(term.getViewport()).findIndex(line => line.includes("draft"))).toBe(editorRowIndex);
			expect(plainRows(term.getViewport()).at(-1)).toBe(initialAll.at(-1));
			beforeDock = afterDock;
		}
		// Horizontal wheels, releases and events outside the window do not scroll.
		term.sendInput("\x1b[<64;5;99M");
		term.sendInput("\x1b[<66;5;3M");
		term.sendInput("\x1b[<67;5;3M");
		term.sendInput("\x1b[<64;5;3m");
		term.sendInput("\x1b[<0;5;3m");
		await term.waitForRender();
		expect(plainRows(term.getViewport()).slice(0, transcriptHeight)).toEqual(beforeDock);
		expect(mode.editor.getText()).toBe("draft");
	});

	it("routes Alt+PageUp/Down/End to transcript, keeps PageUp/Down in editor, and yields to overlays and editor selectors", async () => {
		await mode.init({ suppressWelcomeIntro: true });
		void mode.getUserInput();
		await term.waitForRender();

		for (let i = 0; i < 100; i++) {
			mode.chatContainer.addChild(new Text(`ROW-${String(i).padStart(3, "0")}`, 0, 0));
		}
		mode.ui.requestRender();
		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes("ROW-099")));

		const transcriptHeight = mode.composer.transcriptViewportHeight;
		const pageStep = Math.max(1, transcriptHeight - 1);
		const tailTranscript = plainRows(term.getViewport()).slice(0, transcriptHeight);

		// Alt+PageUp scrolls up by one page (transcriptViewportHeight - 1)
		term.sendInput("\x1b[5;3~");
		await term.waitForRender(() => !plainRows(term.getViewport()).some(row => row.includes("ROW-099")));
		const afterPageUp = plainRows(term.getViewport()).slice(0, transcriptHeight);
		expect(afterPageUp[pageStep]).toBe(tailTranscript[0]);

		// Alt+PageUp again, then Alt+PageDown returns to the previous page
		term.sendInput("\x1b[5;3~");
		await term.waitForRender(() => plainRows(term.getViewport())[0] !== afterPageUp[0]);
		const afterTwoPageUp = plainRows(term.getViewport()).slice(0, transcriptHeight);
		expect(afterTwoPageUp[pageStep]).toBe(afterPageUp[0]);

		term.sendInput("\x1b[6;3~");
		await term.waitForRender(() => plainRows(term.getViewport())[0] === afterPageUp[0]);
		expect(plainRows(term.getViewport()).slice(0, transcriptHeight)).toEqual(afterPageUp);

		// Ordinary PageUp / PageDown stay with the editor and do not move the transcript window
		mode.editor.setText("line-0\nline-1\nline-2");
		mode.ui.requestRender();
		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes("line-2")));
		const pausedTranscript = plainRows(term.getViewport()).slice(0, mode.composer.transcriptViewportHeight);
		expect(mode.editor.getCursor().line).toBe(2);
		term.sendInput("\x1b[5~");
		await term.waitForRender();
		expect(mode.editor.getCursor().line).toBe(0);
		expect(plainRows(term.getViewport()).slice(0, mode.composer.transcriptViewportHeight)).toEqual(pausedTranscript);
		term.sendInput("\x1b[6~");
		await term.waitForRender();
		expect(mode.editor.getCursor().line).toBe(2);
		expect(plainRows(term.getViewport()).slice(0, mode.composer.transcriptViewportHeight)).toEqual(pausedTranscript);

		// Fullscreen overlay takes priority for wheel and Alt+PageUp/End, then restores the exact browsed position
		const modal = new FullscreenWheelModal();
		const overlayHandle = mode.ui.showOverlay(modal, { fullscreen: true });
		mode.ui.renderNow();
		term.sendInput("\x1b[<65;5;3M");
		term.sendInput("\x1b[1;3F");
		mode.ui.renderNow();
		expect(modal.list.pickerView().selected).toBe("entry-1");
		overlayHandle.hide();
		mode.ui.renderNow();
		expect(plainRows(term.getViewport()).slice(0, mode.composer.transcriptViewportHeight)).toEqual(pausedTranscript);

		// Editor-slot selector (mounted in editorContainer with focus) receives wheel/keys without scrolling transcript
		const selector = new FullscreenWheelModal();
		mode.editorContainer.clear();
		mode.editorContainer.addChild(selector);
		mode.ui.setFocus(selector);
		mode.ui.renderNow();
		term.sendInput("\x1b[<64;5;3M");
		mode.ui.renderNow();
		expect(selector.list.pickerView().selected).toBe("entry-0");
		term.sendInput("\x1b[<65;5;3M");
		mode.ui.renderNow();
		expect(selector.list.pickerView().selected).toBe("entry-1");
		term.sendInput("\x1b[5;3~");
		term.sendInput("\x1b[1;3F");

		mode.editorContainer.clear();
		mode.editorContainer.addChild(mode.editor);
		mode.ui.setFocus(mode.editor);
		mode.ui.renderNow();
		expect(plainRows(term.getViewport()).slice(0, mode.composer.transcriptViewportHeight)).toEqual(pausedTranscript);

		// Alt+End returns transcript to the latest tail output
		term.sendInput("\x1b[1;3F");
		await term.waitForRender(() => plainRows(term.getViewport()).some(row => row.includes("ROW-099")));
		expect(plainRows(term.getViewport()).some(row => row.includes("ROW-099"))).toBe(true);
		mode.chatContainer.addChild(new Text("ROW-100", 0, 0));
		mode.ui.renderNow();
		expect(plainRows(term.getViewport()).some(row => row.includes("ROW-100"))).toBe(true);
	});
	it("keeps navigation to one row without an idle throughput row or duplicate working rate", async () => {
		cfgComposerShape.set(mode.settings, "default");
		cfgComposerTokenRate.set(mode.settings, true);
		await mode.init({ suppressWelcomeIntro: true });
		void mode.getUserInput();
		for (let i = 0; i < 100; i++) mode.chatContainer.addChild(new Text(`ROW-${i}`, 0, 0));
		mode.editor.setText("compact draft");
		mode.ui.renderNow();
		const H = mode.composer.transcriptViewportHeight;
		session.tokenRate.seed(1000, 10000);
		mode.ui.renderNow();
		expect(mode.statusContainer.render(120)).toEqual([]);
		expect(mode.composer.transcriptViewportHeight).toBe(H);
		const idle = plainRows(term.getViewport());
		expect(idle[H]).toContain("Go to top");
		expect(idle[H]).not.toContain("tok/s");
		mode.ensureLoadingAnimation();
		mode.setWorkingMessage("Inspecting navigation layout");
		mode.ui.renderNow();
		const working = Bun.stripANSI(mode.statusContainer.render(120).join("\n"));
		expect(working).toContain("Inspecting navigation layout");
		expect(working).not.toContain("tok/s");
	});

	it("scrolls TODO and informational panels away while editor/status stay fixed, including short windows", async () => {
		await mode.init({ suppressWelcomeIntro: true });
		void mode.getUserInput();
		for (let i = 0; i < 100; i++) mode.chatContainer.addChild(new Text(`ROW-${String(i).padStart(3, "0")}`, 0, 0));
		mode.setTodos([
			{
				name: "Scroll tasks",
				tasks: [
					{ content: "SCROLLABLE-TODO", status: "in_progress" },
					{ content: "NEXT-TODO", status: "pending" },
				],
			},
		]);
		mode.subagentContainer.addChild(new Text("SCROLLABLE-AGENT", 0, 0));
		mode.editor.setText("fixed draft");
		mode.ui.renderNow();
		for (const rows of [32, 12, 32]) {
			term.resize(120, rows);
			mode.composer.scrollTranscriptToBottom();
			mode.ui.renderNow();
			const H = mode.composer.transcriptViewportHeight;
			const initial = plainRows(term.getViewport());
			expect(initial.slice(0, H).some(row => row.includes("SCROLLABLE-TODO"))).toBe(true);
			expect(initial.slice(H + 1).some(row => row.includes("TODO") || row.includes("SCROLLABLE-AGENT"))).toBe(false);
			const dock = initial.slice(H + 1);
			mode.composer.scrollTranscript(-40);
			mode.ui.renderNow();
			const browsing = plainRows(term.getViewport());
			expect(browsing.some(row => row.includes("SCROLLABLE-TODO") || row.includes("SCROLLABLE-AGENT"))).toBe(false);
			expect(browsing.slice(H + 1)).toEqual(dock);
			expect(mode.editor.getText()).toBe("fixed draft");
			expect(mode.ui.getDebugPaint()?.cursor?.visible).toBe(true);
		}
	});

	it("uses real SGR track/drag/navigation by default, prevents click-through, and cancels capture across overlays", async () => {
		await mode.init({ suppressWelcomeIntro: true });
		void mode.getUserInput();
		for (let i = 0; i < 100; i++) mode.chatContainer.addChild(new Text(`ROW-${String(i).padStart(3, "0")}`, 0, 0));
		mode.ui.renderNow();
		const H = mode.composer.transcriptViewportHeight;
		const click = (button: number, col: number, row: number, suffix = "M") => {
			term.sendInput(`\x1b[<${button};${col};${row}${suffix}`);
			mode.ui.renderNow();
		};
		click(0, 120, Math.floor(H / 2));
		expect(
			plainRows(term.getViewport())
				.slice(0, H)
				.some(row => /ROW-04\d|ROW-05\d/.test(row)),
		).toBe(true);
		click(32, 30, 1);
		expect(plainRows(term.getViewport()).some(row => row.includes("ROW-000"))).toBe(true);
		click(32, 5, H + 10);
		expect(plainRows(term.getViewport()).some(row => row.includes("ROW-099"))).toBe(true);
		click(0, 125, 60, "m");
		const tail = plainRows(term.getViewport()).slice(0, H);
		click(32, 120, 1);
		expect(plainRows(term.getViewport()).slice(0, H)).toEqual(tail);
		click(0, 120, 4);
		const modal = new FullscreenWheelModal();
		const handle = mode.ui.showOverlay(modal, { fullscreen: true });
		mode.ui.renderNow();
		click(0, 120, 8, "m");
		handle.hide();
		mode.ui.renderNow();
		const beforeMotion = plainRows(term.getViewport()).slice(0, H);
		click(35, 120, 1);
		click(32, 120, 1);
		expect(plainRows(term.getViewport()).slice(0, H)).toEqual(beforeMotion);
		click(0, 120, 4);
		const beforeNative = plainRows(term.getViewport()).slice(0, H);
		Object.defineProperty(mode.ui, "nativeRendering", { configurable: true, get: () => true });
		try {
			term.sendInput("\x1b[<64;5;3M");
			term.sendInput("\x1b[<32;120;1M");
		} finally {
			Reflect.deleteProperty(mode.ui, "nativeRendering");
		}
		mode.ui.renderNow();
		expect(plainRows(term.getViewport()).slice(0, H)).toEqual(beforeNative);
		click(32, 120, 1);
		expect(plainRows(term.getViewport()).slice(0, H)).toEqual(beforeNative);
		cfgTuiMouse.set(mode.settings, true);
		let detailClicks = 0;
		let linkClicks = 0;
		mode.routeViewportDetailClick = () => {
			detailClicks++;
			return true;
		};
		mode.activateViewportLink = () => {
			linkClicks++;
			return true;
		};
		click(0, 120, H + 1);
		expect(plainRows(term.getViewport()).some(row => row.includes("ROW-099"))).toBe(true);
		expect(detailClicks).toBe(0);
		expect(linkClicks).toBe(0);
		mode.chatContainer.addChild(new Text("ROW-100", 0, 0));
		mode.ui.renderNow();
		expect(plainRows(term.getViewport()).some(row => row.includes("ROW-100"))).toBe(true);
		expect(mode.editor.getText()).toBe("");
	});
});
