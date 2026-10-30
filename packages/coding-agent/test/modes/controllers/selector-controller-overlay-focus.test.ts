import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeAll, describe, expect, it, vi } from "bun:test";
import type { SessionSelectorComponent } from "@reverse/tui/overlays/session-selector";
import { Settings } from "@reverse/coding-agent/config/settings";
import { SelectorController } from "@reverse/coding-agent/modes/controllers/selector-controller";
import { initTheme } from "@reverse/tui/theme";
import type { InteractiveModeContext } from "@reverse/coding-agent/modes/types";
import type { SessionInfo } from "@reverse/coding-agent/session/session-listing";
import { SessionManager } from "@reverse/coding-agent/session/session-manager";
import { Container, Input, Text, TUI } from "@reverse/tui";
import { VirtualRenderScheduler } from "../../../../tui/test/virtual-render-scheduler";
import { VirtualTerminal } from "../../../../tui/test/virtual-terminal";

beforeAll(async () => {
	await initTheme();
});

afterEach(() => {
	vi.restoreAllMocks();
});

interface EditorSlot {
	children: unknown[];
	clear: () => void;
	addChild: (child: unknown) => void;
}

function createEditorSlot(...initial: unknown[]): EditorSlot {
	return {
		children: [...initial],
		clear() {
			this.children = [];
		},
		addChild(child: unknown) {
			this.children.push(child);
		},
	};
}

function createCtx(slot: EditorSlot, editor: unknown, focused: unknown = editor) {
	const setFocus = vi.fn();
	const ctx = {
		editor,
		editorContainer: slot,
		ui: {
			getFocused: vi.fn(() => focused),
			setFocus,
			requestRender: vi.fn(),
		},
	} as unknown as InteractiveModeContext;
	return { ctx, setFocus };
}

describe("SelectorController.focusActiveEditorArea", () => {
	// Regression for issue #3349: closing a fullscreen overlay (settings,
	// extensions dashboard, agents dashboard) while a hook selector / approval
	// prompt occupies the editor slot must restore focus to that prompt — not
	// to the editor that the prompt replaced. Pre-fix, the close handlers
	// hardcoded `setFocus(this.ctx.editor)`, leaving keystrokes routed to a
	// no-longer-mounted editor while the visible prompt sat unreachable.

	it("focuses the editor when the slot has only the editor in it", () => {
		const editor = { id: "editor" };
		const slot = createEditorSlot(editor);
		const { ctx, setFocus } = createCtx(slot, editor);

		new SelectorController(ctx).focusActiveEditorArea();

		expect(setFocus).toHaveBeenCalledTimes(1);
		expect(setFocus).toHaveBeenCalledWith(editor);
	});

	it("focuses the active hook-selector-style prompt when the slot holds it instead of the editor", () => {
		const editor = { id: "editor" };
		const approvalPrompt = { id: "approval-prompt" };
		// Mirrors `ExtensionUiController.showHookSelector`: the hook surface
		// clears the slot and replaces the editor with its prompt component.
		const slot = createEditorSlot(approvalPrompt);
		const { ctx, setFocus } = createCtx(slot, editor);

		new SelectorController(ctx).focusActiveEditorArea();

		expect(setFocus).toHaveBeenCalledTimes(1);
		expect(setFocus).toHaveBeenCalledWith(approvalPrompt);
		expect(setFocus).not.toHaveBeenCalledWith(editor);
	});

	it("falls back to the editor when the slot is empty (defensive)", () => {
		const editor = { id: "editor" };
		const slot = createEditorSlot();
		const { ctx, setFocus } = createCtx(slot, editor);

		new SelectorController(ctx).focusActiveEditorArea();

		expect(setFocus).toHaveBeenCalledTimes(1);
		expect(setFocus).toHaveBeenCalledWith(editor);
	});
});

describe("SelectorController.showSelector", () => {
	it("restores an ask dialog and its draft editor after history search closes", () => {
		const editor = new Text("editor", 0, 0);
		const askDialog = new Text("ask", 0, 0);
		const historySearch = new Text("history", 0, 0);
		const slot = createEditorSlot(askDialog, editor);
		const { ctx, setFocus } = createCtx(slot, editor, askDialog);
		let finish: (() => void) | undefined;

		new SelectorController(ctx).showSelector(done => {
			finish = done;
			return { component: historySearch, focus: historySearch };
		});

		expect(slot.children).toEqual([historySearch]);
		expect(setFocus).toHaveBeenLastCalledWith(historySearch);
		if (!finish) throw new Error("selector did not provide its completion callback");
		finish();
		expect(slot.children).toEqual([askDialog, editor]);
		expect(setFocus).toHaveBeenLastCalledWith(askDialog);
	});
});

describe("SelectorController session replacement overlay", () => {
	it("keeps the fullscreen selector visible until the resumed transcript is ready", async () => {
		const session: SessionInfo = {
			path: "/tmp/resume.jsonl",
			id: "resume",
			cwd: "/tmp",
			title: "Resume target",
			created: new Date("2026-01-01T00:00:00Z"),
			modified: new Date("2026-01-02T00:00:00Z"),
			messageCount: 2,
			size: 1,
			firstMessage: "first",
			allMessagesText: "first second",
		};
		vi.spyOn(SessionManager, "listForPicker").mockResolvedValue([session]);

		const overlayHidden = Promise.withResolvers<void>();
		const hide = vi.fn(() => overlayHidden.resolve());
		let selector: SessionSelectorComponent | undefined;
		const editor = { id: "editor" };
		const editorContainer = createEditorSlot(editor);
		const ctx = {
			editor,
			editorContainer,
			settings: Settings.isolated(),
			sessionManager: {
				getCwd: () => "/tmp",
				getSessionDir: () => "/tmp",
				// Live-session path: keeps the picker's current-marker/focus code live
				// during the overlay assertions (single-row list stays deterministic).
				getSessionFile: () => session.path,
			},
			ui: {
				showOverlay: vi.fn(component => {
					selector = component as SessionSelectorComponent;
					return { hide, setHidden: vi.fn(), isHidden: () => false };
				}),
				setFocus: vi.fn(),
				requestRender: vi.fn(),
				terminal: { rows: 24 },
			},
		} as unknown as InteractiveModeContext;
		const controller = new SelectorController(ctx);
		const resumeStarted = Promise.withResolvers<void>();
		const resumed = Promise.withResolvers<boolean>();
		const handleResume = vi.spyOn(controller, "handleResumeSession").mockImplementation(() => {
			resumeStarted.resolve();
			return resumed.promise;
		});
		await controller.showSessionSelector();
		expect(selector).toBeDefined();
		selector!.handleInput("\n");
		await resumeStarted.promise;

		expect(handleResume).toHaveBeenCalledWith(session.path, { followContinuation: true });
		expect(hide).not.toHaveBeenCalled();

		// The selector remains mounted until resume finishes, but it must not accept
		// a second selection or cancel the overlay during that interval.
		selector!.handleInput("\n");
		selector!.handleInput("\x1b");
		expect(handleResume).toHaveBeenCalledTimes(1);
		expect(hide).not.toHaveBeenCalled();

		resumed.resolve(true);
		await overlayHidden.promise;
		expect(hide).toHaveBeenCalledTimes(1);
	});
});

describe("SelectorController.showCustomProviderWizard", () => {
	it("mounts custom provider wizard through #showFullscreenMenu over active overlay, accepts typing/editing/Enter into Step 2, and restores overlay and editor", async () => {
		const terminal = new VirtualTerminal(100, 32);
		const scheduler = new VirtualRenderScheduler();
		const tui = new TUI(terminal, false, { renderScheduler: scheduler });

		const editor = new Input();
		editor.setValue("original editor input");
		const slot = new Container();
		slot.addChild(editor);
		tui.addChild(slot);
		tui.setFocus(editor);

		// Mount an active background overlay (simulating an active fullscreen setup or modal)
		const backgroundOverlay = new Text("active background overlay", 0, 0);
		const backgroundHandle = tui.showOverlay(backgroundOverlay, {
			fullscreen: true,
			width: "100%",
			maxHeight: "100%",
			anchor: "top-left",
			margin: 0,
		});
		tui.setFocus(backgroundOverlay);

		const ctx = {
			editor,
			editorContainer: slot,
			session: {
				modelRegistry: {
					getAll: () => [],
					authStorage: {
						credentials: { has: () => false },
						keys: { source: () => undefined },
					},
					refresh: vi.fn(),
				},
			},
			settings: Settings.isolated(),
			ui: tui,
			showStatus: vi.fn(),
			showError: vi.fn(),
		} as unknown as InteractiveModeContext;

		const controller = new SelectorController(ctx);
		tui.start();
		await scheduler.settle(terminal);

		// Invoke real showCustomProviderWizard
		const wizardPromise = controller.showCustomProviderWizard();
		await scheduler.settle(terminal);

		// 1. editorContainer must NOT have been cleared or replaced
		expect(slot.children).toEqual([editor]);

		// 2. The nested custom provider wizard overlay owns focus over background overlay
		const focused = tui.getFocused();
		expect(focused).not.toBeNull();
		expect(focused).not.toBe(backgroundOverlay);
		expect(focused).not.toBe(editor);

		// 3. Dispatch real typing: "custom-prov"
		for (const char of "custom-prov") terminal.sendInput(char);
		await scheduler.settle(terminal);
		expect(terminal.getViewport().join("\n")).toContain("custom-prov");

		// 4. Dispatch backspace: delete 'v', then type 'v' and Enter '\r'
		terminal.sendInput("\x7f");
		await scheduler.settle(terminal);
		expect(terminal.getViewport().join("\n")).not.toContain("custom-prov");
		expect(terminal.getViewport().join("\n")).toContain("custom-pro");

		terminal.sendInput("v");
		terminal.sendInput("\r");
		await scheduler.settle(terminal);

		// 5. Explicit Step 2 assertion
		const step2Viewport = terminal.getViewport().join("\n");
		expect(step2Viewport).toContain("Step 2: API Protocol");
		expect(step2Viewport).toContain("OpenAI Chat Completions");

		// 6. Cancel wizard via Ctrl+C '\x03'
		terminal.sendInput("\x03");
		await wizardPromise;
		await scheduler.settle(terminal);

		// 7. Verify wizard overlay closed and background overlay regained focus
		expect(tui.getFocused()).toBe(backgroundOverlay);

		// 8. Closing background overlay restores focus and input routing to original editor
		backgroundHandle.hide();
		await scheduler.settle(terminal);
		expect(tui.getFocused()).toBe(editor);
		expect(editor.getValue()).toBe("original editor input");

		terminal.sendInput("!");
		await scheduler.settle(terminal);
		expect(editor.getValue()).toBe("original editor input!");

		tui.stop();
	});
});

describe("SelectorController.showProviderModelsWizard", () => {
	it("routes input to a prompt installed while management is open and preserves nested overlay focus", async () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "reverse-manager-focus-"));
		const terminal = new VirtualTerminal(100, 32);
		const scheduler = new VirtualRenderScheduler();
		const tui = new TUI(terminal, false, { renderScheduler: scheduler });
		try {
			fs.writeFileSync(
				path.join(dir, "models.yml"),
				"providers:\n  local-focus:\n    api: openai-completions\n    baseUrl: http://127.0.0.1:8080/v1\n    models:\n      - id: local-model\n",
			);
			const editor = new Input();
			const prompt = new Input();
			const slot = new Container();
			slot.addChild(editor);
			tui.addChild(slot);
			tui.setFocus(editor);
			const settings = await Settings.loadIsolated({ cwd: dir, agentDir: dir });
			const controller = new SelectorController({
				editor,
				editorContainer: slot,
				settings,
				ui: tui,
				session: { modelRegistry: {} },
				showError: (message: string) => {
					throw new Error(message);
				},
			} as unknown as InteractiveModeContext);
			tui.start();
			const management = controller.showProviderModelsWizard("local-focus");
			await scheduler.settle(terminal);
			slot.clear();
			slot.addChild(prompt);
			terminal.sendInput("\x1b");
			await management;
			await scheduler.settle(terminal);
			terminal.sendInput("approval");
			await scheduler.settle(terminal);
			expect(prompt.getValue()).toBe("approval");
			expect(editor.getValue()).toBe("");

			const background = new Input();
			const backgroundHandle = tui.showOverlay(background, { fullscreen: true, width: "100%", maxHeight: "100%" });
			tui.setFocus(background);
			const nested = controller.showProviderModelsWizard("local-focus");
			await scheduler.settle(terminal);
			terminal.sendInput("\x1b");
			await nested;
			await scheduler.settle(terminal);
			terminal.sendInput("setup");
			await scheduler.settle(terminal);
			expect(background.getValue()).toBe("setup");
			expect(prompt.getValue()).toBe("approval");
			backgroundHandle.hide();
		} finally {
			tui.stop();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});
