import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { KeybindingsManager } from "@reverse/tui/app-keybindings";
import { resetSettingsForTest, Settings, settings } from "@reverse/coding-agent/config/settings";
import { PINNED_HUD_TOGGLE_ID } from "@reverse/coding-agent/task/output-manager";
import { InputController } from "@reverse/coding-agent/modes/controllers/input-controller";
import { SpaceHoldGesture } from "@reverse/tui/space-hold";
import type { InteractiveModeContext } from "@reverse/coding-agent/modes/types";
import { AgentRegistry } from "@reverse/coding-agent/registry/agent-registry";
import type { AgentSession } from "@reverse/coding-agent/session/agent-session";

import { cfgTuiMouse } from "@reverse/coding-agent/modes/settings";

const ESC = String.fromCharCode(27);
// SGR click on viewport row 2 (1-based y=3): the pinned expander row when the
// candidates below resolve it to the toggle sentinel.
const EXPANDER_CLICK = `${ESC}[<0;5;3M`;

function makeHarness(options?: { detailClickResult?: boolean; candidatesAtRow?: (index: number) => string[] }) {
	const listeners: Array<(data: string) => { consume?: boolean; data?: string } | undefined> = [];
	const focused: string[] = [];
	let toggled = 0;
	let requestRenderCount = 0;
	const routedDetailClicks: Array<{ index: number; col: number }> = [];
	const ctx = {
		ui: {
			addInputListener: (fn: (data: string) => { consume?: boolean; data?: string } | undefined) => {
				listeners.push(fn);
			},
			getMutableViewport: () => ({ top: 0, length: 5 }),
			hasOverlay: () => false,
			requestRender: () => {
				requestRenderCount++;
			},
			resetDisplay: () => {},
			addStartListener: () => {},
			getFocused: () => undefined,
		},
		handlesBtwBranchKey: () => false,
		editor: {
			getText: () => "",
			setActionKeys: () => {},
			setCustomKeyHandler: () => {},
			clearCustomKeyHandlers: () => {},
			spaceHold: new SpaceHoldGesture(() => {}),
		},
		keybindings: KeybindingsManager.inMemory(),
		settings,
		dictationSpaceHold: () => undefined,
		session: {
			extensionRunner: undefined,
		},
		resolveViewportClickCandidates:
			options?.candidatesAtRow ?? ((index: number) => (index === 2 ? [PINNED_HUD_TOGGLE_ID] : [])),
		routeViewportDetailClick: (index: number, col: number) => {
			routedDetailClicks.push({ index, col });
			return options?.detailClickResult ?? false;
		},
		activateViewportLink: () => false,
		focusedAgentId: undefined,
		focusAgentSession: async (id: string) => {
			focused.push(id);
		},
		togglePinnedHudExpanded: () => {
			toggled++;
		},
		showStatus: () => {},
		setClickHoverId: () => {},
	} as unknown as InteractiveModeContext;
	const controller = new InputController(ctx);
	controller.setupKeyHandlers();
	return {
		click: (data: string = EXPANDER_CLICK) => {
			let consumed: boolean | undefined;
			for (const listener of listeners) {
				const res = listener(data);
				if (res?.consume) consumed = true;
			}
			return consumed;
		},
		focused,
		toggled: () => toggled,
		routedDetailClicks,
		requestRenderCount: () => requestRenderCount,
	};
}

describe("InputController click routing", () => {
	beforeEach(async () => {
		AgentRegistry.resetGlobalForTests();
		await Settings.init({ inMemory: true });
		cfgTuiMouse.set(settings, true);
	});

	afterEach(() => {
		AgentRegistry.resetGlobalForTests();
		resetSettingsForTest();
	});

	it("focuses a live agent whose id equals the toggle sentinel", () => {
		AgentRegistry.global().register({
			id: PINNED_HUD_TOGGLE_ID,
			displayName: "evil",
			kind: "sub",
			session: {} as unknown as AgentSession,
			sessionFile: null,
		});
		const h = makeHarness();
		h.click();
		expect(h.focused).toEqual([PINNED_HUD_TOGGLE_ID]);
		expect(h.toggled()).toBe(0);
	});

	it("toggles when no live agent matches the sentinel", () => {
		const h = makeHarness();
		h.click();
		expect(h.toggled()).toBe(1);
		expect(h.focused).toEqual([]);
	});

	it("bypasses mouse events when tui.mouse is disabled", () => {
		cfgTuiMouse.set(settings, false);
		const h = makeHarness();
		const consumed = h.click();
		expect(consumed).toBeUndefined();
		expect(h.toggled()).toBe(0);
		expect(h.focused).toEqual([]);
	});

	it("routes left clicks on non-agent rows to detail routing and requests render on toggle", () => {
		cfgTuiMouse.set(settings, true);
		const h = makeHarness({ detailClickResult: true });
		// Click at row 1 (1-based y=2, col 5 -> 1-based x=6)
		const clickRow1 = `${ESC}[<0;6;2M`;
		const consumed = h.click(clickRow1);
		expect(consumed).toBe(true);
		expect(h.routedDetailClicks).toEqual([{ index: 1, col: 5 }]);
		expect(h.requestRenderCount()).toBe(1);
		expect(h.toggled()).toBe(0);
		expect(h.focused).toEqual([]);
	});

	it("does not request render when detail click routing returns false (body click no-op)", () => {
		cfgTuiMouse.set(settings, true);
		const h = makeHarness({ detailClickResult: false });
		const clickRow1 = `${ESC}[<0;6;2M`;
		const consumed = h.click(clickRow1);
		expect(consumed).toBe(true);
		expect(h.routedDetailClicks).toEqual([{ index: 1, col: 5 }]);
		expect(h.requestRenderCount()).toBe(0);
	});

	it("gives agent candidate priority over detail routing", () => {
		cfgTuiMouse.set(settings, true);
		AgentRegistry.global().register({
			id: "LiveWorker",
			displayName: "Live Worker",
			kind: "sub",
			session: {} as unknown as AgentSession,
			sessionFile: null,
		});
		const h = makeHarness({
			detailClickResult: true,
			candidatesAtRow: (index: number) => (index === 1 ? ["LiveWorker"] : []),
		});
		const clickRow1 = `${ESC}[<0;6;2M`;
		h.click(clickRow1);
		expect(h.focused).toEqual(["LiveWorker"]);
		expect(h.routedDetailClicks).toEqual([]);
		expect(h.requestRenderCount()).toBe(0);
	});
});
