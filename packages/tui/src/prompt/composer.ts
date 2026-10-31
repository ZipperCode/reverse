import { getComposerStyle } from "../components/composer/registry";
import { Spacer } from "../components/spacer";
import type { StatusLineComponent } from "../status-line/component";
import { compositeLineAt } from "../render/composite";
import { type ExtensionLinkLabel, extensionLinkLabels, linkHintTags } from "../render/extension-links";
import type { StatusLineSession } from "../status-line/host";
import { createStartupStatusLine, type StatusLineStartupData } from "../status-line/startup";
import { ProcessTerminal, type Terminal } from "../terminal";
import {
	type Component,
	Container,
	type TerminalFramePlan,
	type TerminalFrameProvider,
	TUI,
	type TUIOptions,
	type ViewportSize,
} from "../tui";
import type { NativeChild, NativeSurface, NativeSurfaceProvider } from "../native/node";
import { sameItems } from "../native/memo";
import { postmortem } from "@reverse/utils";
import { CustomEditor } from "./custom-editor";
import type { WordCompletionMethod } from "./word-completion";
import { type AnimationFrame, TranscriptContainer } from "../chrome/transcript-container";
import { TranscriptViewport } from "../chrome/transcript-viewport";
import { CURSOR_MARKER } from "../tui";
import { WelcomeComponent } from "./welcome";
import { ensureThemeSync, getEditorTheme, theme } from "../theme/theme";

import { type DetailClickResult, hasMouseRouter, type SgrMouseEvent } from "../mouse";
const DOUBLE_INTERRUPT_MS = 500;

/** Live settings that affect the composer before and after session adoption. */
export interface ComposerPreferences {
	readonly quiet: boolean;
	readonly composerShape: string;
	readonly showHardwareCursor: boolean;
	readonly maxInlineImages: number;
	readonly imeSafeCursor: boolean;
	readonly autocompleteMaxVisible: number;
	readonly spellingTypoDetection: boolean;
	readonly spellingAutocomplete: WordCompletionMethod;
	readonly spellingAutocorrect: boolean;
}

/** Settings-schema-compatible defaults used when constructing a dependency-free composer. */
export const COMPOSER_DEFAULTS: ComposerPreferences = {
	quiet: false,
	composerShape: "band",
	showHardwareCursor: true,
	maxInlineImages: 8,
	imeSafeCursor: false,
	autocompleteMaxVisible: 10,
	spellingTypoDetection: true,
	spellingAutocomplete: "auto",
	spellingAutocorrect: false,
};

/** Welcome data that can be supplied initially or patched as startup resolves it. */
export interface ComposerWelcomeUpdate {
	readonly version?: string;
}

/**
 * Status-bar inputs persisted by the last session. The first frame renders
 * them through a startup {@link StatusLineComponent} at the live width until
 * the session-aware status line attaches.
 */
export interface ComposerStatusCache {
	/** ANSI wrapper of the editor border when persisted (session accent or thinking color). */
	readonly borderColor?: {
		readonly prefix: string;
		readonly suffix: string;
	};
	readonly statusLine: StatusLineStartupData;
}

/** Optional dependencies and initial state for a standalone composer. */
export interface ComposerOptions {
	readonly terminal?: Terminal;
	/** Extra TUI construction options (render scheduler injection for tests and `reverse render`). */
	readonly tuiOptions?: TUIOptions;
	readonly preferences?: Partial<ComposerPreferences>;
	readonly welcome?: ComposerWelcomeUpdate;
	readonly status?: ComposerStatusCache;
	readonly exit?: (code: number) => void;
	readonly now?: () => number;
}

/** How {@link Composer.setRuntimeChildren} lays out the roots below the transcript. */
export interface RuntimeChildrenOptions {
	/**
	 * Dock order on a TSP terminal (no status strip; the composer carries its
	 * facts): the native dock stacks HUD pills, the working row and queued messages over
	 * the composer in its own order, and may add describe-only roots. Defaults
	 * to the roots below the transcript in render order.
	 */
	readonly nativeDock?: readonly Component[];
}

/** Controls the first terminal paint for a composer that does not already own the terminal. */
export interface ComposerStartOptions {
	readonly clearScrollback?: boolean;
	readonly playWelcomeIntro?: boolean;
	/**
	 * Paint without owning stdin: the tty keeps cooked-mode echo/editing so
	 * typing stays visible while startup module loading blocks the event loop.
	 * {@link Composer.enableInput} later switches to raw input and replays the
	 * kernel-buffered keystrokes into the editor.
	 */
	readonly deferInput?: boolean;
}

/**
 * Mount slot below the editor: the startup status line, then the session-aware
 * one. ANSI only: a TSP terminal has no status strip, the composer carries the
 * status line's facts ({@link StatusLineComponent.describeComposerFacts}).
 */
class StatusHost implements Component {
	#component: Component | undefined;

	setComponent(component: Component): void {
		this.#component = component;
	}

	render(width: number): readonly string[] {
		return this.#component?.render(width) ?? [];
	}
}

/** One click target's row span within the mutable viewport (half-open `[start, end)`). */
export interface ViewportClickSpan {
	start: number;
	end: number;
	/** Candidate subagent ids for a span-local row. */
	candidates: (local: number) => string[];
}

/**
 * Row-level click target: maps rendered rows to subagent ids. Implemented by
 * the subagent HUD, whose rows are fixed 1:1 with visible sessions.
 */
export interface ViewportClickRowTarget {
	getClickAgentAtRow(row: number): string | undefined;
}

/**
 * Candidates under a mutable-viewport line: the first span containing it.
 * Pure seam for tests; the caller intersects with the live registry, which
 * decides focusability and recency.
 */
export function routeViewportClick(spans: readonly ViewportClickSpan[], index: number): string[] {
	if (!Number.isInteger(index) || index < 0) return [];
	for (const span of spans) {
		if (index < span.start || index >= span.end) continue;
		return span.candidates(index - span.start);
	}
	return [];
}

/** An extension link label drawn on a mutable-viewport line: what a click or hint tag lands on. */
export interface ViewportLink {
	readonly url: string;
	/** Mutable-viewport line the label is drawn on. */
	readonly row: number;
	/** First cell of the label's part on that line. */
	readonly start: number;
}

/** An extension link label tagged for picking by keyboard in link-hint mode. */
interface ViewportLinkHint {
	readonly tag: string;
	readonly link: ViewportLink;
}

/**
 * Called once when link-hint mode ends; `reason` is `"crowded"` when a row held more links than
 * their tags could fit side by side, so no tags were drawn.
 */
export type LinkHintsEnd = (reason?: "crowded") => void;

/**
 * The extension link labels drawn on `rows`, top to bottom, a wrapped label once at its first row:
 * a row's first label continues the previous row's last label when that has the same marker id
 * and ends its row.
 */
function viewportLinkTargets(rows: readonly string[]): ViewportLink[] {
	const targets: ViewportLink[] = [];
	let previous: ExtensionLinkLabel | undefined;
	for (let row = 0; row < rows.length; row++) {
		const labels = extensionLinkLabels(rows[row]!);
		for (const [index, label] of labels.entries()) {
			if (index === 0 && previous?.endsRow && previous.id === label.id) continue;
			targets.push({ url: label.url, row, start: label.start });
		}
		previous = labels.at(-1);
	}
	return targets;
}

/** One transcript detail target's row span within the mutable viewport (half-open `[start, end)`). */
export interface ViewportDetailClickSpan {
	start: number;
	end: number;
	component: Component;
	getComponentRow: (local: number) => number | undefined;
}

/**
 * Route a detail click to the component under mutable-viewport line `index`.
 * Resolves the component-local row and forwards via `MouseRoutable.routeMouse`.
 */
export function routeViewportDetailClick(
	spans: readonly ViewportDetailClickSpan[],
	index: number,
	col: number,
	event?: SgrMouseEvent,
): boolean | DetailClickResult {
	if (!Number.isInteger(index) || index < 0) return false;
	for (const span of spans) {
		if (index < span.start || index >= span.end) continue;
		const componentRow = span.getComponentRow(index - span.start);
		if (componentRow === undefined) return false;
		if (hasMouseRouter(span.component)) {
			const mouseEvent: SgrMouseEvent = event ?? {
				button: 0,
				col,
				row: index,
				release: false,
				wheel: null,
				motion: false,
				leftClick: true,
			};
			const res = span.component.routeMouse(mouseEvent, componentRow, col);
			if (typeof res === "object" && res !== null && "consumed" in res) {
				return res;
			}
			return res === true;
		}
		return false;
	}
	return false;
}

/**
 * Nested background opens inside a hovered row. The band wraps the line, so a
 * surviving nested open would paint over it for every cell it covers; the
 * matching closes stay and become band resumes via bgFill.
 */
const NESTED_BG_OPEN_PATTERN = new RegExp(`${String.fromCharCode(27)}\\[(?:4[0-7]|10[0-7]|48;[0-9;]*)m`, "g");

/**
 * Candidate resolver for a row-level click target, if the component is one.
 * Shared by root and nested-child hit-testing so both stay in lockstep.
 */
function rowTargetCandidates(target: Component): ((local: number) => string[]) | undefined {
	const rowTarget = target as Partial<ViewportClickRowTarget>;
	if (typeof rowTarget.getClickAgentAtRow !== "function") return undefined;
	return (local: number) => {
		const id = rowTarget.getClickAgentAtRow?.(local);
		return id === undefined ? [] : [id];
	};
}

/**
 * Canonical interactive composer, usable before session/settings exist and updatable in place.
 * It owns the terminal, welcome header, and editor; InteractiveMode later supplies authoritative
 * data and mounts the session-aware runtime children without replacing the visible header.
 */
export class Composer implements TerminalFrameProvider, NativeSurfaceProvider {
	readonly ui: TUI;
	#editor: CustomEditor;
	readonly #header = new Container();
	readonly #bootstrapInputGap = new Spacer(1);
	readonly #statusHost = new StatusHost();
	readonly #exit: (code: number) => void;
	readonly #now: () => number;
	#preferences: ComposerPreferences;
	#welcome: WelcomeComponent | undefined;
	#version = "";
	#headerBefore: readonly Component[] = [];
	#headerAfter: readonly Component[] = [];
	#runtimeChildren: readonly Component[] = [];
	#nativeDock: readonly Component[] | undefined;
	/** Cache-driven status line shown until {@link setStatusComponent} mounts the session's. */
	#startupStatus: StatusLineComponent | undefined;
	#runtimeMounted = false;
	readonly #transcriptViewport = new TranscriptViewport();
	#transcript: TranscriptContainer | undefined;
	#transcriptChildren: readonly Component[] | undefined;
	#scrollRoots: Component[] = [];
	#scrollSource: readonly Component[] | undefined;
	#scrollRuntime: readonly Component[] | undefined;
	#scrollTranscriptIndex = -1;
	#transcriptViewportHeight = 0;
	/** Click spans of the last `renderFrame` viewport, in viewport coordinates. */
	#lastClickSpans: ViewportClickSpan[] = [];
	#lastDetailSpans: ViewportDetailClickSpan[] = [];
	/** Rows of the last `renderFrame` viewport, before the hover band; read to hit-test extension links. */
	#lastViewportRows: readonly string[] = [];
	/** Click-candidate id under the pointer, painted with the hover band. Id-anchored so it follows streaming rows. */
	#hoveredClickId: string | undefined;
	/**
	 * Keyboard link-hint mode: the tags drawn over the extension links on screen (`undefined` until
	 * the first frame after `startLinkHints` assigns them), the letters typed so far, and what to run
	 * when the mode ends for any reason.
	 */
	#linkHints: { hints: ViewportLinkHint[] | undefined; typed: string; onEnd: LinkHintsEnd } | undefined;
	/** Width of the last painted viewport, which `#lastViewportRows` was laid out for. */
	#lastViewportWidth = 0;
	/** Rows the chrome below each below-transcript root took in the last frame (see {@link rowsBelow}). */
	#rowsBelow = new Map<Component, number>();
	#lastInterruptAt = 0;
	/** Last described surface; its arrays are reused while their children are unchanged. */
	#nativeSurface: NativeSurface = { main: [], dock: [] };
	#started = false;
	#stopped = false;
	#transferred = false;

	constructor(options: ComposerOptions = {}) {
		ensureThemeSync();
		// Host-owned hard exit: route through postmortem so a double-Ctrl-C during
		// an open extension-load guard window exits cleanly instead of throwing
		// ExtensionExitError through the guarded process.exit (#11789).
		this.#exit = options.exit ?? (code => postmortem.exitProcess(code));
		this.#now = options.now ?? Date.now;
		this.#preferences = { ...COMPOSER_DEFAULTS, ...options.preferences };
		this.#applyWelcomeUpdate(options.welcome ?? {});

		this.ui = new TUI(options.terminal ?? new ProcessTerminal(), this.#preferences.showHardwareCursor, {
			...options.tuiOptions,
			screenMode: "fullscreen",
		});
		this.ui.setFrameProvider(this);
		this.ui.setMaxInlineImages(this.#preferences.maxInlineImages);

		this.#editor = new CustomEditor(getEditorTheme());
		this.editor.disableSubmit = true;
		this.editor.setUseTerminalCursor(this.ui.getShowHardwareCursor());
		this.editor.setImeSafeCursorLayout(this.#preferences.imeSafeCursor);
		this.editor.setAutocompleteMaxVisible(this.#preferences.autocompleteMaxVisible);
		this.editor.setSpellingFeatures({
			typoDetection: this.#preferences.spellingTypoDetection,
			autocomplete: this.#preferences.spellingAutocomplete,
			autocorrect: this.#preferences.spellingAutocorrect,
		});
		try {
			this.editor.setBorderStyle(this.#preferences.composerShape);
		} catch {
			// Extension-defined styles arrive with the session; InteractiveMode reapplies them.
		}
		if (options.status) {
			const { borderColor, statusLine } = options.status;
			if (borderColor) this.editor.borderColor = text => `${borderColor.prefix}${text}${borderColor.suffix}`;
			this.#startupStatus = createStartupStatusLine(statusLine);
			this.#statusHost.setComponent(this.#startupStatus);
			this.#startupStatus.attachToEditor(this.editor, getComposerStyle(this.#preferences.composerShape));
		}
		// Emergency controls stay active until InteractiveMode installs configured bindings.
		// They deliberately mirror the interactive editor's contract so a stalled startup
		// never behaves differently from a healthy one: Ctrl+C clears the draft and a second
		// press exits 130 — the unconditional abort, draft or not; Ctrl+D exits 0 on an
		// empty draft and otherwise forward-deletes (see CustomEditor's app.exit handling),
		// so typing while the session loads cannot be lost to a mistyped delete.
		this.editor.setActionKeys("app.clear", ["ctrl+c"]);
		this.editor.setActionKeys("app.exit", ["ctrl+d"]);
		this.editor.onClear = () => this.#handleInterrupt();
		this.editor.onExit = () => this.#requestExit(0);
		this.editor.setShimmerRepaintHandler(() => this.ui.requestComponentRender(this.editor));

		if (!this.#preferences.quiet) this.#ensureWelcome();
		this.#rebuildHeader();
		this.ui.addChild(this.#header);
		this.ui.addChild(this.#bootstrapInputGap);
		this.ui.addChild(this.editor);
		this.ui.addChild(this.#statusHost);
		this.ui.setFocus(this.editor);
	}
	/**
	 * Rows the below-transcript chrome under `root` (editor, status line, …)
	 * took in the last frame, so a root that grows upward can cap itself to
	 * the screen rows left above them; `undefined` before `root` was laid out.
	 */
	rowsBelow(root: Component): number | undefined {
		return this.#rowsBelow.get(root);
	}

	/** Compose the scrolling conversation above a bottom-aligned, bounded dock. */
	renderFrame(viewport: ViewportSize): TerminalFramePlan {
		if (!this.#started || this.#stopped) return { viewport: [] };
		const width = Math.max(1, viewport.columns);
		const height = Math.max(0, viewport.rows);
		const roots = this.#runtimeChildren;
		const transcriptIndex = roots.findIndex(root => root instanceof TranscriptContainer);
		const transcript = transcriptIndex < 0 ? undefined : (roots[transcriptIndex] as TranscriptContainer);
		if (transcript !== this.#transcript || transcript?.children !== this.#transcriptChildren) {
			this.#transcriptViewport.reset();
			this.#transcript = transcript;
			this.#transcriptChildren = transcript?.children;
		}
		// 拼接只随源数组/长度变化；未知的原位替换仅修正对应组件身份。
		const source = transcript?.children;
		const prefix = Math.max(0, transcriptIndex);
		const length = 1 + prefix + (source?.length ?? 0);
		if (
			this.#scrollSource !== source ||
			this.#scrollRuntime !== roots ||
			this.#scrollTranscriptIndex !== transcriptIndex ||
			this.#scrollRoots.length !== length
		) {
			this.#scrollRoots = [this.#header, ...roots.slice(0, prefix), ...(source ?? [])];
			this.#scrollSource = source;
			this.#scrollRuntime = roots;
			this.#scrollTranscriptIndex = transcriptIndex;
		} else {
			for (let i = 0; i < prefix; i++) {
				if (this.#scrollRoots[i + 1] !== roots[i]) this.#scrollRoots[i + 1] = roots[i]!;
			}
			for (let i = 0; i < (source?.length ?? 0); i++) {
				if (this.#scrollRoots[prefix + 1 + i] !== source![i]) this.#scrollRoots[prefix + 1 + i] = source![i]!;
			}
		}
		const dockRoots = !this.#runtimeMounted
			? [this.#bootstrapInputGap, this.editor, this.#statusHost]
			: [...(transcript ? roots.slice(transcriptIndex + 1) : roots), this.#statusHost];
		const dock: string[] = [];
		const dockSpans: ViewportClickSpan[] = [];
		const ends: { root: Component; end: number }[] = [];
		for (const root of dockRoots) {
			this.#renderBelowRoot(root, width, dock, dockSpans);
			ends.push({ root, end: dock.length });
		}
		this.#rowsBelow = new Map(ends.map(({ root, end }) => [root, dock.length - end]));
		let drop = Math.max(0, dock.length - height);
		// 极小终端优先保留真实焦点光标，不能让尾部状态栏挤掉输入行。
		if (drop > 0) {
			const marker = dock.findIndex(row => row.includes(CURSOR_MARKER));
			if (marker >= 0 && (marker < drop || marker >= drop + height)) {
				drop = Math.max(0, Math.min(marker, dock.length - height));
			}
		}
		const visibleDock = height === 0 ? [] : dock.slice(drop, drop + height);
		const available = Math.max(0, height - visibleDock.length);
		this.#transcriptViewportHeight = available;
		const now = performance.now();
		const frame: AnimationFrame = { now, tick: Math.floor(now / 80) };
		const window = this.#transcriptViewport.render(this.#scrollRoots, width, available, frame);
		const mutable = [...window.rows, ...Array<string>(available - window.rows.length).fill(""), ...visibleDock];
		const spans: ViewportClickSpan[] = [];
		for (const span of window.spans) {
			const ids = (span.component as Component & { getClickFocusAgentIds?(): string[] }).getClickFocusAgentIds?.();
			const resolve = ids?.length ? (_local: number) => ids : rowTargetCandidates(span.component);
			if (resolve)
				spans.push({
					start: span.start,
					end: span.end,
					candidates: local => resolve(span.getComponentRow?.(local) ?? local),
				});
		}
		for (const span of dockSpans) {
			const start = Math.max(drop, span.start);
			const end = Math.min(drop + visibleDock.length, span.end);
			if (end > start)
				spans.push({
					start: available + start - drop,
					end: available + end - drop,
					candidates: local => span.candidates(local + start - span.start),
				});
		}
		this.#lastClickSpans = spans;
		this.#lastDetailSpans = window.spans.map(span => ({
			...span,
			getComponentRow: local => span.getComponentRow?.(local),
		}));
		this.#lastViewportRows = mutable;
		this.#lastViewportWidth = width;
		this.#syncLinkHints(mutable, width);
		return { viewport: this.#paintLinkHints(this.#paintHoverBand(mutable, spans), width) };
	}

	get transcriptViewportHeight(): number {
		return this.#transcriptViewportHeight;
	}

	scrollTranscript(rows: number): void {
		this.#transcriptViewport.scrollBy(rows);
		this.#hoveredClickId = undefined;
		this.ui.requestRender();
	}

	scrollTranscriptToBottom(): void {
		this.#transcriptViewport.scrollToBottom();
		this.#hoveredClickId = undefined;
		this.ui.requestRender();
	}

	/**
	 * Keep link-hint tags on what `rows` show. The first frame after `startLinkHints` tags its
	 * labels; later frames keep the tags while the tagged labels are still drawn first, in the same
	 * order and columns (rows may scroll, links may be added below), and otherwise end the mode, so a
	 * tag never picks a label no longer drawn under it. Every frame ends the mode as `"crowded"` when
	 * some row has more tag cells than `width` (a resize can narrow it), since tags drawn side by
	 * side could not all be read.
	 */
	#syncLinkHints(rows: readonly string[], width: number): void {
		const state = this.#linkHints;
		if (state === undefined) return;
		const targets = viewportLinkTargets(rows);
		const hints = state.hints;
		if (hints === undefined) {
			state.hints = linkHintTags(targets.length).map((tag, index) => ({ tag, link: targets[index]! }));
			if (state.hints.length === 0) {
				this.#endLinkHints();
				return;
			}
		} else {
			const unchanged =
				targets.length >= hints.length &&
				hints.every(({ link }, index) => link.url === targets[index]!.url && link.start === targets[index]!.start);
			if (!unchanged) {
				this.#endLinkHints();
				return;
			}
			state.hints = hints.map(({ tag }, index) => ({ tag, link: targets[index]! }));
		}
		const cells = new Map<number, number>();
		for (const { tag, link } of state.hints) cells.set(link.row, (cells.get(link.row) ?? 0) + tag.length);
		if ([...cells.values()].some(count => count > width)) this.#endLinkHints("crowded");
	}

	#endLinkHints(reason?: "crowded"): void {
		const state = this.#linkHints;
		if (state === undefined) return;
		this.#linkHints = undefined;
		state.onEnd(reason);
	}

	/**
	 * Draw every tag the typed letters still lead to over the start of its label. Tags on one row
	 * never overlap: one that would land on an earlier tag moves right, and tags that would run past
	 * the right edge move left, so each stays readable as long as the row has room for them all.
	 */
	#paintLinkHints(viewport: string[], width: number): string[] {
		const state = this.#linkHints;
		if (state?.hints === undefined) return viewport;
		const rows = new Map<number, { tag: string; col: number }[]>();
		for (const { tag, link } of state.hints) {
			if (viewport[link.row] === undefined || !tag.startsWith(state.typed)) continue;
			let row = rows.get(link.row);
			if (!row) rows.set(link.row, (row = []));
			row.push({ tag, col: link.start });
		}
		const painted = [...viewport];
		for (const [index, tags] of rows) {
			tags.sort((a, b) => a.col - b.col);
			let free = 0;
			for (const placed of tags) {
				placed.col = Math.max(placed.col, free);
				free = placed.col + placed.tag.length;
			}
			let limit = width;
			for (let i = tags.length - 1; i >= 0; i--) {
				const placed = tags[i]!;
				placed.col = Math.max(0, Math.min(placed.col, limit - placed.tag.length));
				limit = placed.col;
			}
			let line = painted[index]!;
			for (const { tag, col } of tags) {
				// Raw SGR like the hover highlight: chalk's inverse/bold drop out when it detects no color.
				const styled = `\x1b[1;7m${theme.fg("accent", tag)}\x1b[22;27m`;
				line = compositeLineAt(line, styled, col, tag.length, width);
			}
			painted[index] = line;
		}
		return painted;
	}

	/**
	 * Describe the whole surface for a TSP terminal. `main` is the flowing
	 * document: the header (welcome, extras) and every transcript block as its
	 * own component child. `dock` is the live chrome below the transcript in
	 * render order: pending messages, HUDs, the working row, the editor and the
	 * status line. TSP owns its document scrolling and dock layout; ANSI uses
	 * the component-anchored viewport and hover bands.
	 */
	describeSurface(): NativeSurface {
		if (!this.#started || this.#stopped) return this.#nativeSurface;
		const main: NativeChild[] = [...this.#header.children];
		const dock: NativeChild[] = [];
		if (!this.#runtimeMounted) {
			// The bootstrap gap is row spacing; the terminal owns the dock layout.
			dock.push(this.editor);
		} else {
			const roots = this.#runtimeChildren;
			const transcriptIndex = roots.findIndex(root => root instanceof TranscriptContainer);
			if (transcriptIndex < 0) {
				dock.push(...roots);
			} else {
				const transcript = roots[transcriptIndex] as TranscriptContainer;
				main.push(...roots.slice(0, transcriptIndex), ...transcript.nativeBlocks());
				dock.push(...(this.#nativeDock ?? roots.slice(transcriptIndex + 1)));
			}
		}
		const previous = this.#nativeSurface;
		const nextMain = sameItems(previous.main, main) ? previous.main : main;
		const nextDock = sameItems(previous.dock, dock) ? previous.dock : dock;
		if (nextMain !== previous.main || nextDock !== previous.dock) {
			this.#nativeSurface = { main: nextMain, dock: nextDock };
		}
		return this.#nativeSurface;
	}

	/**
	 * Append one below-transcript root's rows to `after`, recording click spans
	 * for its row targets in `after` coordinates.
	 *
	 * Row targets usually nest one level down: chrome roots are plain
	 * containers (the HUD lives inside `subagentContainer`), and
	 * `Container.render` is a pure concatenation, so child spans tile the root
	 * span exactly. Render those children once and share the rows for
	 * composition and measurement — a second render per frame would duplicate
	 * render-time side effects (image placement registration). Roots with a
	 * custom render keep the composed output as the source of truth and measure
	 * up to the last target.
	 */
	#renderBelowRoot(root: Component, width: number, after: string[], spans: ViewportClickSpan[]): void {
		const start = after.length;
		const plainContainer = root instanceof Container && root.render === Container.prototype.render;
		const targets = root instanceof Container ? root.children : [root];
		const resolves = targets.map(rowTargetCandidates);
		const lastTarget = resolves.findLastIndex(resolve => resolve !== undefined);
		if (plainContainer) {
			let offset = start;
			for (let index = 0; index < targets.length; index++) {
				const childLines = targets[index]!.render(width);
				after.push(...childLines);
				if (index > lastTarget) continue;
				const resolve = resolves[index];
				if (resolve !== undefined && childLines.length > 0) {
					spans.push({ start: offset, end: offset + childLines.length, candidates: resolve });
				}
				offset += childLines.length;
			}
			return;
		}
		after.push(...root.render(width));
		if (lastTarget === -1) return;
		let offset = start;
		for (let index = 0; index <= lastTarget; index++) {
			const childLines = targets[index] === root ? after.length - start : targets[index]!.render(width).length;
			const resolve = resolves[index];
			if (resolve !== undefined && childLines > 0) {
				spans.push({ start: offset, end: offset + childLines, candidates: resolve });
			}
			offset += childLines;
		}
	}

	/**
	 * Band the hovered click target's current rows. Id-anchored (not
	 * line-anchored) so the band follows an agent whose rows shift while it
	 * streams; an offscreen id matches no span and simply paints nothing. Only
	 * the viewport copy is banded; component render rows remain unchanged.
	 */
	#paintHoverBand(viewport: string[], spans: readonly ViewportClickSpan[]): string[] {
		const hovered = this.#hoveredClickId;
		if (hovered === undefined) return viewport;
		let banded = false;
		const painted = viewport.map((line, index) => {
			for (const span of spans) {
				if (index < span.start || index >= span.end) continue;
				if (!span.candidates(index - span.start).includes(hovered)) continue;
				banded = true;
				// A wrapping band loses to background opens nested inside the row
				// (live card rows carry the pending-tint bg, which would paint over
				// the band for every cell it covers), so drop nested bg opens
				// first; their closes stay and become band resumes via bgFill.
				return theme.bgFill("selectedBg", line.replace(NESTED_BG_OPEN_PATTERN, ""));
			}
			return line;
		});
		return banded ? painted : viewport;
	}

	/**
	 * Candidate subagent ids under a mutable-viewport line, for click-to-focus.
	 * Empty when the line has no click target (chrome or separators).
	 * Callers intersect with the live registry.
	 */
	viewportClickCandidates(index: number): string[] {
		return routeViewportClick(this.#lastClickSpans, index);
	}

	/**
	 * Route a click on a mutable-viewport line to a detail target (thinking, tool, read, skill).
	 * Returns true if the target consumed the event.
	 */
	routeViewportDetailClick(index: number, col: number, event?: SgrMouseEvent): boolean | DetailClickResult {
		return routeViewportDetailClick(this.#lastDetailSpans, index, col, event);
	}

	/**
	 * The extension-owned link label drawn at cell `col` of a mutable-viewport line, or `undefined`.
	 * Only links whose scheme an extension registered match; see `extensionLinkLabels`.
	 */
	viewportLinkAt(index: number, col: number): ViewportLink | undefined {
		const line = this.#lastViewportRows[index];
		if (line === undefined || col < 0) return undefined;
		const label = extensionLinkLabels(line).find(label => col >= label.start && col < label.end);
		return label && { url: label.url, row: index, start: label.start };
	}

	/**
	 * Point the hover band at a click-candidate id (or clear it). Takes effect
	 * on the next frame; callers repaint only when the target actually changes.
	 */
	setHoveredClickId(id: string | undefined): void {
		this.#hoveredClickId = id;
	}

	/** How many extension link labels the last frame drew; a label wrapped across rows counts once. */
	viewportLinkCount(): number {
		return viewportLinkTargets(this.#lastViewportRows).length;
	}

	/**
	 * Enter keyboard link-hint mode: the next frame draws a tag over each extension link label it
	 * shows. `onEnd` runs once when the mode ends: a pick, a cancel, a key no tag starts with, a
	 * repaint that no longer draws the tagged labels where they were, or (`"crowded"`) a row with
	 * too many links for their tags to fit side by side.
	 */
	startLinkHints(onEnd: LinkHintsEnd): void {
		this.#endLinkHints();
		this.#linkHints = { hints: undefined, typed: "", onEnd };
	}

	/** Whether link-hint mode is on. */
	get linkHintsActive(): boolean {
		return this.#linkHints !== undefined;
	}

	/**
	 * Type one letter of a tag. Returns the link whose whole tag is now typed, `true` while the
	 * letters still lead to several tags, and `false` when none starts with them. The mode ends on
	 * a pick or a miss.
	 */
	typeLinkHint(letter: string): ViewportLink | boolean {
		const state = this.#linkHints;
		if (state === undefined) return false;
		// A key typed before the tags were first painted picks among the labels last drawn.
		if (state.hints === undefined) this.#syncLinkHints(this.#lastViewportRows, this.#lastViewportWidth);
		const hints = this.#linkHints?.hints;
		if (hints === undefined) return false;
		const typed = state.typed + letter.toLowerCase();
		const matching = hints.filter(hint => hint.tag.startsWith(typed));
		const picked = matching.length === 1 && matching[0]!.tag === typed ? matching[0]!.link : undefined;
		if (matching.length === 0 || picked !== undefined) {
			this.#endLinkHints();
			return picked ?? false;
		}
		state.typed = typed;
		return true;
	}

	/** Leave link-hint mode without picking a link. */
	cancelLinkHints(): void {
		this.#endLinkHints();
	}

	/** Live editor whose draft survives startup and session adoption. */
	get editor(): CustomEditor {
		return this.#editor;
	}

	/** The welcome component currently mounted in the header, if quiet mode is off. */
	get welcome(): WelcomeComponent | undefined {
		return this.#welcome;
	}

	/** Whether this composer already owns the terminal render/input loop. */
	get started(): boolean {
		return this.#started && !this.#stopped;
	}

	/** Start terminal ownership and optionally begin the welcome intro. */
	start(options: ComposerStartOptions = {}): void {
		if (this.#started || this.#stopped) return;
		this.#started = true;
		// A TSP terminal keeps (and draws) what is typed until startup releases
		// the held input, standing in for the kernel echo other terminals give.
		this.#editor.nativeTypeahead = options.deferInput === true;
		this.ui.start({ clearScrollback: options.clearScrollback === true, deferInput: options.deferInput === true });
		if (options.playWelcomeIntro !== false) this.playWelcomeIntro();
		// Deferred input identifies the CLI prepaint handoff. Flush the queued
		// forced frame before returning so subsequent dynamic-import evaluation
		// cannot monopolize the event loop ahead of the speculative status chrome.
		if (options.deferInput === true) this.ui.renderNow({ clearScrollback: options.clearScrollback === true });
	}
	/** Take raw-input ownership after a deferred-input start. Idempotent. */
	enableInput(): void {
		if (this.#stopped) return;
		this.ui.enableInput();
	}

	/** Apply settings changes without replacing the editor or welcome component. */
	setPreferences(update: Partial<ComposerPreferences>): void {
		if (this.#stopped) return;
		const wasQuiet = this.#preferences.quiet;
		this.#preferences = { ...this.#preferences, ...update };
		this.editor.setTheme(getEditorTheme());
		try {
			this.editor.setBorderStyle(this.#preferences.composerShape);
		} catch {
			// Extension-defined styles arrive with the session; InteractiveMode reapplies them.
		}
		this.ui.setShowHardwareCursor(this.#preferences.showHardwareCursor);
		this.editor.setUseTerminalCursor(this.ui.getShowHardwareCursor());
		this.ui.setMaxInlineImages(this.#preferences.maxInlineImages);
		this.editor.setImeSafeCursorLayout(this.#preferences.imeSafeCursor);
		this.editor.setAutocompleteMaxVisible(this.#preferences.autocompleteMaxVisible);
		this.editor.setSpellingFeatures({
			typoDetection: this.#preferences.spellingTypoDetection,
			autocomplete: this.#preferences.spellingAutocomplete,
			autocorrect: this.#preferences.spellingAutocorrect,
		});
		this.#startupStatus?.attachToEditor(this.editor, getComposerStyle(this.#preferences.composerShape));
		if (this.#preferences.quiet) {
			this.#welcome?.stopIntro();
			this.#welcome = undefined;
		} else {
			this.#ensureWelcome();
			this.#welcome?.invalidate();
			if (wasQuiet && this.#started) this.playWelcomeIntro();
		}
		if (wasQuiet !== this.#preferences.quiet) this.#rebuildHeader();
		this.ui.requestRender();
	}

	/** Patch welcome data in place as version, session, and project discovery complete. */
	updateWelcome(update: ComposerWelcomeUpdate): void {
		if (this.#stopped) return;
		this.#applyWelcomeUpdate(update);
		if (this.#preferences.quiet) return;
		this.#ensureWelcome();
		const welcome = this.#welcome;
		if (!welcome) return;
		if (update.version !== undefined) welcome.setVersion(this.#version);
		this.ui.requestRender();
	}

	/** Replace optional header content around the stable welcome scene. */
	setHeaderExtras(before: readonly Component[], after: readonly Component[]): void {
		if (this.#stopped) return;
		this.#headerBefore = before;
		this.#headerAfter = after;
		this.#rebuildHeader();
		this.ui.requestRender();
	}

	/** Update the canonical editor reference after InteractiveMode remounts a custom editor. */
	setEditor(editor: CustomEditor): void {
		this.ui.replaceHeldFocus(this.#editor, editor);
		editor.nativeTypeahead = this.#editor.nativeTypeahead;
		this.#editor = editor;
	}

	/**
	 * End the startup input hold once the app's handlers are wired: the TSP
	 * terminal sends the typing it kept, and the keys the TUI held replay
	 * ({@link TUI.releaseHeldInput}). Idempotent.
	 */
	releaseHeldInput(): void {
		if (this.#editor.nativeTypeahead) {
			this.#editor.nativeTypeahead = false;
			this.ui.requestRender();
		}
		this.ui.releaseHeldInput();
	}

	/**
	 * Mount the session-aware status component into the slot below the editor,
	 * retiring the startup status line; the caller installs the real top-border
	 * provider through its composer-shape sync.
	 */
	setStatusComponent<TSession extends StatusLineSession>(component: StatusLineComponent<TSession>): void {
		if (this.#startupStatus) component.adoptGitStatus(this.#startupStatus);
		this.#disposeStartupStatus();
		this.#statusHost.setComponent(component);
		this.editor.setTopBorderProvider(undefined);
		this.editor.composerFacts = component;
	}

	#disposeStartupStatus(): void {
		this.#startupStatus?.dispose();
		this.#startupStatus = undefined;
	}

	/** Mount or replace session-aware root children while preserving the header and status hosts. */
	setRuntimeChildren(children: readonly Component[], options: RuntimeChildrenOptions = {}): void {
		if (this.#stopped) return;
		this.#nativeDock = options.nativeDock;
		this.ui.removeChild(this.#statusHost);
		if (this.#runtimeMounted) {
			for (const child of this.#runtimeChildren) this.ui.removeChild(child);
		} else {
			this.ui.removeChild(this.#bootstrapInputGap);
			this.ui.removeChild(this.editor);
			this.#runtimeMounted = true;
		}
		this.#runtimeChildren = children;
		for (const child of children) this.ui.addChild(child);
		this.ui.addChild(this.#statusHost);
		this.ui.requestRender();
	}

	/** Play or replay the welcome intro against the stable header render target. */
	playWelcomeIntro(): void {
		this.#welcome?.playIntro(() => this.ui.requestComponentRender(this.#header));
	}

	/** Transfer terminal ownership to InteractiveMode without stopping the composer. */
	transfer(): void {
		if (!this.#started || this.#stopped || this.#transferred) {
			throw new Error("Composer is not available for transfer");
		}
		this.#transferred = true;
	}

	/** Stop a composer that has not transferred terminal ownership. */
	stop(): void {
		if (!this.#started || this.#stopped || this.#transferred) return;
		this.#welcome?.stopIntro();
		this.#disposeStartupStatus();
		this.ui.stop();
		this.#stopped = true;
	}

	#applyWelcomeUpdate(update: ComposerWelcomeUpdate): void {
		if (update.version !== undefined) this.#version = update.version;
	}

	#ensureWelcome(): void {
		this.#welcome ??= new WelcomeComponent(this.#version);
	}

	#rebuildHeader(): void {
		this.#header.clear();
		for (const component of this.#headerBefore) this.#header.addChild(component);
		if (this.#welcome) {
			this.#header.addChild(new Spacer(1));
			this.#header.addChild(this.#welcome);
			this.#header.addChild(new Spacer(1));
		}
		for (const component of this.#headerAfter) this.#header.addChild(component);
	}

	#handleInterrupt(): void {
		const now = this.#now();
		if (now - this.#lastInterruptAt < DOUBLE_INTERRUPT_MS) {
			this.#requestExit(130);
			return;
		}
		this.editor.setText("");
		this.#lastInterruptAt = now;
	}

	#requestExit(code: number): void {
		// Remains live after transfer until InteractiveMode installs its configured handlers.
		if (this.#stopped) return;
		this.#welcome?.stopIntro();
		if (this.#started) this.ui.stop();
		this.#stopped = true;
		this.#exit(code);
	}
}
