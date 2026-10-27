import { BashInteractiveOverlayComponent } from "@reverse/tui/tools/bash-interactive";
import type { AgentToolContext } from "@reverse/agent";
import type { ImageContent } from "@reverse/ai";
import { type PtyRunResult, PtySession } from "@reverse/natives";
import { loadXtermTerminal } from "@reverse/tui/tools/terminal-output";
import { Settings } from "../config/settings";
import { OutputSink, type OutputSummary } from "@reverse/tui/tools/streaming-output";
import { TerminalGraphicsDecoder } from "../utils/terminal-graphics";
import {
	type CaptureBudgetTracker,
	isArtifactSessionBudgetExhausted,
	resolveArtifactSessionMaxBytes,
	resolveOutputMaxColumns,
	resolveOutputSinkArtifactMaxBytes,
	resolveOutputSinkHeadBytes,
	resolveOutputSinkSpillThreshold,
} from "./output-meta";

export interface BashInteractiveResult extends OutputSummary {
	exitCode: number | undefined;
	cancelled: boolean;
	timedOut: boolean;
	/** Terminal graphics extracted from raw PTY output before transcript sanitization. */
	images?: ImageContent[];
}

export async function runInteractiveBashPty(
	ui: Pick<NonNullable<AgentToolContext["ui"]>, "custom">,
	options: {
		command: string;
		cwd: string;
		timeoutMs?: number;
		signal?: AbortSignal;
		env?: Record<string, string>;
		settings?: Settings;
		artifactPath?: string;
		artifactId?: string;
		artifactManager?: CaptureBudgetTracker | null;
	},
): Promise<BashInteractiveResult> {
	const settings = options.settings ?? (await Settings.init());
	// Load the xterm Terminal ctor here (async boundary) — the ui.custom factory below is sync.
	const XtermTerminal = await loadXtermTerminal();
	const { shell: resolvedShell, env: shellEnv } = settings.getShellConfig();
	// The native PTY starts from the process's C environ, which Bun's
	// `process.env` writes never reach, so it is handed the spawn env. A pty call
	// has a user at the keyboard, so it gets the spawn env minus its
	// non-interactive guards (GIT_EDITOR, GPG_TTY, CI; added by procmgr's
	// `buildSpawnEnv`, and a guard added there belongs here too) and NO_COLOR, a
	// monochrome marker. A key left out keeps the inherited launch value.
	const { GIT_EDITOR: _gitEditor, GPG_TTY: _gpgTty, CI: _ci, NO_COLOR: _noColor, ...interactiveShellEnv } = shellEnv;
	const graphics = new TerminalGraphicsDecoder();
	const artifactManager = options.artifactManager ?? null;
	const budgetExhausted = isArtifactSessionBudgetExhausted(settings, artifactManager);
	const perCallArtifactMaxBytes = resolveOutputSinkArtifactMaxBytes(settings);
	const effectiveArtifactMaxBytes = resolveOutputSinkArtifactMaxBytes(settings, artifactManager);
	const sessionMaxBytes = resolveArtifactSessionMaxBytes(settings);
	const remainingSessionBytes = artifactManager?.getRemainingCaptureBudgetBytes(sessionMaxBytes);
	const artifactCapFromSessionBudget =
		remainingSessionBytes !== undefined &&
		(perCallArtifactMaxBytes === 0 || remainingSessionBytes < perCallArtifactMaxBytes);
	const effectiveArtifactPath = budgetExhausted ? undefined : options.artifactPath;
	if (effectiveArtifactPath && artifactManager?.reserveCaptureBytes && effectiveArtifactMaxBytes > 0) {
		artifactManager.reserveCaptureBytes(effectiveArtifactPath, effectiveArtifactMaxBytes);
	}
	const sink = new OutputSink({
		artifactPath: effectiveArtifactPath,
		artifactId: budgetExhausted ? undefined : options.artifactId,
		spillThreshold: resolveOutputSinkSpillThreshold(options.settings),
		headBytes: resolveOutputSinkHeadBytes(settings),
		artifactMaxBytes: effectiveArtifactMaxBytes,
		artifactSessionBudgetExhausted: budgetExhausted,
		artifactCapFromSessionBudget,
		onArtifactFinalized: bytes => {
			if (effectiveArtifactPath && artifactManager?.recordCapturedArtifact) {
				artifactManager.recordCapturedArtifact(effectiveArtifactPath, bytes);
			} else if (bytes > 0) {
				artifactManager?.recordCapturedBytes(bytes);
			}
		},
		maxColumns: resolveOutputMaxColumns(settings),
	});
	try {
		const result = await ui.custom<BashInteractiveResult>(
			(tui, uiTheme, _keybindings, done) => {
				const session = new PtySession();
				const component = new BashInteractiveOverlayComponent(
					options.command,
					uiTheme,
					() => tui.terminal.rows,
					XtermTerminal,
					{ resize: (columns, rows) => session.resize(columns, rows) },
				);
				let finished = false;
				const finalize = (run: PtyRunResult) => {
					if (finished) return;
					finished = true;
					component.setComplete({ exitCode: run.exitCode, cancelled: run.cancelled, timedOut: run.timedOut });
					tui.requestRender();
					void (async () => {
						await component.flushOutput();
						const tail = graphics.finish();
						if (tail) sink.push(tail);
						const [summary, images] = await Promise.all([sink.dump(), graphics.images()]);
						done({
							exitCode: run.exitCode,
							cancelled: run.cancelled,
							timedOut: run.timedOut,
							...summary,
							...(images.length > 0 ? { images } : {}),
						});
					})();
				};
				const cols = Math.max(20, tui.terminal.columns - 2);
				const rows = Math.max(5, tui.terminal.rows - 4);
				component.setHandlers(
					data => {
						try {
							session.write(data);
						} catch {
							// ignore writes after command exits
						}
					},
					() => {
						try {
							session.kill();
						} catch {
							// ignore
						}
					},
					() => {
						try {
							session.kill();
						} catch {
							// ignore
						}
					},
				);
				void session
					.start(
						{
							command: options.command,
							cwd: options.cwd,
							timeoutMs: options.timeoutMs,
							// A real TERM so editors, pagers, and TUIs behave like a normal
							// terminal; direnv's values win over everything.
							env: { ...interactiveShellEnv, TERM: "xterm-256color", ...options.env },
							signal: options.signal,
							cols,
							rows,
							shell: resolvedShell,
						},
						(err, chunk) => {
							if (finished || err || !chunk) return;
							component.appendOutput(chunk);
							const clean = graphics.push(chunk);
							if (clean) sink.push(clean.replace(/\r\n?/gu, "\n"));
							tui.requestRender();
						},
					)
					.then(finalize)
					.catch(error => {
						sink.push(`PTY error: ${error instanceof Error ? error.message : String(error)}\n`);
						finalize({ exitCode: undefined, cancelled: false, timedOut: false });
					});
				return component;
			},
			{ overlay: true },
		);
		return result;
	} finally {
		await sink.dispose();
	}
}
