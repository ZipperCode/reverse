// Real ProcessTerminal + fullscreen Composer for the tmux height regression.
import { TranscriptContainer } from "@reverse/tui/chrome/transcript-container";
import { COMPOSER_DEFAULTS, Composer } from "@reverse/tui/prompt/composer";
import { ProcessTerminal } from "@reverse/tui/terminal";
import { CURSOR_MARKER } from "@reverse/tui/tui";
import { setTerminalHeadless } from "@reverse/utils";
import { parseSgrMouse } from "@reverse/tui/mouse";
import { matchesKey } from "@reverse/tui/keys";

class RecordingTerminal extends ProcessTerminal {
	resets = 0;
	override write(data: string): void {
		this.resets += data.split("\x1b[3J").length - 1;
		super.write(data);
	}
}

class Block {
	constructor(readonly id: number) {}
	render(width: number): string[] {
		return [`block-${String(this.id).padStart(5, "0")}`.padEnd(Math.max(0, width - 1), ".")];
	}
}

class Editor {
	render(): string[] {
		return ["EDITOR-TOP", `input${CURSOR_MARKER}`, "EDITOR-BOTTOM"];
	}
}

setTerminalHeadless(false);
const terminal = new RecordingTerminal();
const composer = new Composer({
	terminal,
	preferences: { ...COMPOSER_DEFAULTS, quiet: true },
});
const transcript = new TranscriptContainer();
for (let id = 0; id < 1000; id++) transcript.addChild(new Block(id));
composer.setRuntimeChildren([transcript, new Editor()]);
composer.ui.addInputListener(data => {
	if (data.startsWith("\x1b[<")) {
		const event = parseSgrMouse(data);
		if (!event) return undefined;
		const viewport = composer.ui.getMutableViewport();
		const row = event.row - viewport.top;
		if (event.button & 64) {
			composer.cancelTranscriptDrag();
			if (event.wheel !== null && !event.release && !event.motion && row >= 0 && row < viewport.length) {
				composer.scrollTranscript(event.wheel * 3);
			}
		} else composer.handleTranscriptMouse(event, row);
		return { consume: true };
	}
	const page = Math.max(1, composer.transcriptViewportHeight - 1);
	if (matchesKey(data, "alt+pageUp")) composer.scrollTranscript(-page);
	else if (matchesKey(data, "alt+pageDown")) composer.scrollTranscript(page);
	else if (matchesKey(data, "alt+end")) composer.scrollTranscriptToBottom();
	else return undefined;
	return { consume: true };
});
composer.ui.addPaintListener(paint => {
	terminal.setTitle(JSON.stringify({ height: paint.rows, resets: terminal.resets }));
});
composer.start({ playWelcomeIntro: false });
await Bun.sleep(60000);
composer.ui.stop();
