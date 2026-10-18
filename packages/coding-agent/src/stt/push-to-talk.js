import { theme } from "@rva/tui/theme";
import { hsvToRgb } from "@rva/utils";
const TRANSCRIBING_COLOR = { r: 200, g: 200, b: 200 };
/** Replaces a text input's cursor with a hue-cycling mic glyph while speech is recorded, holds it
 *  grey while the recording is transcribed, and restores the cursor state it found on {@link dispose}. */
export class MicCursor {
    #ui;
    #target;
    #previousShowHardwareCursor;
    #previousUseTerminalCursor;
    #hue = 0;
    #animation;
    constructor(ui, target) {
        this.#ui = ui;
        this.#target = target;
        this.#previousShowHardwareCursor = ui.getShowHardwareCursor();
        this.#previousUseTerminalCursor = target.getUseTerminalCursor();
        ui.setShowHardwareCursor(false);
        target.setUseTerminalCursor(false);
        this.#paintHue();
        this.#animation = setInterval(() => {
            this.#hue = (this.#hue + 8) % 360;
            this.#paintHue();
            // Component-scoped: the hue sweep only recolors the input's cursor
            // glyph, so the transcript subtree is reused per animation frame.
            ui.requestComponentRender(target);
        }, 60);
    }
    /** Stop cycling and hold the glyph grey while the recording is transcribed. */
    showTranscribing() {
        this.#stopAnimation();
        this.#paint(TRANSCRIBING_COLOR);
    }
    dispose() {
        this.#stopAnimation();
        this.#target.cursorOverride = undefined;
        this.#ui.setShowHardwareCursor(this.#previousShowHardwareCursor);
        this.#target.setUseTerminalCursor(this.#previousUseTerminalCursor);
    }
    #stopAnimation() {
        clearInterval(this.#animation);
        this.#animation = undefined;
    }
    #paintHue() {
        this.#paint(hsvToRgb({ h: this.#hue, s: 0.9, v: 1.0 }));
    }
    #paint({ r, g, b }) {
        this.#target.cursorOverride = `\x1b[38;2;${r};${g};${b}m${theme.icon.mic}\x1b[0m`;
    }
}
