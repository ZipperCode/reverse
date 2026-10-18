import { COMPOSER_DEFAULTS, Composer, } from "@rva/tui/prompt/composer";
import { sharedComposerCache, } from "@rva/tui/prompt/composer-cache";
import { setMagicKeywords } from "@rva/tui/prompt/magic-keywords";
import { initThemeSync } from "@rva/tui/theme";
import { MAGIC_KEYWORDS } from "./magic-keywords";
let pendingComposer;
/** Ownership token that transfers one already-started Composer to InteractiveMode. */
export class ComposerLease {
    composer;
    #adopted = false;
    constructor(composer) {
        this.composer = composer;
    }
    /** Transfer terminal ownership exactly once. */
    adopt() {
        if (this.#adopted)
            return;
        // Safety net: startup paths that never applied resolved settings must
        // still hand InteractiveMode a raw-input terminal.
        this.composer.enableInput();
        this.composer.transfer();
        this.#adopted = true;
    }
    /** Stop an unadopted composer when startup exits before InteractiveMode. */
    dispose() {
        if (!this.#adopted)
            this.composer.stop();
    }
}
/** Start the canonical Composer with speculative cached state. */
export function beginStartupComposer(options = {}) {
    if (pendingComposer)
        throw new Error("A prepaint composer is already active");
    const cwd = options.cwd ?? process.cwd();
    const cache = options.cache === false ? undefined : sharedComposerCache();
    const cached = cache ? cache.read(cwd) : { preferences: undefined, theme: undefined, status: undefined };
    const theme = { ...cached.theme, ...options.theme };
    initThemeSync(theme.symbolPreset, theme.colorBlindMode, theme.darkTheme, theme.lightTheme);
    setMagicKeywords(MAGIC_KEYWORDS);
    const preferences = { ...COMPOSER_DEFAULTS, ...cached.preferences, ...options.preferences };
    const welcome = { version: options.version ?? "" };
    const composer = new Composer({
        terminal: options.terminal,
        exit: options.exit,
        now: options.now,
        preferences,
        welcome,
        status: cached.status,
    });
    try {
        composer.start({ clearScrollback: true, deferInput: true });
    }
    catch (error) {
        try {
            composer.stop();
        }
        catch { }
        throw error;
    }
    pendingComposer = { composer, cwd, cache };
}
/** Take the live prepaint composer away from the module-level startup owner. */
export function takeStartupComposerLease() {
    const pending = pendingComposer;
    pendingComposer = undefined;
    return pending ? new ComposerLease(pending.composer) : undefined;
}
/** Stop and forget any prepaint composer that never reached InteractiveMode. */
export function stopPendingStartupComposer() {
    pendingComposer?.composer.stop();
    pendingComposer = undefined;
}
/** Apply final settings to the pending Composer and cache them for the next first frame. */
export function applyStartupComposerPreferences(update) {
    const pending = pendingComposer;
    if (!pending)
        return;
    const preferences = {
        quiet: update.quiet,
        composerShape: update.composerShape,
        showHardwareCursor: update.showHardwareCursor,
        maxInlineImages: update.maxInlineImages,
        resizeScrollback: update.resizeScrollback,
        imeSafeCursor: update.imeSafeCursor,
        autocompleteMaxVisible: update.autocompleteMaxVisible,
        spellingTypoDetection: update.spellingTypoDetection,
        spellingAutocomplete: update.spellingAutocomplete,
        spellingAutocorrect: update.spellingAutocorrect,
    };
    pending.composer.setPreferences(preferences);
    // Settings resolved means the module graph is loaded and the event loop is
    // responsive again: take raw-input ownership now. The kernel echoed (and
    // buffered) everything typed during the load; the editor replays it here.
    pending.composer.enableInput();
    pending.cache?.writeUi(pending.cwd, preferences, update.theme);
}
