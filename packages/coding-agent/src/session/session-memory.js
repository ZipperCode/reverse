/** Session memory backend lifecycle and transcript resets. */
import { logger } from "@rva/utils";
import { all as allSettings, combine } from "../config/registry";
import { resolveMemoryBackend } from "../memory-backend/resolve";
import { releaseSharpshooterSession } from "../sharpshooter/backend";
import { cfgMemoryBackend } from "../memory-backend/settings";
/** Id prefixes of the memory backends' own settings; their live edits reconfigure the active backend. */
const MEMORY_BACKEND_SETTING_PREFIXES = ["hindsight.", "mnemopi.", "sharpshooter."];
let memorySettings;
/** `memory.backend` plus every backend's own settings, keyed by setting id (built once registration is complete). */
function memorySettingsValue() {
    memorySettings ??= combine(Object.fromEntries(allSettings()
        .filter(handle => handle.id === cfgMemoryBackend.id ||
        MEMORY_BACKEND_SETTING_PREFIXES.some(prefix => handle.id.startsWith(prefix)))
        .map(handle => [handle.id, handle])));
    return memorySettings;
}
/** Owns memory backend transitions and transcript-scoped memory state. */
export class SessionMemory {
    #host;
    #memoryAgentDir;
    #memoryTaskDepth;
    #createMemoryTools;
    #memoryBackendTransition = Promise.resolve();
    #localMemoryStartupAbort;
    #baseSystemPromptBeforeMemoryPromotion;
    /** Cwd the running backend state was built for; a transcript is never retained after it moved. */
    #runtimeCwd;
    /** Apply waiting behind the current transition; later requests join it. */
    #queuedApply;
    /** Memory settings as last dispatched to `#applySettingsChange`; unset when live changes are disabled. */
    #observedSettings;
    /** Dispatched setting changes still running, including backend hooks that run outside the transition queue. */
    #settingsChanges = new Set();
    constructor(host, options) {
        this.#host = host;
        this.#memoryAgentDir = options.memoryAgentDir;
        this.#memoryTaskDepth = options.memoryTaskDepth ?? 0;
        this.#createMemoryTools = options.createMemoryTools;
        if (this.#memoryAgentDir)
            this.#runtimeCwd = host.cwd();
        // Subagents alias the parent's backend state and never replace it live.
        if (options.memoryEnabled !== false && this.#memoryAgentDir && this.#memoryTaskDepth === 0) {
            const value = memorySettingsValue();
            this.#observedSettings = value.get(host.settings);
            value.listen(host, () => this.#observeSettings());
        }
    }
    /**
     * Dispatches memory-setting edits not handled yet. The settings listener and
     * {@link settle} both land here, so an edit starts exactly once, whichever
     * observes it first.
     */
    #observeSettings() {
        const previous = this.#observedSettings;
        if (!previous || this.#host.isDisposed())
            return;
        const next = memorySettingsValue().get(this.#host.settings);
        const changed = [];
        for (const id in next)
            if (!Bun.deepEquals(next[id], previous[id]))
                changed.push(id);
        if (changed.length === 0)
            return;
        this.#observedSettings = next;
        const handling = this.#applySettingsChange(changed);
        this.#settingsChanges.add(handling);
        void handling.then(() => this.#settingsChanges.delete(handling));
    }
    /**
     * Resolves once the runtime reflects every memory-setting edit made so far:
     * starts edits the listener has not delivered yet, then waits out backend
     * transitions and settings hooks until no new work arrives. Failed edits are
     * reported by their handler; callers inspect the settled runtime themselves.
     */
    async settle() {
        let drained;
        for (;;) {
            this.#observeSettings();
            const transition = this.#memoryBackendTransition;
            if (transition === drained && this.#settingsChanges.size === 0)
                return;
            drained = transition;
            await Promise.all([transition, ...this.#settingsChanges]);
        }
    }
    /**
     * Live memory-setting edits: switching `memory.backend` re-applies everything;
     * edits to the active backend's own `<id>.*` settings go to its
     * `applySettings` hook, or re-apply the backend when it has none.
     */
    async #applySettingsChange(changed) {
        try {
            if (changed.includes("memory.backend")) {
                await this.applyMemoryBackend();
                return;
            }
            // Queue synchronously, like a backend switch, so the next prompt's
            // transition drain orders after this edit.
            const hook = await this.#enqueueTransition(async () => {
                if (this.#host.isDisposed())
                    return undefined;
                const backend = await resolveMemoryBackend(this.#host.settings);
                const own = changed.filter(path => path.startsWith(`${backend.id}.`));
                if (own.length === 0)
                    return undefined;
                if (backend.applySettings)
                    return { backend, own };
                await this.#applyMemoryBackend(true);
                return undefined;
            });
            // Backend hooks may re-enter `applyMemoryBackend`, so they run outside the transition.
            await hook?.backend.applySettings?.(this.#host.memoryBackendSession(), hook.own);
        }
        catch (error) {
            logger.warn("Memory lifecycle: applying setting change failed", { changed, error: String(error) });
            this.#host.emitNotice("error", `Failed to apply memory settings: ${String(error)}`, "Memory");
        }
    }
    /** Current serialized backend transition, used by prompt and disposal drains. */
    get transition() {
        return this.#memoryBackendTransition;
    }
    /** Base prompt captured before a per-turn memory promotion. */
    get promotionSnapshot() {
        return this.#baseSystemPromptBeforeMemoryPromotion;
    }
    /** Clears the per-turn memory promotion after a canonical prompt rebuild. */
    clearPromotionSnapshot() {
        this.#baseSystemPromptBeforeMemoryPromotion = undefined;
    }
    /** Captures the canonical prompt before the first per-turn memory promotion. */
    capturePromotionSnapshot(prompt) {
        this.#baseSystemPromptBeforeMemoryPromotion ??= prompt;
    }
    /** Restores a promotion snapshot while rolling back a failed session switch. */
    restorePromotionSnapshot(prompt) {
        this.#baseSystemPromptBeforeMemoryPromotion = prompt;
    }
    /** Rekeys every active memory backend to the current provider session. */
    rekeyForCurrentSessionId() {
        this.#rekeyHindsightMemoryForCurrentSessionId();
        this.#rekeyMnemopiMemoryForCurrentSessionId();
    }
    #rekeyHindsightMemoryForCurrentSessionId() {
        if (cfgMemoryBackend.get(this.#host.settings) !== "hindsight")
            return;
        const sid = this.#host.agent.sessionId;
        if (!sid)
            return;
        this.#host.getHindsightSessionState()?.setSessionId(sid);
    }
    #rekeyMnemopiMemoryForCurrentSessionId() {
        if (cfgMemoryBackend.get(this.#host.settings) !== "mnemopi")
            return;
        const sid = this.#host.agent.sessionId;
        if (!sid)
            return;
        this.#host.getMnemopiSessionState()?.setSessionId(sid);
    }
    /** New transcript: reset Hindsight counters and reload its frozen mental-model snapshot. */
    #resetHindsightConversationTrackingIfHindsight() {
        if (cfgMemoryBackend.get(this.#host.settings) !== "hindsight")
            return false;
        const state = this.#host.getHindsightSessionState();
        if (!state || state.aliasOf)
            return false;
        state.resetConversationTracking();
        // Start a bounded first-turn reload without delaying /new, fork, clear, or
        // session switches. A slow result is discarded so the previous snapshot
        // remains byte-stable for this transcript (#11961).
        state.beginMentalModelsTranscriptReload();
        return true;
    }
    #resetMnemopiConversationTrackingIfMnemopi() {
        if (cfgMemoryBackend.get(this.#host.settings) !== "mnemopi")
            return false;
        const state = this.#host.getMnemopiSessionState();
        if (!state || state.aliasOf)
            return false;
        state.resetConversationTracking();
        return true;
    }
    /** Resets transcript-scoped memory counters and removes a promoted prompt. */
    async resetContextForNewTranscript() {
        const hadPromotedMemoryPrompt = this.#baseSystemPromptBeforeMemoryPromotion !== undefined;
        const resetHindsight = this.#resetHindsightConversationTrackingIfHindsight();
        const resetMnemopi = this.#resetMnemopiConversationTrackingIfMnemopi();
        if (hadPromotedMemoryPrompt) {
            this.#host.setBaseSystemPrompt(this.#baseSystemPromptBeforeMemoryPromotion);
            this.#baseSystemPromptBeforeMemoryPromotion = undefined;
        }
        if (resetHindsight || resetMnemopi || hadPromotedMemoryPrompt) {
            await this.#host.refreshBaseSystemPrompt();
        }
    }
    /** Cancel the local rollout-memory startup owned by this session. */
    cancelLocalMemoryStartup() {
        this.#localMemoryStartupAbort?.abort();
        this.#localMemoryStartupAbort = undefined;
    }
    /** Start a new local rollout-memory generation and cancel its predecessor. */
    beginLocalMemoryStartup() {
        this.cancelLocalMemoryStartup();
        const controller = new AbortController();
        this.#localMemoryStartupAbort = controller;
        return controller.signal;
    }
    /** Release the local startup slot if `signal` still owns it. */
    endLocalMemoryStartup(signal) {
        if (this.#localMemoryStartupAbort?.signal === signal)
            this.#localMemoryStartupAbort = undefined;
    }
    async #disposeMemoryBackendState(consolidateMnemopi = true, retainMnemopi = true) {
        this.cancelLocalMemoryStartup();
        try {
            releaseSharpshooterSession(this.#host.memoryBackendSession());
        }
        catch (error) {
            logger.warn("Memory lifecycle: Sharpshooter dispose failed", { error: String(error) });
        }
        const hindsight = this.#host.getHindsightSessionState();
        if (hindsight) {
            try {
                await hindsight.flushRetainQueue();
            }
            catch (error) {
                logger.warn("Memory lifecycle: Hindsight flush failed", { error: String(error) });
            }
            this.#host.setHindsightSessionState(undefined);
            hindsight.dispose();
        }
        const mnemopi = this.#host.takeMnemopiSessionState();
        if (mnemopi) {
            try {
                await mnemopi.dispose({ consolidate: consolidateMnemopi, retain: retainMnemopi });
            }
            catch (error) {
                logger.warn("Memory lifecycle: Mnemopi dispose failed", { error: String(error) });
            }
        }
    }
    /**
     * Apply the selected memory backend to runtime state, tools, and prompt.
     * Concurrent settings changes run in order and settle before the next turn;
     * requests arriving while an apply is still queued join it, since it reads
     * settings only once it starts. Cwd rebinding can disable Mnemopi
     * auto-retention without skipping its drain.
     */
    async applyMemoryBackend(options = {}) {
        if (this.#host.isDisposed())
            return;
        const retainMnemopi = options.retainMnemopi !== false;
        const queued = this.#queuedApply;
        if (queued) {
            queued.retainMnemopi &&= retainMnemopi;
            return queued.done;
        }
        const request = { retainMnemopi, done: Promise.resolve() };
        this.#queuedApply = request;
        request.done = this.#enqueueTransition(() => {
            this.#queuedApply = undefined;
            return this.#applyMemoryBackend(request.retainMnemopi);
        });
        await request.done;
    }
    /** Runs `work` after every earlier transition; its failure does not block later ones. */
    #enqueueTransition(work) {
        const transition = this.#memoryBackendTransition.then(work);
        this.#memoryBackendTransition = transition.then(() => undefined, () => undefined);
        return transition;
    }
    async #applyMemoryBackend(retainMnemopi) {
        if (this.#host.isDisposed())
            return;
        const cwd = this.#host.cwd();
        // A cwd move (or its rollback) may reach here before the rebind does:
        // drain the outgoing state without capturing the transcript under a stale scope.
        const retain = retainMnemopi && (this.#runtimeCwd ?? cwd) === cwd;
        try {
            await this.#disposeMemoryBackendState(true, retain);
            this.#runtimeCwd = cwd;
            if (this.#memoryAgentDir && this.#memoryTaskDepth === 0 && !this.#host.isDisposed()) {
                const backend = await resolveMemoryBackend(this.#host.settings);
                await backend.start({
                    session: this.#host.memoryBackendSession(),
                    settings: this.#host.settings,
                    modelRegistry: this.#host.modelRegistry,
                    agentDir: this.#memoryAgentDir,
                    taskDepth: this.#memoryTaskDepth,
                });
            }
            if (this.#host.isDisposed())
                return;
            await this.#refreshMemoryTools();
            if (this.#host.isDisposed())
                return;
            await this.#host.refreshBaseSystemPrompt();
        }
        catch (error) {
            await this.#disposeMemoryBackendState(false);
            if (!this.#host.isDisposed()) {
                await this.#replaceMemoryTools([]).catch(refreshError => {
                    logger.warn("Failed to remove memory tools after backend apply error", {
                        error: String(refreshError),
                    });
                });
            }
            throw error;
        }
    }
    async #refreshMemoryTools() {
        const tools = (await this.#createMemoryTools?.()) ?? [];
        await this.#replaceMemoryTools(tools);
    }
    #replaceMemoryTools(tools) {
        return this.#host.replaceMemoryTools(tools);
    }
}
