import { logger } from "@rva/utils";
import { resolveRoleChain } from "../config/model-resolver";
import { roleCandidatePool } from "../config/model-roles";
import { settings } from "../config/settings";
import { DEFAULT_TTS_VOICE, TTS_LOCAL_MODELS } from "./models";
import { SpeakableStream } from "./speakable";
import { BlockAccumulator } from "./speech-enhancer";
import { createStreamingPlayer, DUCK_GAIN } from "./streaming-player";
import { ttsClient } from "./tts-client";
import { cfgSpeechEnabled, cfgSpeechEnhanced, cfgSpeechSpeed, cfgSpeechVoice } from "./settings";
/** Quiet time on the delta stream before the buffered partial is spoken. */
const IDLE_FLUSH_MS = 1000;
/** Coalesce completed blocks until this many chars before one rewrite call. */
const COALESCE_MIN_CHARS = 400;
/** Bounded rewrite concurrency across utterances. */
const MAX_REWRITES_IN_FLIGHT = 2;
/** Resolve the first speech-role candidate that the local streaming worker can run. */
export function resolveLocalSpeechModelId(source) {
    const pool = roleCandidatePool("speech", source.settings, source.registry);
    const local = resolveRoleChain("speech", source.settings, pool).find(candidate => candidate.model.api === "local-inference");
    return local?.model.id ?? TTS_LOCAL_MODELS[0].key;
}
export class Vocalizer {
    /** Mechanical mode: open stream session for the current utterance. */
    #handle = null;
    /** Mechanical mode: markdown → segment transform for the current utterance. */
    #speakable = null;
    /** Enhanced mode: the utterance currently receiving deltas. */
    #enhanced = null;
    /** Per-session rewrite service; wired by the event controller, null elsewhere. */
    #enhancer = null;
    /** Live per-session settings and registry used to resolve the speech role. */
    #modelSource = null;
    /** Fires when the delta stream goes quiet mid-sentence; speaks the partial. */
    #idleTimer = null;
    /** Abort controllers of every not-yet-finished utterance; all aborted on {@link clear}. */
    #liveAborts = new Set();
    /** Players of every not-yet-finished utterance; ducked together, stopped on {@link clear}. */
    #livePlayers = new Set();
    /** Serialized playback chain across utterances; awaited by {@link idle}. */
    #chain = Promise.resolve();
    /** Whether the user is currently speaking; new sessions open ducked. */
    #ducked = false;
    /** Active scopes that suppress local TTS while another speech surface owns audio. */
    #suspensions = 0;
    /** Available rewrite slots; blocks queue when exhausted. */
    #rewriteSlots = MAX_REWRITES_IN_FLIGHT;
    #slotWaiters = [];
    #createPlayer;
    constructor(createPlayer = createStreamingPlayer) {
        this.#createPlayer = createPlayer;
    }
    /** Wire (or drop) the per-session enhanced-rewrite service. */
    setEnhancer(enhancer) {
        this.#enhancer = enhancer;
    }
    /** Wire (or drop) the live per-session model source used by local speech synthesis. */
    setModelSource(source) {
        this.#modelSource = source;
    }
    /**
     * Suppress new vocalization until the returned idempotent release function runs.
     * Existing synthesis and playback stop immediately; nested scopes release independently.
     */
    suspend() {
        this.#suspensions += 1;
        this.clear();
        let released = false;
        return () => {
            if (released)
                return;
            released = true;
            this.#suspensions = Math.max(0, this.#suspensions - 1);
        };
    }
    /**
     * Stream a delta of assistant text into the pipeline. No-op when
     * vocalization is disabled. The synthesis session (worker, player) is only
     * opened once the first speakable segment exists, so a reply that
     * normalizes to silence (pure code, tables, URLs) costs nothing. The
     * trailing partial is flushed by {@link flush} or the idle timer. The
     * pipeline (enhanced vs mechanical) is latched per utterance.
     */
    pushDelta(text) {
        const speechSettings = this.#modelSource?.settings ?? settings;
        if (this.#suspensions > 0 || !cfgSpeechEnabled.get(speechSettings))
            return;
        if (!text)
            return;
        if (this.#enhanced || (!this.#speakable && this.#enhancer && cfgSpeechEnhanced.get(speechSettings))) {
            this.#pushEnhanced(text);
            return;
        }
        this.#speakable ??= new SpeakableStream();
        const speakable = this.#speakable;
        this.#pushSegments(speakable.push(text));
        this.#armIdle(() => {
            if (this.#speakable !== speakable)
                return;
            this.#pushSegments(speakable.flushIdle());
        });
    }
    /**
     * Close the current input stream (call at message/turn end). Drains the
     * trailing partial as final segments; in enhanced mode the session ends
     * only after the last in-flight rewrite has pushed, while the next
     * utterance may already be streaming.
     */
    flush() {
        this.#clearIdleTimer();
        const utterance = this.#enhanced;
        if (utterance) {
            this.#enhanced = null;
            const last = utterance.blocks.flush();
            if (last !== null) {
                utterance.pending.push(last);
                utterance.pendingChars += last.length;
            }
            this.#dispatchPending(utterance);
            utterance.order = utterance.order.then(() => {
                if (utterance.abort.signal.aborted)
                    return;
                utterance.handle?.end();
                // A rewrite-only utterance (nothing speakable, no session) has no
                // playback teardown to reap its abort controller — do it here.
                if (!utterance.handle)
                    this.#liveAborts.delete(utterance.abort);
            });
            return;
        }
        const speakable = this.#speakable;
        this.#speakable = null;
        if (speakable)
            this.#pushSegments(speakable.flush());
        this.#handle?.end();
        this.#handle = null;
    }
    /**
     * Speak a complete piece of text in one shot (ask questions, yield-mode final
     * message): stream it in and immediately close the input. No-op when disabled.
     */
    speak(text) {
        this.pushDelta(text);
        this.flush();
    }
    /**
     * Interrupt and drop every utterance, killing in-flight playback, synthesis,
     * and rewrites (new turn / user message / Esc interrupt). Audio stops at once.
     */
    clear() {
        this.#clearIdleTimer();
        this.#enhanced = null;
        this.#speakable = null;
        this.#handle = null;
        for (const abort of this.#liveAborts)
            abort.abort();
        this.#liveAborts.clear();
        for (const player of this.#livePlayers)
            player.stop();
        this.#livePlayers.clear();
    }
    /**
     * True while any utterance is still audible or synthesizing — a live
     * player, an unfinished stream handle, or an in-flight rewrite is enough.
     * Callers (Esc handler) treat this as the "silence me" signal.
     */
    isSpeaking() {
        return this.#livePlayers.size > 0 || this.#liveAborts.size > 0 || this.#handle !== null;
    }
    /** Lower the volume while the user is speaking (push-to-talk), so speech doesn't drown them out. */
    duck() {
        this.#ducked = true;
        for (const player of this.#livePlayers)
            player.setGain(DUCK_GAIN);
    }
    /** Restore full volume once the user stops speaking. */
    unduck() {
        this.#ducked = false;
        for (const player of this.#livePlayers)
            player.setGain(1);
    }
    /** Resolve once the playback chain has drained (tests / shutdown). */
    idle() {
        return this.#chain;
    }
    // --- Enhanced pipeline ---------------------------------------------------
    #pushEnhanced(text) {
        if (!this.#enhanced)
            this.#enhanced = this.#newEnhancedUtterance();
        const utterance = this.#enhanced;
        for (const block of utterance.blocks.push(text)) {
            utterance.pending.push(block);
            utterance.pendingChars += block.length;
            // The first rewrite dispatches immediately for fast first audio;
            // later blocks coalesce so a heading and its list cost one call.
            if (!utterance.dispatchedFirst || utterance.pendingChars >= COALESCE_MIN_CHARS) {
                this.#dispatchPending(utterance);
            }
        }
        this.#armIdle(() => {
            if (this.#enhanced !== utterance)
                return;
            const partial = utterance.blocks.flushPartial();
            if (partial !== null) {
                utterance.pending.push(partial);
                utterance.pendingChars += partial.length;
            }
            this.#dispatchPending(utterance);
        });
    }
    #newEnhancedUtterance() {
        const abort = new AbortController();
        this.#liveAborts.add(abort);
        return {
            blocks: new BlockAccumulator(),
            speakable: new SpeakableStream(),
            pending: [],
            pendingChars: 0,
            dispatchedFirst: false,
            order: Promise.resolve(),
            handle: null,
            abort,
        };
    }
    /**
     * Send the coalesced pending blocks to the rewriter and chain the ordered
     * push of the result. The completion runs concurrently (bounded by the
     * slot pool); only the push into the synthesizer is serialized, so block
     * N+1's rewrite overlaps block N's synthesis.
     */
    #dispatchPending(utterance) {
        if (utterance.pending.length === 0)
            return;
        const block = utterance.pending.join("\n\n");
        utterance.pending = [];
        utterance.pendingChars = 0;
        utterance.dispatchedFirst = true;
        const result = this.#boundedRewrite(block, utterance.abort.signal);
        utterance.order = utterance.order.then(async () => {
            const rewritten = await result;
            if (utterance.abort.signal.aborted)
                return;
            // Empty string: the model judged the block unspeakable (pure code).
            if (rewritten === "")
                return;
            // Null: rewrite failed/timed out — mechanical cleanup of the raw
            // block via the SpeakableStream keeps speech flowing.
            const spoken = rewritten ?? block;
            const segments = utterance.speakable.push(spoken.endsWith("\n") ? spoken : `${spoken}\n`);
            if (segments.length === 0)
                return;
            if (!utterance.handle)
                utterance.handle = this.#openSession(utterance.abort);
            for (const segment of segments)
                utterance.handle.push(segment);
        });
    }
    /** Run one rewrite through the bounded slot pool; never rejects. */
    async #boundedRewrite(block, signal) {
        await this.#acquireSlot();
        try {
            if (signal.aborted || !this.#enhancer)
                return null;
            return await this.#enhancer.rewrite(block, signal);
        }
        finally {
            this.#releaseSlot();
        }
    }
    #acquireSlot() {
        if (this.#rewriteSlots > 0) {
            this.#rewriteSlots--;
            return Promise.resolve();
        }
        const { promise, resolve } = Promise.withResolvers();
        this.#slotWaiters.push(resolve);
        return promise;
    }
    #releaseSlot() {
        const next = this.#slotWaiters.shift();
        if (next)
            next();
        else
            this.#rewriteSlots++;
    }
    // --- Shared synthesis/playback tail --------------------------------------
    /** Mechanical mode: feed ready segments, opening the session lazily. */
    #pushSegments(segments) {
        if (segments.length === 0)
            return;
        if (!this.#handle) {
            const abort = new AbortController();
            this.#liveAborts.add(abort);
            this.#handle = this.#openSession(abort);
        }
        for (const segment of segments)
            this.#handle.push(segment);
    }
    /**
     * Open a streaming-synthesis session and chain its playback after any
     * prior utterance's, so sequential utterances never overlap.
     */
    #openSession(abort) {
        const source = this.#modelSource;
        const modelKey = source ? resolveLocalSpeechModelId(source) : TTS_LOCAL_MODELS[0].key;
        const sessionSettings = source?.settings ?? settings;
        const voice = cfgSpeechVoice.get(sessionSettings) || DEFAULT_TTS_VOICE;
        const speed = cfgSpeechSpeed.get(sessionSettings);
        const handle = ttsClient.synthesizeStream(modelKey, { voice, speed, signal: abort.signal });
        const player = this.#createPlayer();
        player.setGain(this.#ducked ? DUCK_GAIN : 1);
        this.#liveAborts.add(abort);
        this.#livePlayers.add(player);
        this.#chain = this.#chain.then(async () => {
            try {
                await this.#play(handle, player, abort.signal);
            }
            finally {
                this.#liveAborts.delete(abort);
                this.#livePlayers.delete(player);
            }
        });
        return handle;
    }
    /**
     * (Re)arm the stall timer: if no delta arrives for {@link IDLE_FLUSH_MS},
     * speak buffered text instead of holding it through a tool call or
     * thinking block. The callback checks utterance identity itself.
     */
    #armIdle(onIdle) {
        this.#clearIdleTimer();
        const timer = setTimeout(() => {
            this.#idleTimer = null;
            onIdle();
        }, IDLE_FLUSH_MS);
        timer.unref?.();
        this.#idleTimer = timer;
    }
    #clearIdleTimer() {
        if (this.#idleTimer === null)
            return;
        clearTimeout(this.#idleTimer);
        this.#idleTimer = null;
    }
    /** Feed each synthesized segment into the player in arrival order; abort stops it. */
    async #play(handle, player, signal) {
        let started = false;
        try {
            for await (const chunk of handle.chunks) {
                if (signal.aborted)
                    break;
                if (!started) {
                    player.start(chunk.sampleRate);
                    started = true;
                }
                player.write(chunk.pcm);
            }
            if (started && !signal.aborted) {
                await player.end();
                return;
            }
        }
        catch (error) {
            logger.debug("vocalizer: stream failed", {
                error: error instanceof Error ? error.message : String(error),
            });
        }
        player.stop();
    }
}
/** Process-level vocalizer shared by the event controller and the ask tool. */
export const vocalizer = new Vocalizer();
