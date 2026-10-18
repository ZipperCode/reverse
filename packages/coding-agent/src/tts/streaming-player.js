import { AudioPlayback } from "@rva/natives";
/** Kokoro emits 24 kHz mono PCM when a chunk does not declare a rate. */
const DEFAULT_SAMPLE_RATE = 24000;
/** Output gain applied while the user speaks over assistant audio. */
export const DUCK_GAIN = 0.25;
function errorFrom(cause) {
    return cause instanceof Error ? cause : new Error(String(cause));
}
/**
 * One native gapless playback session. Call {@link start}, enqueue mono `f32`
 * chunks with {@link write}, then {@link end} to drain or {@link stop} to abort.
 */
export class StreamingAudioPlayer {
    #native = null;
    #sampleRate = DEFAULT_SAMPLE_RATE;
    #gain = 1;
    #error = null;
    #ending = null;
    #inputClosed = false;
    #stopped = false;
    #failNative(native, cause) {
        this.#error = errorFrom(cause);
        if (this.#native === native)
            this.#native = null;
        try {
            native.stop();
        }
        catch {
            // Preserve the original playback failure.
        }
    }
    /** Opens the default speaker at the stream's logical sample rate. */
    start(sampleRate = DEFAULT_SAMPLE_RATE) {
        if (this.#native || this.#error || this.#inputClosed || this.#stopped)
            return;
        this.#sampleRate = sampleRate > 0 ? sampleRate : DEFAULT_SAMPLE_RATE;
        let native;
        try {
            native = new AudioPlayback(this.#sampleRate);
            native.setGain(this.#gain);
            this.#native = native;
        }
        catch (cause) {
            if (native)
                this.#failNative(native, cause);
            else
                this.#error = errorFrom(cause);
        }
    }
    /** Queues one mono `f32` PCM chunk without copying it in TypeScript. */
    write(pcm) {
        if (this.#inputClosed || this.#stopped || pcm.length === 0)
            return;
        if (!this.#native && !this.#error)
            this.start(this.#sampleRate);
        const native = this.#native;
        if (!native)
            return;
        try {
            native.write(pcm);
        }
        catch (cause) {
            this.#failNative(native, cause);
        }
    }
    /** Applies gain at render time, including to samples already queued natively. */
    setGain(gain) {
        if (!Number.isFinite(gain) || gain < 0)
            throw new RangeError("Audio gain must be a finite non-negative number");
        this.#gain = gain;
        const native = this.#native;
        if (!native)
            return;
        try {
            native.setGain(gain);
        }
        catch (cause) {
            this.#failNative(native, cause);
        }
    }
    /** Closes input and resolves after every queued sample reaches the speaker. */
    end() {
        if (this.#ending)
            return this.#ending;
        if (this.#stopped)
            return Promise.resolve();
        this.#inputClosed = true;
        if (this.#error) {
            this.#stopped = true;
            return Promise.reject(this.#error);
        }
        const native = this.#native;
        if (!native) {
            this.#stopped = true;
            return Promise.resolve();
        }
        this.#ending = native
            .end()
            .catch(cause => {
            throw errorFrom(cause);
        })
            .finally(() => {
            if (this.#native === native)
                this.#native = null;
            this.#stopped = true;
        });
        return this.#ending;
    }
    /** Stops immediately and discards queued audio. Safe to call repeatedly. */
    stop() {
        this.#inputClosed = true;
        this.#stopped = true;
        const native = this.#native;
        this.#native = null;
        if (!native)
            return;
        try {
            native.stop();
        }
        catch {
            // Best-effort abort during session teardown.
        }
    }
}
/** Creates the single-use player used by the speech vocalizer. */
export function createStreamingPlayer() {
    return new StreamingAudioPlayer();
}
