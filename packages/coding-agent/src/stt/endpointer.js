/**
 * Energy-based speech endpointer for live transcription.
 *
 * The on-device ASR models we ship are non-streaming: the sherpa-onnx Parakeet
 * recognizer and the transformers.js Whisper pipelines both decode a complete
 * waveform in one shot. To transcribe *while the user is still speaking*, this
 * splits the continuous 16 kHz mono float stream into speech segments at natural
 * pauses — each segment is decoded and committed as it finalizes, and the
 * in-progress segment is re-decoded periodically for a volatile live preview.
 *
 * Segmentation is pure short-time-energy VAD with an adaptive noise floor, so it
 * needs no extra model and is engine-agnostic (it runs the same way whether the
 * downstream model is sherpa or transformers). It is deliberately simple and
 * fully deterministic so it can be unit-tested with synthetic signals.
 */
export const DEFAULT_ENDPOINTER_CONFIG = {
    sampleRate: 16000,
    frameMs: 30,
    endSilenceMs: 600,
    minSpeechMs: 200,
    maxSegmentMs: 12000,
    preRollMs: 240,
    partialIntervalMs: 450,
    energyRatio: 2.5,
    floorAttack: 0.05,
    minThreshold: 0.008,
};
/** Append-growable Float32 buffer (amortized O(1) push, no per-frame realloc). */
class FloatBuffer {
    #data = new Float32Array(0);
    #len = 0;
    get length() {
        return this.#len;
    }
    push(samples) {
        const needed = this.#len + samples.length;
        if (needed > this.#data.length) {
            const next = new Float32Array(Math.max(this.#data.length * 2, needed, 1 << 14));
            next.set(this.#data.subarray(0, this.#len));
            this.#data = next;
        }
        this.#data.set(samples, this.#len);
        this.#len += samples.length;
    }
    /** Copy `[0, end)` into a fresh array the caller can retain. */
    take(end = this.#len) {
        return this.#data.slice(0, Math.max(0, Math.min(end, this.#len)));
    }
    reset() {
        this.#len = 0;
    }
}
/** Fixed-capacity ring keeping the most recent `capacity` samples. */
class FloatRing {
    #data;
    #start = 0;
    #len = 0;
    constructor(capacity) {
        this.#data = new Float32Array(capacity);
    }
    push(samples) {
        const cap = this.#data.length;
        if (cap === 0)
            return;
        if (samples.length >= cap) {
            this.#data.set(samples.subarray(samples.length - cap));
            this.#start = 0;
            this.#len = cap;
            return;
        }
        const pos = (this.#start + this.#len) % cap;
        const first = Math.min(samples.length, cap - pos);
        this.#data.set(samples.subarray(0, first), pos);
        if (first < samples.length)
            this.#data.set(samples.subarray(first), 0);
        const total = this.#len + samples.length;
        if (total > cap) {
            this.#start = (this.#start + total - cap) % cap;
            this.#len = cap;
        }
        else {
            this.#len = total;
        }
    }
    /** Append the retained samples, oldest first, to `target`. */
    copyInto(target) {
        const cap = this.#data.length;
        const end = this.#start + this.#len;
        target.push(this.#data.subarray(this.#start, Math.min(end, cap)));
        if (end > cap)
            target.push(this.#data.subarray(0, end - cap));
    }
    reset() {
        this.#start = 0;
        this.#len = 0;
    }
}
function rms(frame) {
    let sum = 0;
    for (let i = 0; i < frame.length; i += 1)
        sum += frame[i] * frame[i];
    return Math.sqrt(sum / Math.max(1, frame.length));
}
export class StreamEndpointer {
    #cfg;
    #frameSamples;
    #preRollSamples;
    /** Partial frame carried to the next push; always shorter than one frame. */
    #leftover;
    #leftoverLen = 0;
    #inSpeech = false;
    #noiseFloor;
    #silenceMs = 0;
    #segmentMs = 0;
    #msSincePartial = 0;
    #partialDirty = false;
    #segment = new FloatBuffer();
    /** Ring of the most recent pre-onset samples, used as segment pre-roll. */
    #preRoll;
    constructor(config = {}) {
        this.#cfg = { ...DEFAULT_ENDPOINTER_CONFIG, ...config };
        this.#frameSamples = Math.max(1, Math.round((this.#cfg.sampleRate * this.#cfg.frameMs) / 1000));
        this.#preRollSamples = Math.max(0, Math.round((this.#cfg.sampleRate * this.#cfg.preRollMs) / 1000));
        this.#leftover = new Float32Array(this.#frameSamples);
        this.#preRoll = new FloatRing(this.#preRollSamples);
        this.#noiseFloor = this.#cfg.minThreshold;
    }
    /** Feed newly-captured samples; returns ordered partial/segment events. */
    push(samples) {
        const events = [];
        const frame = this.#frameSamples;
        let offset = 0;
        // Complete the carried-over partial frame first, then consume whole frames in place.
        if (this.#leftoverLen > 0) {
            const fill = Math.min(frame - this.#leftoverLen, samples.length);
            this.#leftover.set(samples.subarray(0, fill), this.#leftoverLen);
            this.#leftoverLen += fill;
            offset = fill;
            if (this.#leftoverLen < frame)
                return events;
            this.#processFrame(this.#leftover, events);
            this.#leftoverLen = 0;
        }
        for (; offset + frame <= samples.length; offset += frame) {
            this.#processFrame(samples.subarray(offset, offset + frame), events);
        }
        if (offset < samples.length) {
            this.#leftover.set(samples.subarray(offset));
            this.#leftoverLen = samples.length - offset;
        }
        return events;
    }
    /** End the stream; returns a trailing committed segment if one is pending. */
    flush() {
        const events = [];
        if (this.#inSpeech && this.#leftoverLen > 0) {
            this.#segment.push(this.#leftover.subarray(0, this.#leftoverLen));
            this.#segmentMs += (this.#leftoverLen / this.#cfg.sampleRate) * 1000;
        }
        this.#leftoverLen = 0;
        if (this.#inSpeech) {
            const speechMs = this.#segmentMs - this.#silenceMs;
            if (speechMs >= this.#cfg.minSpeechMs) {
                events.push({ kind: "segment", audio: this.#segment.take(this.#endpointKeep()) });
            }
        }
        this.#reset();
        return events;
    }
    #processFrame(frame, events) {
        const energy = rms(frame);
        const threshold = Math.max(this.#cfg.minThreshold, this.#noiseFloor * this.#cfg.energyRatio);
        const voiced = energy > threshold;
        // Track ambient noise on non-speech frames only, so loud speech never
        // inflates the floor (which would make the tail of an utterance read as
        // silence and clip the segment short).
        if (!voiced) {
            this.#noiseFloor = this.#noiseFloor * (1 - this.#cfg.floorAttack) + energy * this.#cfg.floorAttack;
        }
        if (!this.#inSpeech) {
            this.#preRoll.push(frame);
            if (voiced)
                this.#beginSegment(frame);
            return;
        }
        this.#segment.push(frame);
        this.#segmentMs += this.#cfg.frameMs;
        this.#msSincePartial += this.#cfg.frameMs;
        if (voiced) {
            this.#silenceMs = 0;
            this.#partialDirty = true;
        }
        else {
            this.#silenceMs += this.#cfg.frameMs;
        }
        if (this.#silenceMs >= this.#cfg.endSilenceMs) {
            this.#finalizeSegment(events);
            return;
        }
        if (this.#segmentMs >= this.#cfg.maxSegmentMs) {
            // Pause-free long speech: commit what we have and continue a fresh
            // segment so output keeps flowing.
            events.push({ kind: "segment", audio: this.#segment.take() });
            this.#segment.reset();
            this.#segmentMs = 0;
            this.#silenceMs = 0;
            this.#msSincePartial = 0;
            this.#partialDirty = false;
            return;
        }
        if (this.#partialDirty && this.#msSincePartial >= this.#cfg.partialIntervalMs) {
            events.push({ kind: "partial", audio: this.#segment.take() });
            this.#msSincePartial = 0;
            this.#partialDirty = false;
        }
    }
    #beginSegment(onsetFrame) {
        this.#inSpeech = true;
        this.#segment.reset();
        this.#preRoll.copyInto(this.#segment);
        this.#segment.push(onsetFrame);
        this.#preRoll.reset();
        this.#silenceMs = 0;
        this.#segmentMs = (this.#segment.length / this.#cfg.sampleRate) * 1000;
        this.#msSincePartial = 0;
        this.#partialDirty = true;
    }
    #finalizeSegment(events) {
        const speechMs = this.#segmentMs - this.#silenceMs;
        if (speechMs >= this.#cfg.minSpeechMs) {
            events.push({ kind: "segment", audio: this.#segment.take(this.#endpointKeep()) });
        }
        this.#inSpeech = false;
        this.#segment.reset();
        this.#silenceMs = 0;
        this.#segmentMs = 0;
        this.#msSincePartial = 0;
        this.#partialDirty = false;
    }
    /** Samples to keep when committing on silence: drop most of the trailing
     *  silence but leave a short tail so the final word is not cut. */
    #endpointKeep() {
        const tailMs = Math.min(this.#silenceMs, 120);
        const dropMs = Math.max(0, this.#silenceMs - tailMs);
        const drop = Math.round((this.#cfg.sampleRate * dropMs) / 1000);
        return Math.max(0, this.#segment.length - drop);
    }
    #reset() {
        this.#inSpeech = false;
        this.#segment.reset();
        this.#preRoll.reset();
        this.#silenceMs = 0;
        this.#segmentMs = 0;
        this.#msSincePartial = 0;
        this.#partialDirty = false;
        this.#noiseFloor = this.#cfg.minThreshold;
    }
}
