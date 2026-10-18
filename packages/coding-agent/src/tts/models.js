/**
 * Curated Kokoro-82M voice catalog. Kokoro ships ~28 voices; we surface the
 * higher-graded ones across American/British × female/male so the picker stays
 * useful without listing every D/F-grade sample. `af_heart` (grade A) leads and
 * is the default voice. Grades are Kokoro's own `overallGrade` ratings.
 */
export const KOKORO_VOICES = [
    { id: "af_heart", label: "Heart (American female)" },
    { id: "af_bella", label: "Bella (American female)" },
    { id: "af_nicole", label: "Nicole (American female)" },
    { id: "af_aoede", label: "Aoede (American female)" },
    { id: "af_kore", label: "Kore (American female)" },
    { id: "af_sarah", label: "Sarah (American female)" },
    { id: "am_michael", label: "Michael (American male)" },
    { id: "am_fenrir", label: "Fenrir (American male)" },
    { id: "am_puck", label: "Puck (American male)" },
    { id: "bf_emma", label: "Emma (British female)" },
    { id: "bm_george", label: "George (British male)" },
    { id: "bm_fable", label: "Fable (British male)" },
];
/** Default voice within the default model — Kokoro's flagship grade-A voice. */
export const DEFAULT_TTS_VOICE = "af_heart";
/**
 * Local TTS model registry. Kokoro-82M is the on-device SoTA tiny TTS (tops the
 * TTS Arena leaderboard); the `onnx-community` ONNX export runs through
 * `kokoro-js` on the shared transformers.js/onnxruntime worker. q8 keeps the
 * weights ~100 MB and CPU inference fast while preserving quality. One model
 * spans every voice/accent — language selection is a voice choice, not a
 * separate download.
 */
export const TTS_LOCAL_MODELS = [
    {
        key: "kokoro",
        repo: "onnx-community/Kokoro-82M-v1.0-ONNX",
        dtype: "q8",
        sampleRate: 24000,
        label: "Kokoro-82M",
        description: "Kokoro-82M neural TTS — SoTA on-device quality, multi-voice, fully local",
        voices: KOKORO_VOICES,
    },
];
/** Voice options for the `tts.localVoice` setting picker (default model's catalog). */
export const TTS_LOCAL_VOICE_OPTIONS = KOKORO_VOICES.map(voice => ({
    value: voice.id,
    label: voice.label,
}));
/** Accepted `tts.localVoice` values (default model's catalog) for schema validation. */
export const TTS_LOCAL_VOICE_VALUES = KOKORO_VOICES.map(voice => voice.id);
export function getTtsLocalModelSpec(key) {
    return TTS_LOCAL_MODELS.find(model => model.key === key);
}
export function isTtsLocalModelKey(value) {
    return getTtsLocalModelSpec(value) !== undefined;
}
/** Resolve a model key (or the default) to its Hugging Face repo id. */
export function resolveTtsRepo(modelKey) {
    const fallbackKey = TTS_LOCAL_MODELS[0].key;
    const spec = (modelKey && getTtsLocalModelSpec(modelKey)) || getTtsLocalModelSpec(fallbackKey);
    if (!spec)
        throw new Error(`No local TTS model registered for key: ${modelKey ?? fallbackKey}`);
    return spec.repo;
}
/**
 * Resolve a requested voice id to a concrete voice the model supports, falling
 * back to the model's default voice (first entry) when the id is unknown or the
 * legacy `"default"` sentinel. The returned id is always a valid Kokoro voice.
 */
export function resolveTtsVoice(modelKey, voice) {
    const spec = (modelKey && getTtsLocalModelSpec(modelKey)) || getTtsLocalModelSpec(TTS_LOCAL_MODELS[0].key);
    const fallback = spec?.voices[0]?.id ?? DEFAULT_TTS_VOICE;
    if (!spec || !voice)
        return fallback;
    const match = spec.voices.find(v => v.id === voice);
    return match ? match.id : fallback;
}
/** Kokoro's native speaking rate; also the value used when no speed is configured. */
export const DEFAULT_TTS_SPEED = 1;
/**
 * Accepted speaking-rate band. Kokoro takes any positive float, but intelligibility
 * collapses well outside this range.
 */
export const TTS_SPEED_MIN = 0.5;
export const TTS_SPEED_MAX = 2.5;
/** Speed presets for the `tts.localSpeed` / `speech.speed` setting pickers. */
export const TTS_SPEED_OPTIONS = [
    { value: "0.5", label: "0.5×" },
    { value: "0.75", label: "0.75×" },
    { value: "1", label: "1× (normal)" },
    { value: "1.25", label: "1.25×" },
    { value: "1.5", label: "1.5×" },
    { value: "1.75", label: "1.75×" },
    { value: "2", label: "2×" },
    { value: "2.5", label: "2.5×" },
];
/**
 * Resolve a requested speaking rate to one Kokoro is given: clamped into
 * [{@link TTS_SPEED_MIN}, {@link TTS_SPEED_MAX}], or {@link DEFAULT_TTS_SPEED}
 * when missing or not a finite number.
 */
export function resolveTtsSpeed(speed) {
    if (speed === undefined || !Number.isFinite(speed))
        return DEFAULT_TTS_SPEED;
    return Math.min(TTS_SPEED_MAX, Math.max(TTS_SPEED_MIN, speed));
}
