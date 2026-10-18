/**
 * Speech models. Defaults to the multilingual {@link DEFAULT_STT_MODEL_KEY}.
 * Whisper uses transformers.js; Parakeet and native streaming Nemotron use
 * sherpa-onnx.
 */
export const STT_MODELS = [
    {
        key: "whisper-base",
        engine: "transformers",
        repo: "onnx-community/whisper-base",
        dtype: "q8",
        englishOnly: false,
        label: "Fast (Whisper base)",
        description: "Whisper base, multilingual. Smallest + fastest; lowest accuracy. Best for low-resource machines.",
        sizeHint: "~60 MB",
    },
    {
        key: "whisper-small",
        engine: "transformers",
        repo: "onnx-community/whisper-small",
        dtype: "q8",
        englishOnly: false,
        label: "Balanced (Whisper small)",
        description: "Whisper small, multilingual. More accurate than Fast, still light on CPU/RAM.",
        sizeHint: "~190 MB",
    },
    {
        key: "whisper-large-v3-turbo",
        engine: "transformers",
        repo: "onnx-community/whisper-large-v3-turbo",
        dtype: "q4",
        englishOnly: false,
        label: "Turbo (Whisper large-v3)",
        description: "Whisper large-v3-turbo, 99 languages. Widest language coverage; large download, slower.",
        sizeHint: "~600 MB",
    },
    {
        key: "parakeet-tdt-0.6b-v3",
        engine: "sherpa",
        mode: "offline",
        repo: "csukuangfj/sherpa-onnx-nemo-parakeet-tdt-0.6b-v3-int8",
        modelType: "nemo_transducer",
        files: {
            encoder: "encoder.int8.onnx",
            decoder: "decoder.int8.onnx",
            joiner: "joiner.int8.onnx",
            tokens: "tokens.txt",
        },
        englishOnly: false,
        label: "Parakeet TDT v3 (SoTA)",
        description: "NVIDIA Parakeet TDT 0.6B v3, 25 languages. Open ASR Leaderboard leader — best accuracy and far fastest decoding. Default.",
        sizeHint: "~680 MB",
    },
    {
        key: "nemotron-streaming-en-0.6b",
        engine: "sherpa",
        mode: "online",
        repo: "csukuangfj2/sherpa-onnx-nemotron-speech-streaming-en-0.6b-160ms-int8-2026-04-25",
        modelType: "",
        files: {
            encoder: "encoder.int8.onnx",
            decoder: "decoder.int8.onnx",
            joiner: "joiner.int8.onnx",
            tokens: "tokens.txt",
        },
        englishOnly: true,
        label: "Nemotron 0.6B (live streaming, English)",
        description: "NVIDIA Nemotron Speech 0.6B, English only. Native streaming recognition with live words while you speak; 160 ms audio chunks.",
        sizeHint: "~630 MB",
    },
];
/**
 * SoTA default — NVIDIA Parakeet TDT 0.6B v3 (sherpa-onnx). Tops the Open ASR
 * Leaderboard on accuracy while decoding ~20× faster than Whisper large-v3.
 */
export const DEFAULT_STT_MODEL_KEY = "parakeet-tdt-0.6b-v3";
export const STT_MODEL_VALUES = [
    "whisper-base",
    "whisper-small",
    "whisper-large-v3-turbo",
    "parakeet-tdt-0.6b-v3",
    "nemotron-streaming-en-0.6b",
];
const STT_MODEL_VALUES_MATCH_REGISTRY = true;
void STT_MODEL_VALUES_MATCH_REGISTRY;
export const STT_MODEL_OPTIONS = STT_MODELS.map(({ key, label, description }) => ({
    value: key,
    label,
    description,
}));
export function isSttModelKey(value) {
    return STT_MODELS.some(model => model.key === value);
}
export function getSttModelSpec(key) {
    return STT_MODELS.find(model => model.key === key);
}
/** Resolve a catalog model id, falling back to the SoTA default when unknown. */
export function resolveSttModelSpec(key) {
    return (key !== undefined ? getSttModelSpec(key) : undefined) ?? getSttModelSpec(DEFAULT_STT_MODEL_KEY);
}
