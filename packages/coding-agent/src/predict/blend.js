/** N-gram's share of the blend; SmolLM gets the rest. */
const NGRAM_WEIGHT = 0.3;
/** Minimum blended score to show a ghost. */
const SHOW_THRESHOLD = 0.05;
/** Blend both engines' answers for one query; `null` shows nothing. */
export function blendPredictions(ngram, smollm) {
    const agree = ngram && smollm && ngram.suffix.toLowerCase() === smollm.suffix.toLowerCase();
    const shared = agree ? NGRAM_WEIGHT * ngram.confidence + (1 - NGRAM_WEIGHT) * smollm.confidence : 0;
    const ngramScore = agree ? shared : ngram ? NGRAM_WEIGHT * ngram.confidence : 0;
    const smollmScore = agree ? shared : smollm ? (1 - NGRAM_WEIGHT) * smollm.confidence : 0;
    const pick = ngramScore >= smollmScore ? ngram : smollm;
    const confidence = Math.max(ngramScore, smollmScore);
    return pick && confidence >= SHOW_THRESHOLD ? { suffix: pick.suffix, confidence } : null;
}
