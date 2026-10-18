import { cfgHindsightApiToken, cfgHindsightApiUrl, cfgHindsightAutoRecall, cfgHindsightAutoRetain, cfgHindsightBankId, cfgHindsightBankIdPrefix, cfgHindsightBankMission, cfgHindsightDebug, cfgHindsightMentalModelAutoSeed, cfgHindsightMentalModelMaxRenderChars, cfgHindsightMentalModelsEnabled, cfgHindsightRecallBudget, cfgHindsightRecallContextTurns, cfgHindsightRecallMaxQueryChars, cfgHindsightRecallMaxTokens, cfgHindsightRecallTimeoutMs, cfgHindsightRecallTypes, cfgHindsightReflectTimeoutMs, cfgHindsightRequestTimeoutMs, cfgHindsightRetainContext, cfgHindsightRetainEveryNTurns, cfgHindsightRetainMission, cfgHindsightRetainMode, cfgHindsightRetainOverlapTurns, cfgHindsightRetainTimeoutMs, cfgHindsightScoping, } from "./settings";
const DEFAULT_PREAMBLE = "Relevant memories from past conversations (prioritize recent when conflicting). " +
    "Only use memories that are directly useful to continue this conversation; ignore the rest:";
/**
 * Load the resolved Hindsight config. `HINDSIGHT_*` environment variables override settings
 * through the setting definitions (`hindsight/settings.ts`); invalid values fall back to defaults.
 */
export function loadHindsightConfig(settings) {
    const config = {
        hindsightApiUrl: cfgHindsightApiUrl.get(settings),
        hindsightApiToken: cfgHindsightApiToken.get(settings) ?? null,
        bankId: cfgHindsightBankId.get(settings) ?? null,
        bankIdPrefix: cfgHindsightBankIdPrefix.get(settings) ?? "",
        scoping: cfgHindsightScoping.get(settings),
        bankMission: cfgHindsightBankMission.get(settings) ?? "",
        retainMission: cfgHindsightRetainMission.get(settings) ?? null,
        autoRecall: cfgHindsightAutoRecall.get(settings),
        autoRetain: cfgHindsightAutoRetain.get(settings),
        retainMode: cfgHindsightRetainMode.get(settings),
        retainEveryNTurns: cfgHindsightRetainEveryNTurns.get(settings),
        retainOverlapTurns: cfgHindsightRetainOverlapTurns.get(settings),
        retainContext: cfgHindsightRetainContext.get(settings),
        recallBudget: cfgHindsightRecallBudget.get(settings),
        recallMaxTokens: cfgHindsightRecallMaxTokens.get(settings),
        recallTypes: [...cfgHindsightRecallTypes.get(settings)],
        recallContextTurns: cfgHindsightRecallContextTurns.get(settings),
        recallMaxQueryChars: cfgHindsightRecallMaxQueryChars.get(settings),
        recallPromptPreamble: DEFAULT_PREAMBLE,
        debug: cfgHindsightDebug.get(settings),
        requestTimeoutMs: cfgHindsightRequestTimeoutMs.get(settings),
        reflectTimeoutMs: cfgHindsightReflectTimeoutMs.get(settings),
        recallTimeoutMs: cfgHindsightRecallTimeoutMs.get(settings),
        retainTimeoutMs: cfgHindsightRetainTimeoutMs.get(settings),
        mentalModelsEnabled: cfgHindsightMentalModelsEnabled.get(settings),
        mentalModelAutoSeed: cfgHindsightMentalModelAutoSeed.get(settings),
        mentalModelMaxRenderChars: cfgHindsightMentalModelMaxRenderChars.get(settings),
    };
    return config;
}
/** Whether the caller has enough config to talk to a Hindsight server. */
export function isHindsightConfigured(config) {
    return typeof config.hindsightApiUrl === "string" && config.hindsightApiUrl.length > 0;
}
