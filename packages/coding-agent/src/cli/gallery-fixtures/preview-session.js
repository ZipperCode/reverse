import { Settings } from "../../config/settings";
export const GALLERY_CONTEXT_WINDOW = 200000;
/** Deterministic session double for production composer/status renderers. */
export function createGallerySession(options = {}) {
    const contextTokens = options.contextTokens ?? 124000;
    const model = {
        id: "claude-sonnet-4-5",
        name: "Claude Sonnet 4.5",
        contextWindow: GALLERY_CONTEXT_WINDOW,
        thinking: true,
        provider: "anthropic",
    };
    const messages = [{ role: "user", content: "Show the production preview" }];
    const goalStatus = options.goalStatus ?? "active";
    return {
        messages,
        systemPrompt: [],
        agent: { state: { tools: [] } },
        skills: [],
        model,
        state: { messages, model, thinkingLevel: "high" },
        isAutoThinking: false,
        autoResolvedThinkingLevel: () => undefined,
        isStreaming: false,
        modelRegistry: { isUsingOAuth: () => options.usingSubscription ?? false },
        settings: Settings.isolated({ "goal.statusInFooter": true, "compaction.reserveTokens": 20000 }),
        sessionManager: {
            getUsageStatistics: () => ({
                input: 12400,
                output: 3600,
                cacheRead: 48000,
                cacheWrite: 1200,
                totalTokens: 65200,
                orchestrationInput: 900,
                orchestrationOutput: 240,
                orchestrationCacheRead: 3000,
                premiumRequests: options.premiumRequests ?? 2,
                cost: options.cost ?? 0.42,
            }),
            getSessionName: () => "gallery",
            getSessionId: () => "gallery-session-id",
        },
        getAsyncJobSnapshot: () => ({ running: [] }),
        isFastModeActive: () => options.fastMode ?? false,
        getContextUsage: () => ({
            tokens: contextTokens,
            contextWindow: GALLERY_CONTEXT_WINDOW,
            percent: (contextTokens / GALLERY_CONTEXT_WINDOW) * 100,
        }),
        contextUsageRevision: 0,
        getGoalModeState: () => ({
            goal: { status: goalStatus, tokensUsed: 12400, tokenBudget: 50000 },
        }),
        getAdvisorStatusOverview: () => options.advisorStatus
            ? {
                configured: true,
                advisors: [{ status: options.advisorStatus, yielded: options.advisorYielded ?? false }],
            }
            : { configured: false, advisors: [] },
        getAdvisorCost: () => options.advisorCost ?? 0.08,
        isAdvisorUsingSubscription: () => false,
        getPrewalkState: () => false,
        compactionSpeculation: "idle",
    };
}
