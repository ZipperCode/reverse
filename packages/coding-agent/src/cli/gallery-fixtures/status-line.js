/**
 * Gallery fixture for the status-line context gauge — the box top border that
 * bridges the segment groups. Renders the real `StatusLineComponent` against a
 * fake session at four usage levels, mapping the gallery lifecycle states to
 * fill levels; `error` shows the >100% overflow case (usage anchored to a
 * larger window than the active model's, e.g. after switching to a smaller
 * model mid-session), where the gauge clamps to full while the context_pct
 * segment reports the raw percent.
 */
import { StatusLineComponent } from "@rva/tui/status-line";
import { statusLineHost } from "../../modes/status-line-host";
import { theme } from "@rva/tui/theme";
const GAUGE_WINDOW = 200000;
/** Simulated usage per gallery lifecycle state, against {@link GAUGE_WINDOW}. */
const GAUGE_CASES = {
    streaming: { tokens: 6000, note: "3% used — fresh session" },
    progress: { tokens: 124000, note: "62% used — warning zone" },
    success: { tokens: 194000, note: "97% used — past compaction threshold" },
    error: { tokens: 240000, note: "120% used — overflow: percent breaks past the window label in red" },
};
/** Minimal session double satisfying every query `getTopBorder` makes. */
function fakeGaugeSession(tokens) {
    const model = { id: "test-model", contextWindow: GAUGE_WINDOW };
    const messages = [{ role: "user", content: "hi" }];
    return {
        messages,
        systemPrompt: [],
        agent: { state: { tools: [] } },
        skills: [],
        model,
        modelRegistry: { isUsingOAuth: () => false },
        state: { messages, model },
        settings: undefined,
        sessionManager: {
            getUsageStatistics: () => ({
                input: 0,
                output: 0,
                cacheRead: 0,
                cacheWrite: 0,
                totalTokens: 0,
                orchestrationInput: 0,
                orchestrationOutput: 0,
                orchestrationCacheRead: 0,
                premiumRequests: 0,
                cost: 0,
            }),
            getSessionName: () => "gallery",
        },
        getAsyncJobSnapshot: () => ({ running: [] }),
        isFastModeActive: () => false,
        getContextUsage: () => ({ tokens, contextWindow: GAUGE_WINDOW, percent: (tokens / GAUGE_WINDOW) * 100 }),
        contextUsageRevision: 0,
    };
}
/** Render one contextLine variant of the top border for the given usage. */
function renderGaugeVariant(tokens, contextLine, width) {
    const component = new StatusLineComponent(fakeGaugeSession(tokens), statusLineHost);
    component.updateSettings({
        preset: "custom",
        leftSegments: contextLine === "embedded" ? ["model", "context_pct"] : ["model"],
        rightSegments: contextLine === "embedded" ? ["session_name"] : ["context_pct"],
        separator: "powerline-thin",
        sessionAccent: false,
        contextLine,
    });
    try {
        return component.getTopBorder(width).content;
    }
    finally {
        component.dispose();
    }
}
function renderContextGaugeState(state, width) {
    const { tokens, note } = GAUGE_CASES[state];
    return [
        theme.fg("dim", `  ${note}`),
        renderGaugeVariant(tokens, "annotated", width),
        renderGaugeVariant(tokens, "embedded", width),
    ];
}
export const statusLineFixtures = {
    context_gauge: {
        label: "Context Gauge",
        renderState: renderContextGaugeState,
        args: { note: "status-line context gauge preview" },
        result: { content: [{ type: "text", text: "Rendered annotated and embedded context gauges." }] },
    },
};
