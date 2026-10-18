import { resolveModelServiceTier, streamSimple } from "@rva/ai";
import { renderTableRow, replaceTabs, truncateToWidth, visibleWidth, } from "@rva/tui";
import { formatDuration, formatNumber, prompt } from "@rva/utils";
import chalk from "@rva/utils/chalk";
import { formatModelSelectorValue } from "@rva/tui/overlays/model-selector";
import { formatModelStringWithRouting } from "../config/model-resolver";
import { buildServiceTierByFamily, serviceTierForAllFamilies, serviceTierSettingToTier } from "../config/service-tier";
import cachePrefixTemplate from "../prompts/bench/cache-prefix.md" with { type: "text" };
import cachePrefixChunk from "../prompts/bench/cache-prefix-chunk.md" with { type: "text" };
import cacheSuffixTemplate from "../prompts/bench/cache-suffix.md" with { type: "text" };
import chatTemplate from "../prompts/bench/chat.md" with { type: "text" };
import generationTemplate from "../prompts/bench/generation.md" with { type: "text" };
import prefillInstruction from "../prompts/bench/prefill-instruction.md" with { type: "text" };
import { shouldDisableReasoning, toReasoningEffort } from "@rva/tui/thinking";
import { createDefaultBenchRuntime, resolveBenchTargets, } from "./bench-runtime";
import { createLiveBoard } from "@rva/tui/chrome/live-board";
import { formatCost } from "@rva/tui/overlays/agent-hub-renderer";
import { cfgTierAnthropic, cfgTierGoogle, cfgTierOpenai } from "../session/settings";
const DEFAULT_PAR = 4;
const DEFAULT_CACHE_MAX_TOKENS = 64;
const DEFAULT_CACHE_PREFIX_BYTES = 8192;
const DEFAULT_CACHE_PAIRS = 1;
const DEFAULT_CACHE_CONCURRENCY = 1;
const DEFAULT_PREFILL_BYTES = 32768;
/**
 * Default prefill input cap per context-window token. Dense tokenizers pack
 * the filler at ~2.3 bytes/token (Apple's on-device model), so 1.5 bytes per
 * window token stays under ~2/3 of the window — room for the instruction and
 * output on small local models.
 */
const PREFILL_BYTES_PER_CONTEXT_TOKEN = 1.5;
/** `--detailed` requests per phase (the parallel phase rounds up to whole `--par` waves). */
const DETAILED_DEFAULT_RUNS = 4;
const ERROR_WIDTH = 110;
const UTF8_ENCODER = new TextEncoder();
const UTF8_DECODER = new TextDecoder();
const CACHE_PREFIX_CHUNK = cachePrefixChunk;
const CACHE_PREFIX_PLACEHOLDER = "__OMP_CACHE_BENCH_RAW_PREFIX__";
const CACHE_PREFIX_CHUNK_BYTES = UTF8_ENCODER.encode(CACHE_PREFIX_CHUNK).byteLength;
const RESPONSE_CACHE_STATUS_HEADERS = ["cf-aig-cache-status"];
/** `mix` rotation order; the lead kind (chat) supplies a mixed table's latency and ranking. */
const CHALLENGE_KINDS = ["chat", "prefill", "generation"];
/** Default max output tokens per challenge kind (`--max-tokens` overrides all). */
const CHALLENGE_MAX_TOKENS = { chat: 512, prefill: 64, generation: 2048 };
/** Default requests per model; mix needs a multiple of the kind count. */
const PROFILE_DEFAULT_RUNS = { mix: 9, chat: 10, prefill: 5, generation: 5 };
/** Chat-challenge topics; one is drawn at random per run so runs never repeat a request. */
const CHAT_TOPICS = [
    "how a web browser turns an HTML payload into pixels on screen",
    "how a garbage collector reclaims memory in a managed runtime",
    "how TCP congestion control adapts to packet loss",
    "how a B-tree index accelerates database lookups",
    "how DNS resolves a hostname to an IP address",
    "how an operating system scheduler shares a CPU between processes",
    "how public-key cryptography secures a TLS handshake",
    "how a compiler lowers source code to optimized machine code",
    "how a CPU cache hierarchy hides memory latency",
    "how a distributed consensus protocol keeps replicas consistent",
];
/** Generation-challenge topics; long, low-ambiguity narrations that sustain decoding. */
const GENERATION_TOPICS = [
    "the history of computing",
    "the history of aviation",
    "the history of astronomy",
    "the history of railways",
    "the history of medicine",
    "the history of telecommunications",
    "the history of cartography",
    "the history of shipbuilding",
];
function getErrorMessage(error) {
    if (error instanceof Error && error.message)
        return error.message;
    return String(error);
}
function normalizePositiveInteger(name, value, fallback) {
    if (value === undefined)
        return fallback;
    if (!Number.isInteger(value) || value <= 0) {
        throw new Error(`Expected --${name} to be a positive integer, got ${value}`);
    }
    return value;
}
function closeProviderSessionStates(providerSessionState) {
    for (const state of providerSessionState.values()) {
        state.close();
    }
    providerSessionState.clear();
}
function isFirstTokenEvent(event) {
    switch (event.type) {
        case "text_delta":
        case "thinking_delta":
        case "toolcall_delta":
            return event.delta.length > 0;
        case "text_end":
        case "thinking_end":
            return event.content.length > 0;
        case "image_end":
            return true;
        default:
            return false;
    }
}
/** Final message carries visible output — non-empty text/thinking, an image, or a tool call. */
function hasVisibleFinalContent(message) {
    return message.content.some(block => {
        switch (block.type) {
            case "text":
                return block.text.length > 0;
            case "thinking":
                return block.thinking.length > 0;
            case "image":
            case "redactedThinking":
            case "toolCall":
                return true;
            default:
                return false;
        }
    });
}
function payloadStructure(payload) {
    if (payload === null)
        return "null";
    if (Array.isArray(payload))
        return `[${payload.map(payloadStructure).join(",")}]`;
    if (typeof payload === "object") {
        const record = payload;
        return `{${Object.keys(record)
            .sort()
            .map(key => `${key}:${payloadStructure(record[key])}`)
            .join(",")}}`;
    }
    return typeof payload;
}
function asNonNegativeNumber(value) {
    return typeof value === "number" && Number.isFinite(value) && value > 0 ? value : 0;
}
/** Nearest-rank distribution summary; `values` MUST be non-empty. */
function metricStats(values) {
    const sorted = [...values].sort((a, b) => a - b);
    const at = (q) => sorted[Math.max(0, Math.min(sorted.length - 1, Math.ceil(q * sorted.length) - 1))];
    return {
        mean: sorted.reduce((sum, value) => sum + value, 0) / sorted.length,
        min: sorted[0],
        p50: at(0.5),
        p95: at(0.95),
        max: sorted[sorted.length - 1],
    };
}
function mean(values) {
    return values.length === 0 ? 0 : values.reduce((sum, value) => sum + value, 0) / values.length;
}
function captureUsage(message) {
    const usage = message.usage;
    return {
        inputTokens: asNonNegativeNumber(usage.input),
        outputTokens: asNonNegativeNumber(usage.output),
        cacheReadTokens: asNonNegativeNumber(usage.cacheRead),
        cacheWriteTokens: asNonNegativeNumber(usage.cacheWrite),
        totalTokens: asNonNegativeNumber(usage.totalTokens),
        cost: asNonNegativeNumber(usage.cost?.total),
    };
}
function cacheObservations(capture) {
    const observations = [];
    if ((capture.usage?.cacheReadTokens ?? 0) > 0)
        observations.push("prompt_cache_read_observed");
    if ((capture.usage?.cacheWriteTokens ?? 0) > 0)
        observations.push("prompt_cache_write_observed");
    if (capture.responseCacheHit)
        observations.push("response_cache_hit_observed");
    return observations.length > 0 ? observations : ["no_provider_proof"];
}
function cacheRunReport(phase, result, capture) {
    return {
        phase,
        result,
        usage: capture.usage,
        requestIdObserved: capture.requestIdObserved,
        observations: cacheObservations(capture),
    };
}
function truncateUtf8ByteLength(bytes, maxBytes) {
    const end = Math.min(bytes.byteLength, maxBytes);
    if (end === 0)
        return 0;
    let sequenceStart = end - 1;
    while (sequenceStart > 0 && (bytes[sequenceStart] & 192) === 128)
        sequenceStart--;
    const leadingByte = bytes[sequenceStart];
    const sequenceLength = leadingByte <= 127
        ? 1
        : leadingByte >= 194 && leadingByte <= 223
            ? 2
            : leadingByte >= 224 && leadingByte <= 239
                ? 3
                : leadingByte >= 240 && leadingByte <= 244
                    ? 4
                    : 1;
    return sequenceLength > end - sequenceStart ? sequenceStart : end;
}
async function readBoundedUtf8File(path, maxBytes) {
    const file = Bun.file(path);
    const bytes = new Uint8Array(await file.slice(0, maxBytes).arrayBuffer());
    const end = truncateUtf8ByteLength(bytes, maxBytes);
    return UTF8_DECODER.decode(bytes.subarray(0, end));
}
function truncateUtf8(text, maxBytes) {
    const bytes = UTF8_ENCODER.encode(text);
    const end = truncateUtf8ByteLength(bytes, maxBytes);
    return end === bytes.byteLength ? text : UTF8_DECODER.decode(bytes.subarray(0, end));
}
function generatedCachePrefix(bytes) {
    return truncateUtf8(CACHE_PREFIX_CHUNK.repeat(Math.ceil(bytes / CACHE_PREFIX_CHUNK_BYTES)), bytes);
}
function renderCacheBenchmarkPrefix(prefix, namespace) {
    const rendered = prompt.render(cachePrefixTemplate, {
        prefix: CACHE_PREFIX_PLACEHOLDER,
        namespace,
    });
    if (!rendered.includes(CACHE_PREFIX_PLACEHOLDER)) {
        throw new Error("Cache benchmark prefix template is missing its raw prefix placeholder");
    }
    // Render the static wrapper first, then inject caller bytes so prompt
    // normalization cannot trim spaces or collapse blank lines in prefix files.
    // Function replacer: a prefix containing `$&`/`$'`/`` $` `` must not be
    // expanded as a string-replacement pattern.
    return rendered.replace(CACHE_PREFIX_PLACEHOLDER, () => prefix);
}
async function resolveCachePrefix(flags, readTextFile) {
    const bytes = normalizePositiveInteger("cache-prefix-bytes", flags.cachePrefixBytes, DEFAULT_CACHE_PREFIX_BYTES);
    const prefix = flags.cachePrefixFile
        ? await readTextFile(flags.cachePrefixFile, bytes)
        : generatedCachePrefix(bytes);
    return truncateUtf8(prefix, bytes);
}
function cacheBenchmarkMessages(stablePrefix, suffix) {
    const timestamp = Date.now();
    return [
        { role: "user", content: stablePrefix, timestamp, attribution: "user" },
        { role: "user", content: suffix, timestamp, attribution: "user" },
    ];
}
/** Build a randomized challenge so repeated runs never send a byte-identical request. */
function buildBenchChallenge(kind, opts) {
    const maxTokens = opts.maxTokensOverride ?? CHALLENGE_MAX_TOKENS[kind];
    const pick = (topics) => topics[Math.floor(opts.random() * topics.length)] ?? topics[0];
    const user = (content) => [
        { role: "user", content, timestamp: Date.now(), attribution: "user" },
    ];
    switch (kind) {
        case "chat":
            return {
                kind,
                maxTokens,
                messages: user(opts.promptOverride ?? prompt.render(chatTemplate, { topic: pick(CHAT_TOPICS) }).trim()),
            };
        case "generation":
            return {
                kind,
                maxTokens,
                messages: user(opts.promptOverride ?? prompt.render(generationTemplate, { topic: pick(GENERATION_TOPICS) }).trim()),
            };
        case "prefill":
            return {
                kind,
                maxTokens,
                messages: user(`Benchmark run ${opts.nonce}.\n\n${generatedCachePrefix(opts.prefillBytes)}\n\n${prefillInstruction.trim()}`),
            };
    }
}
/**
 * Prefill input size for `model`: an explicit `--prefill-bytes` wins; the
 * default is capped by the context window so small local models (e.g. Apple's
 * ~4K-token on-device model) are measured instead of rejected.
 */
function prefillBytesFor(model, explicit) {
    if (explicit !== undefined)
        return explicit;
    const window = model.contextWindow;
    return window !== null && Number.isFinite(window) && window > 0
        ? Math.min(DEFAULT_PREFILL_BYTES, Math.floor(window * PREFILL_BYTES_PER_CONTEXT_TOKEN))
        : DEFAULT_PREFILL_BYTES;
}
/** `--detailed` plan: single-user chat, `par`-way parallel chat (whole waves), single-user prefill. */
function detailedSteps(runs, par) {
    return [
        { phase: "single", kinds: ["chat"], runs, concurrency: 1 },
        { phase: "parallel", kinds: ["chat"], runs: par * Math.ceil(runs / par), concurrency: par },
        { phase: "prefill", kinds: ["prefill"], runs, concurrency: 1 },
    ];
}
function buildPhaseReport(concurrency, results, wallMs) {
    const successes = results.filter((result) => result.ok);
    const outputTokens = successes.reduce((sum, result) => sum + result.outputTokens, 0);
    return {
        concurrency,
        runs: results.length,
        wallMs,
        aggregateTps: wallMs > 0 ? (outputTokens * 1000) / wallMs : 0,
        stats: successes.length === 0 ? null : computeBenchStats(successes),
    };
}
async function runWithConcurrency(count, concurrency, run) {
    // oxlint-disable-next-line unicorn/no-new-array -- length preallocation
    const results = new Array(count);
    let next = 0;
    const worker = async () => {
        while (next < count) {
            const index = next++;
            results[index] = await run(index);
        }
    };
    await Promise.all(Array.from({ length: Math.min(count, concurrency) }, worker));
    return results;
}
function formatCachePairLine(pair, index, total) {
    const formatPhase = (run, alreadyWarm = false) => {
        if (!run.result.ok) {
            return `${run.phase} failed: ${truncateToWidth(replaceTabs(run.result.error), ERROR_WIDTH)}`;
        }
        const usage = run.usage;
        return `${run.phase}${alreadyWarm ? " (already warm)" : ""} ${run.observations.join(", ")} ${chalk.dim("input")} ${usage?.inputTokens ?? 0} ${chalk.dim("cache-read")} ${usage?.cacheReadTokens ?? 0} ${chalk.dim("cache-write")} ${usage?.cacheWriteTokens ?? 0} ${chalk.dim("output")} ${usage?.outputTokens ?? run.result.outputTokens} ${chalk.dim("total")} ${usage?.totalTokens ?? 0} ${chalk.dim("cost")} ${formatCost(usage?.cost ?? 0)} ${chalk.dim("TTFT")} ${formatMs(run.result.ttftMs)} ${chalk.dim("duration")} ${formatMs(run.result.durationMs)} ${chalk.dim("throughput")} ${run.result.tokensPerSecond.toFixed(1)}/s`;
    };
    return `  ${chalk.dim(`pair ${index + 1}/${total}`)} ${formatPhase(pair.cold, pair.coldAlreadyWarm)}; ${formatPhase(pair.warm)}`;
}
async function runBenchRequest(model, options, streamFn, now) {
    const startedAt = now();
    let firstTokenAt;
    const providerSessionState = new Map();
    try {
        const context = {
            // Codex's Responses endpoint 400s with "Instructions are required" when no
            // system prompt is present — same guard as eval's completion bridge.
            systemPrompt: ["You are a helpful assistant."],
            messages: options.messages,
        };
        const stream = streamFn(model, context, {
            apiKey: options.apiKey,
            sessionId: options.sessionId,
            maxTokens: model.maxTokens !== null && Number.isFinite(model.maxTokens) && model.maxTokens > 0
                ? Math.min(options.maxTokens, model.maxTokens)
                : options.maxTokens,
            reasoning: options.reasoning,
            promptCacheKey: options.promptCacheKey,
            statefulResponses: options.statefulResponses,
            onPayload: options.cacheCapture
                ? payload => {
                    options.cacheCapture.payloadStructure = payloadStructure(payload);
                    return undefined;
                }
                : undefined,
            onResponse: options.cacheCapture
                ? response => {
                    options.cacheCapture.requestIdObserved = Boolean(response.requestId);
                    options.cacheCapture.responseCacheHit = RESPONSE_CACHE_STATUS_HEADERS.some(header => response.headers[header]?.trim().toLowerCase() === "hit");
                }
                : undefined,
            disableReasoning: options.disableReasoning,
            serviceTier: options.serviceTier,
            providerSessionState,
            preferWebsockets: true,
            // pi-ai opts every OpenRouter request into response caching (1h TTL).
            // Bench sends a byte-identical request each run, so within the TTL
            // OpenRouter replays the cached generation with zeroed usage — the run
            // shows "tokens 0, TPS 0.0" at line speed. Opt back out so every run
            // measures a fresh generation.
            headers: model.provider === "openrouter" ? { "X-OpenRouter-Cache": "false" } : undefined,
        });
        let message;
        for await (const event of stream) {
            if (firstTokenAt === undefined && isFirstTokenEvent(event)) {
                firstTokenAt = now();
            }
            if (event.type === "error") {
                return { ok: false, error: event.error.errorMessage ?? "request failed" };
            }
            if (event.type === "done") {
                message = event.message;
            }
        }
        message ??= await stream.result();
        if (message.stopReason === "error" || message.errorMessage) {
            return { ok: false, error: message.errorMessage ?? "request failed" };
        }
        const rawDuration = message.duration ?? now() - startedAt;
        const durationMs = Number.isFinite(rawDuration) && rawDuration > 0 ? rawDuration : 0;
        const rawTtft = message.ttft ?? (firstTokenAt === undefined ? durationMs : firstTokenAt - startedAt);
        const ttftMs = Number.isFinite(rawTtft) && rawTtft > 0 ? rawTtft : 0;
        const outputTokens = Number.isFinite(message.usage.output) && message.usage.output > 0 ? message.usage.output : 0;
        // A run that streamed no content (no delta/end event set firstTokenAt),
        // carries no visible final content, and measured no output tokens
        // benchmarked nothing — a genuinely empty stream (e.g. a gateway that 200s
        // with an empty body). Surface it as a failure instead of a misleading
        // 0-token "✓". Streaming and buffered providers that produce content keep
        // passing even when usage is omitted.
        if (firstTokenAt === undefined && outputTokens === 0 && !hasVisibleFinalContent(message)) {
            return {
                ok: false,
                error: `provider returned no output (0 tokens, empty stream; stop reason: ${message.stopReason ?? "unknown"})`,
            };
        }
        if (options.cacheCapture)
            options.cacheCapture.usage = captureUsage(message);
        // Providers report cache-written/read prompt tokens outside `usage.input`
        // (e.g. Anthropic auto-caching moves nearly the whole prompt into
        // cacheWrite), so total prompt size must sum all three.
        const inputTokens = asNonNegativeNumber(message.usage.input) +
            asNonNegativeNumber(message.usage.cacheRead) +
            asNonNegativeNumber(message.usage.cacheWrite);
        const generationMs = Math.max(0, durationMs - ttftMs);
        return {
            ok: true,
            ttftMs,
            generationMs,
            durationMs,
            inputTokens,
            outputTokens,
            // TPS over the TOTAL request duration, deliberately not the post-TTFT
            // decode window: reasoning models can spend seconds generating hidden
            // thinking tokens (counted in usage.output) before the first visible
            // byte, so "duration - TTFT" inflates TPS several-fold on providers
            // that buffer or hide reasoning (e.g. google vs google-vertex).
            tokensPerSecond: durationMs > 0 ? (outputTokens * 1000) / durationMs : 0,
            generationTps: generationMs > 0 ? (outputTokens * 1000) / generationMs : 0,
            prefillTps: ttftMs > 0 ? (inputTokens * 1000) / ttftMs : 0,
            cost: asNonNegativeNumber(message.usage.cost?.total),
        };
    }
    catch (error) {
        return { ok: false, error: getErrorMessage(error) };
    }
    finally {
        closeProviderSessionStates(providerSessionState);
    }
}
function buildModelReport(selector, model, thinking, results, phases = {}) {
    const successes = results.filter((result) => result.ok);
    const byChallenge = {};
    for (const kind of CHALLENGE_KINDS) {
        const kindRuns = successes.filter(r => r.challenge === kind);
        if (kindRuns.length > 0)
            byChallenge[kind] = computeBenchStats(kindRuns);
    }
    return {
        selector,
        model: formatModelStringWithRouting(model),
        thinking,
        results,
        stats: successes.length === 0 ? null : computeBenchStats(successes),
        byChallenge,
        phases,
    };
}
function computeBenchStats(successes) {
    return {
        ttftMs: metricStats(successes.map(r => r.ttftMs)),
        durationMs: metricStats(successes.map(r => r.durationMs)),
        tokensPerSecond: metricStats(successes.map(r => r.tokensPerSecond)),
        generationTps: metricStats(successes.map(r => r.generationTps)),
        prefillTps: metricStats(successes.map(r => r.prefillTps)),
        inputTokens: mean(successes.map(r => r.inputTokens)),
        outputTokens: mean(successes.map(r => r.outputTokens)),
        cost: mean(successes.map(r => r.cost)),
    };
}
function formatBenchModelLabel(report) {
    return formatModelSelectorValue(report.model, report.thinking);
}
function formatMs(ms) {
    return formatDuration(Math.max(0, Math.round(ms)));
}
/** One run's result line; `tagKind` labels the challenge (only informative when kinds are mixed). */
function formatRunLine(result, index, total, opts) {
    const prefix = chalk.dim(`run ${index + 1}/${total}`);
    const kind = opts.tagKind && result.challenge ? `${chalk.cyan(result.challenge.padEnd(10))} ` : "";
    if (result.ok) {
        // A prefill run emits a handful of tokens: its output rates are noise, the input rate is the result.
        const gen = result.generationTps > 0 ? `${result.generationTps.toFixed(1)}/s` : "-";
        const rates = result.challenge === "prefill"
            ? `${chalk.dim("prefill")} ${result.prefillTps.toFixed(0)}/s`
            : `${chalk.dim("tok/s")} ${result.tokensPerSecond.toFixed(1)} ${chalk.dim("gen")} ${gen}`;
        return `  ${chalk.green("✓")} ${prefix} ${kind}${chalk.dim("TTFT")} ${formatMs(result.ttftMs)} ${rates} ${chalk.dim("in")} ${formatNumber(result.inputTokens)} ${chalk.dim("out")} ${formatNumber(result.outputTokens)} ${chalk.dim("total")} ${formatMs(result.durationMs)}`;
    }
    return `  ${chalk.red("✗")} ${prefix} ${kind}${chalk.red(truncateToWidth(replaceTabs(result.error).replace(/\r?\n/g, " "), ERROR_WIDTH))}`;
}
const PHASE_LABELS = { single: "single-user", parallel: "parallel", prefill: "prefill" };
/** Placeholder cell for a value the live footer has not measured yet. */
const PENDING_CELL = "…";
function formatProgress(progress, unit) {
    const parts = [`${progress.completed}/${progress.total} ${unit}`];
    if (progress.inFlight > 0)
        parts.push(`${progress.inFlight} in flight`);
    if (progress.failed > 0)
        parts.push(chalk.red(`${progress.failed} failed`));
    return parts.join(chalk.dim(" · "));
}
function formatRowStatus(row, spinner) {
    switch (row.state) {
        case "queued":
            return chalk.dim("queued");
        case "running":
            return `${chalk.yellow(spinner)} ${formatProgress(row.progress, "runs")}`;
        case "done": {
            const failed = row.report.results.filter(result => !result.ok).length;
            return failed > 0 ? chalk.red(`(${failed} failed)`) : "";
        }
    }
}
/** Headline column per challenge kind: output tok/s, or input tok/s for prefill (p50 of `metric`). */
const KIND_HEADLINES = {
    chat: { header: "tok/s", metric: "tokensPerSecond", digits: 1 },
    prefill: { header: "prefill", metric: "prefillTps", digits: 0 },
    generation: { header: "decode", metric: "tokensPerSecond", digits: 1 },
};
const MODEL_COLUMN = { header: "model", value: formatBenchModelLabel };
const COST_COLUMN = {
    header: "cost/run",
    value: r => {
        if (!r.stats)
            return undefined;
        // Zero cost means the model is unpriced, not free.
        return r.stats.cost > 0 ? formatCost(r.stats.cost) : "-";
    },
};
/** `--profile` table: lead-kind latency plus each kind's headline rate, ranked by the lead kind's rate. */
function profileTableSpec(kinds) {
    // The lead kind (chat when mixed) carries the representative latency.
    const lead = kinds[0];
    const columns = [
        MODEL_COLUMN,
        {
            header: "TTFT p50",
            value: r => {
                const ttft = r.byChallenge[lead]?.ttftMs;
                return ttft ? formatMs(ttft.p50) : undefined;
            },
        },
        {
            header: "p95",
            value: r => {
                const ttft = r.byChallenge[lead]?.ttftMs;
                return ttft ? formatMs(ttft.p95) : undefined;
            },
        },
    ];
    for (const kind of kinds) {
        const { header, metric, digits } = KIND_HEADLINES[kind];
        columns.push({ header, value: r => r.byChallenge[kind]?.[metric].p50.toFixed(digits) });
    }
    columns.push(COST_COLUMN);
    const { metric } = KIND_HEADLINES[lead];
    return { columns, rank: r => r.byChallenge[lead]?.[metric].p50 };
}
/**
 * `--detailed` table: single-user latency/rate, the same under `par`
 * concurrent users plus their aggregate rate and scaling, then prefill rate;
 * ranked by single-user tok/s.
 */
function detailedTableSpec(par) {
    // Phase columns stay pending until the phase has a successful run.
    const single = (r) => r.phases.single?.stats ?? undefined;
    const parallel = (r) => r.phases.parallel?.stats ?? undefined;
    const ttft = (stats) => stats && formatMs(stats.ttftMs.p50);
    return {
        columns: [
            MODEL_COLUMN,
            { header: "TTFT", value: r => ttft(single(r)) },
            { header: "tok/s", value: r => single(r)?.tokensPerSecond.p50.toFixed(1) },
            { header: `TTFT@${par}`, value: r => ttft(parallel(r)) },
            { header: `tok/s@${par}`, value: r => parallel(r)?.tokensPerSecond.p50.toFixed(1) },
            {
                header: `agg@${par}`,
                value: r => (r.phases.parallel?.stats ? r.phases.parallel.aggregateTps.toFixed(1) : undefined),
            },
            {
                // Parallel aggregate rate over single-user aggregate rate: ~1× means
                // concurrent requests queue behind each other, ~N× means they scale.
                header: "scale",
                value: r => {
                    const base = r.phases.single?.aggregateTps;
                    const loaded = r.phases.parallel?.aggregateTps;
                    return base && loaded ? `${(loaded / base).toFixed(1)}×` : undefined;
                },
            },
            { header: "prefill", value: r => r.phases.prefill?.stats?.prefillTps.p50.toFixed(0) },
            COST_COLUMN,
        ],
        rank: r => single(r)?.tokensPerSecond.p50,
    };
}
/**
 * Comparison table ranked by `spec.rank` (medians, not means, so one queue
 * hiccup cannot reorder rows). It is also the live footer: unfinished rows
 * show {@link PENDING_CELL} for unmeasured cells and a trailing status
 * animated by `spinner`.
 */
function formatBenchTable(rows, spec, spinner = "") {
    const ranked = rows
        .map(row => ({ row, rate: spec.rank(row.report) ?? Number.NEGATIVE_INFINITY }))
        .sort((a, b) => b.rate - a.rate);
    const { columns } = spec;
    const texts = ranked.map(({ row }) => columns.map(column => column.value(row.report) ?? (row.state === "done" ? "-" : PENDING_CELL)));
    const layout = columns.map((column, index) => ({
        width: Math.max(visibleWidth(column.header), ...texts.map(cells => visibleWidth(cells[index]))),
        align: "left",
        overflow: "allow",
    }));
    // Unpadded trailing status: progress, queue position, or failures.
    layout.push({ width: 0, align: "left", overflow: "allow" });
    const table = [columns.map(column => ({ text: column.header, style: chalk.dim }))];
    for (const [index, { row, rate }] of ranked.entries()) {
        const cells = texts[index].map((text) => ({
            text,
            style: text === PENDING_CELL ? chalk.dim : undefined,
        }));
        // Green marks the leader: the top row once it has a headline rate.
        if (index === 0 && rate > Number.NEGATIVE_INFINITY)
            cells[0] = { text: cells[0].text, style: chalk.green };
        const status = formatRowStatus(row, spinner);
        if (status)
            cells.push({ text: status });
        table.push(cells);
    }
    return table.map(cells => renderTableRow(cells, layout, undefined, { gap: "  " }).trimEnd());
}
function assertCacheModeSupported(targets) {
    if (targets.some(({ model }) => model.api === "openai-codex-responses")) {
        throw new Error("--cache is not supported for openai-codex-responses because Codex WebSocket chaining cannot produce independent prompt-cache pairs");
    }
}
export async function runBenchCommand(command, deps = {}) {
    const cacheMode = command.flags.cache === true;
    const cacheFlagsUsed = command.flags.cachePrefixFile !== undefined ||
        command.flags.cachePrefixBytes !== undefined ||
        command.flags.cachePairs !== undefined ||
        command.flags.cacheConcurrency !== undefined;
    if (!cacheMode && cacheFlagsUsed)
        throw new Error("Cache flags require --cache");
    if (cacheMode && command.flags.runs !== undefined)
        throw new Error("Use --cache-pairs instead of --runs with --cache");
    if (cacheMode && command.flags.prompt !== undefined)
        throw new Error("--cache builds its own stable-prefix prompts");
    if (cacheMode && command.flags.profile !== undefined)
        throw new Error("--profile cannot be combined with --cache");
    if (cacheMode && (command.flags.par ?? 1) > 1) {
        throw new Error("--par cannot parallelize cold/warm pairs; use --cache-concurrency instead");
    }
    const detailed = command.flags.detailed === true;
    if (detailed && cacheMode)
        throw new Error("--detailed cannot be combined with --cache");
    if (detailed && command.flags.profile !== undefined) {
        throw new Error("--profile cannot be combined with --detailed, which runs single-user, parallel, and prefill phases");
    }
    const profileFlag = command.flags.profile;
    if (profileFlag !== undefined &&
        profileFlag !== "mix" &&
        profileFlag !== "chat" &&
        profileFlag !== "prefill" &&
        profileFlag !== "generation") {
        throw new Error(`Unknown --profile "${profileFlag}" (expected chat, prefill, generation, or mix)`);
    }
    const profile = profileFlag ?? "chat";
    if (!cacheMode && command.flags.prompt !== undefined && profile !== "chat" && profile !== "generation") {
        throw new Error("--prompt requires --profile chat or generation");
    }
    if (command.flags.prefillBytes !== undefined &&
        (cacheMode || (!detailed && profile !== "mix" && profile !== "prefill"))) {
        throw new Error("--prefill-bytes requires prefill challenges (--detailed, or --profile mix or prefill)");
    }
    const cachePairs = cacheMode
        ? normalizePositiveInteger("cache-pairs", command.flags.cachePairs, DEFAULT_CACHE_PAIRS)
        : undefined;
    const cacheConcurrency = cacheMode
        ? normalizePositiveInteger("cache-concurrency", command.flags.cacheConcurrency, DEFAULT_CACHE_CONCURRENCY)
        : undefined;
    const runsPerStep = normalizePositiveInteger("runs", command.flags.runs, detailed ? DETAILED_DEFAULT_RUNS : PROFILE_DEFAULT_RUNS[profile]);
    const maxTokensOverride = command.flags.maxTokens !== undefined
        ? normalizePositiveInteger("max-tokens", command.flags.maxTokens, 1)
        : undefined;
    const cacheMaxTokens = cacheMode ? (maxTokensOverride ?? DEFAULT_CACHE_MAX_TOKENS) : undefined;
    const par = command.flags.par !== undefined ? normalizePositiveInteger("par", command.flags.par, DEFAULT_PAR) : DEFAULT_PAR;
    if (detailed && par < 2)
        throw new Error("--detailed needs --par of at least 2 for its parallel phase");
    const promptOverride = command.flags.prompt?.trim() || undefined;
    const explicitPrefillBytes = command.flags.prefillBytes !== undefined
        ? normalizePositiveInteger("prefill-bytes", command.flags.prefillBytes, DEFAULT_PREFILL_BYTES)
        : undefined;
    const kinds = profile === "mix" ? CHALLENGE_KINDS : [profile];
    const steps = detailed
        ? detailedSteps(runsPerStep, par)
        : [{ kinds, runs: runsPerStep, concurrency: par }];
    const runs = cacheMode ? cachePairs * 2 : steps.reduce((sum, step) => sum + step.runs, 0);
    const tableSpec = detailed ? detailedTableSpec(par) : profileTableSpec(kinds);
    // Detailed phases each run a single kind under a phase header; only a mixed profile needs per-run kind tags.
    const tagKind = kinds.length > 1;
    const random = deps.random ?? Math.random;
    const json = command.flags.json === true;
    const randomSessionId = deps.randomSessionId ?? (() => Bun.randomUUIDv7());
    const readTextFile = deps.readTextFile ?? readBoundedUtf8File;
    const cachePrefix = cacheMode ? await resolveCachePrefix(command.flags, readTextFile) : undefined;
    const writeStdout = deps.writeStdout ?? ((text) => process.stdout.write(text));
    const writeStderr = deps.writeStderr ?? ((text) => process.stderr.write(text));
    const setExitCode = deps.setExitCode ??
        ((code) => {
            process.exitCode = code;
        });
    const streamFn = deps.streamSimple ?? streamSimple;
    const now = deps.now ?? (() => performance.now());
    const interactive = deps.stdoutIsTTY ?? process.stdout.isTTY === true;
    if (command.models.length === 0) {
        throw new Error("Pass at least one model selector, e.g. `omp bench opus gpt-5.2`");
    }
    // One row per model, filled as runs finish. Outside cache mode the comparison
    // table doubles as the live footer; cache mode shows a one-line status.
    let rows = [];
    const renderLive = (spinner) => {
        if (!cacheMode) {
            return rows.some(row => row.state !== "done") ? ["", ...formatBenchTable(rows, tableSpec, spinner)] : [];
        }
        const running = rows.find(row => row.state === "running");
        if (!running)
            return [];
        const label = chalk.bold(formatBenchModelLabel(running.report));
        return [`  ${chalk.yellow(spinner)} ${label}${chalk.dim(" · ")}${formatProgress(running.progress, "pairs")}`];
    };
    const board = json
        ? undefined
        : createLiveBoard(renderLive, {
            isTTY: interactive,
            get columns() {
                return process.stdout.columns;
            },
            get rows() {
                return process.stdout.rows;
            },
            write(text) {
                writeStdout(text);
                return true;
            },
        });
    const print = (text) => {
        if (board)
            board.log(text);
        else
            writeStdout(`${text}\n`);
    };
    const runtime = await (deps.createRuntime ?? createDefaultBenchRuntime)();
    try {
        const targets = await resolveBenchTargets(command.models, runtime.modelRegistry, runtime.settings, writeStderr);
        if (cacheMode)
            assertCacheModeSupported(targets);
        // Explicit `--service-tier` (a single value broadcast across families) wins;
        // otherwise fall back to the configured per-family `tier.*` settings. Each
        // model resolves its own family's tier below before reaching the wire.
        const flagTier = command.flags.serviceTier ? serviceTierSettingToTier(command.flags.serviceTier) : undefined;
        const serviceTierByFamily = command.flags.serviceTier
            ? serviceTierForAllFamilies(flagTier)
            : buildServiceTierByFamily((runtime.settings ? cfgTierOpenai.get(runtime.settings) : undefined) ?? "none", (runtime.settings ? cfgTierAnthropic.get(runtime.settings) : undefined) ?? "none", (runtime.settings ? cfgTierGoogle.get(runtime.settings) : undefined) ?? "none");
        if (!json && flagTier)
            print(chalk.dim(`service tier: ${flagTier}`));
        const total = cacheMode ? cachePairs : runs;
        rows = targets.map(({ selector, model, thinking }) => ({
            report: buildModelReport(selector, model, thinking, []),
            state: "queued",
            progress: { total, completed: 0, failed: 0, inFlight: 0 },
        }));
        for (const [targetIndex, { selector, model, thinking }] of targets.entries()) {
            const row = rows[targetIndex];
            const { progress } = row;
            if (!json) {
                const label = formatBenchModelLabel(row.report);
                print(`${chalk.bold(label)}${selector === label ? "" : chalk.dim(` (${selector})`)}`);
            }
            row.state = "running";
            board?.repaint();
            const results = [];
            // Preflight check: let's verify credentials before starting any runs.
            // This matches the old sequential break behavior exactly and avoids launching/printing
            // multiple failures.
            const testSessionId = randomSessionId();
            const preflightKey = await runtime.modelRegistry.getApiKey(model, testSessionId);
            if (!preflightKey) {
                const failure = {
                    ok: false,
                    error: `No credentials for provider "${model.provider}". Run \`omp\` and use /login, or set the provider API key.`,
                };
                results.push(failure);
                if (!json)
                    print(formatRunLine(failure, 0, runs, { tagKind }));
                row.report = buildModelReport(selector, model, thinking, results);
                if (cacheMode)
                    row.report.cachePairs = [];
                row.state = "done";
                continue;
            }
            const serviceTier = resolveModelServiceTier(serviceTierByFamily, model);
            if (cacheMode) {
                const pairs = await runWithConcurrency(cachePairs, cacheConcurrency, async (pairIndex) => {
                    const cacheNamespace = randomSessionId();
                    progress.inFlight++;
                    board?.repaint();
                    const promptCacheKey = `bench-cache:${cacheNamespace}`;
                    const stablePrefix = renderCacheBenchmarkPrefix(cachePrefix, cacheNamespace);
                    const coldSuffix = prompt.render(cacheSuffixTemplate, { variant: "A" }).trim();
                    const warmSuffix = prompt.render(cacheSuffixTemplate, { variant: "B" }).trim();
                    const coldCapture = {
                        requestIdObserved: false,
                        responseCacheHit: false,
                    };
                    // Keep the gateway's credential selection stable for both phases.
                    // Provider-session state is still recreated by runBenchRequest and
                    // stateful Responses chaining is disabled below.
                    const credentialAffinitySessionId = pairIndex === 0 ? testSessionId : randomSessionId();
                    const credentialResolver = runtime.modelRegistry.resolver(model, credentialAffinitySessionId);
                    const coldResult = await runBenchRequest(model, {
                        apiKey: credentialResolver,
                        sessionId: credentialAffinitySessionId,
                        messages: cacheBenchmarkMessages(stablePrefix, coldSuffix),
                        maxTokens: cacheMaxTokens,
                        reasoning: toReasoningEffort(thinking),
                        disableReasoning: shouldDisableReasoning(thinking) ? true : undefined,
                        serviceTier,
                        promptCacheKey,
                        statefulResponses: false,
                        cacheCapture: coldCapture,
                    }, streamFn, now);
                    const warmCapture = {
                        requestIdObserved: false,
                        responseCacheHit: false,
                    };
                    const warmResult = await runBenchRequest(model, {
                        apiKey: credentialResolver,
                        sessionId: credentialAffinitySessionId,
                        messages: cacheBenchmarkMessages(stablePrefix, warmSuffix),
                        maxTokens: cacheMaxTokens,
                        reasoning: toReasoningEffort(thinking),
                        disableReasoning: shouldDisableReasoning(thinking) ? true : undefined,
                        serviceTier,
                        promptCacheKey,
                        statefulResponses: false,
                        cacheCapture: warmCapture,
                    }, streamFn, now);
                    progress.inFlight--;
                    progress.completed++;
                    if (!coldResult.ok)
                        progress.failed++;
                    if (!warmResult.ok)
                        progress.failed++;
                    board?.repaint();
                    return {
                        cold: cacheRunReport("cold", coldResult, coldCapture),
                        warm: cacheRunReport("warm", warmResult, warmCapture),
                        coldAlreadyWarm: (coldCapture.usage?.cacheReadTokens ?? 0) > 0 || coldCapture.responseCacheHit,
                        stablePrefix: true,
                        suffixChanged: true,
                        promptCacheKeyStable: true,
                        statefulResponsesDisabled: true,
                        freshProviderSessionState: true,
                        payloadStructureStable: coldCapture.payloadStructure === undefined || warmCapture.payloadStructure === undefined
                            ? "unavailable"
                            : coldCapture.payloadStructure === warmCapture.payloadStructure,
                    };
                });
                for (const pair of pairs)
                    results.push(pair.cold.result, pair.warm.result);
                row.report = buildModelReport(selector, model, thinking, results);
                row.report.cachePairs = pairs;
                row.state = "done";
                if (!json) {
                    for (const [index, pair] of pairs.entries()) {
                        print(formatCachePairLine(pair, index, pairs.length));
                    }
                }
                continue;
            }
            const prefillBytes = prefillBytesFor(model, explicitPrefillBytes);
            const phases = {};
            let offset = 0;
            // Steps run back to back so one phase's load never skews the next.
            for (const step of steps) {
                const { phase } = step;
                if (!json && phase) {
                    print(`  ${chalk.bold(PHASE_LABELS[phase])} ${chalk.dim(`· ${step.concurrency} concurrent · ${step.runs} runs`)}`);
                }
                const finished = [];
                const startedAt = now();
                // Runs finish out of order under concurrency; lines print in index order.
                let nextToPrint = 0;
                await runWithConcurrency(step.runs, step.concurrency, async (index) => {
                    const runIndex = offset + index;
                    const sessionId = runIndex === 0 ? testSessionId : randomSessionId();
                    const challenge = buildBenchChallenge(step.kinds[index % step.kinds.length], {
                        promptOverride,
                        prefillBytes,
                        nonce: randomSessionId(),
                        random,
                        maxTokensOverride,
                    });
                    progress.inFlight++;
                    board?.repaint();
                    const result = {
                        ...(await runBenchRequest(model, {
                            apiKey: runtime.modelRegistry.resolver(model, sessionId),
                            sessionId,
                            messages: challenge.messages,
                            maxTokens: challenge.maxTokens,
                            reasoning: toReasoningEffort(thinking),
                            disableReasoning: shouldDisableReasoning(thinking) ? true : undefined,
                            serviceTier,
                        }, streamFn, now)),
                        challenge: challenge.kind,
                        phase,
                    };
                    results[runIndex] = result;
                    finished.push(result);
                    progress.inFlight--;
                    progress.completed++;
                    if (!result.ok)
                        progress.failed++;
                    if (phase)
                        phases[phase] = buildPhaseReport(step.concurrency, finished, now() - startedAt);
                    row.report = buildModelReport(selector, model, thinking, results, phases);
                    board?.repaint();
                    if (!json) {
                        while (nextToPrint < step.runs && results[offset + nextToPrint] !== undefined) {
                            print(formatRunLine(results[offset + nextToPrint], nextToPrint, step.runs, { tagKind }));
                            nextToPrint++;
                        }
                    }
                });
                // Chat phases close with the combined output rate across every in-flight request.
                const phaseReport = phase && phase !== "prefill" ? phases[phase] : undefined;
                if (!json && phaseReport) {
                    print(`    ${chalk.dim("aggregate")} ${phaseReport.aggregateTps.toFixed(1)} tok/s ${chalk.dim(`over ${formatMs(phaseReport.wallMs)} wall`)}`);
                }
                offset += step.runs;
            }
            row.state = "done";
        }
        const reports = rows.map(row => row.report);
        const failures = reports.reduce((sum, report) => sum + report.results.filter(result => !result.ok).length, 0);
        const summary = {
            runs,
            ...(cacheMode
                ? { maxTokens: cacheMaxTokens }
                : maxTokensOverride !== undefined
                    ? { maxTokens: maxTokensOverride }
                    : {}),
            models: reports,
            failures,
            serviceTierByFamily,
            ...(cacheMode
                ? { cache: { pairs: cachePairs, concurrency: cacheConcurrency } }
                : detailed
                    ? { detailed: { runsPerPhase: runsPerStep, par } }
                    : { profile }),
        };
        if (json) {
            writeStdout(`${JSON.stringify(summary, null, 2)}\n`);
        }
        else if (!cacheMode && (reports.length > 1 || runs > 1)) {
            print(["", ...formatBenchTable(rows, tableSpec)].join("\n"));
        }
        if (failures > 0)
            setExitCode(1);
        return summary;
    }
    finally {
        board?.close();
        runtime.close?.();
    }
}
